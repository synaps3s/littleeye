import json
import logging
import pathlib
from typing import Any, Dict, List, Optional
import aiosqlite

logger = logging.getLogger("littleeye.dashboard.db")

DEFAULT_SETTINGS = {
    "telegram_enabled": "false",
    "telegram_token": "",
    "telegram_chat_id": "",
    "webhook_enabled": "false",
    "webhook_url": "",
    "alert_severity_threshold": "warning"
}


async def init_db(db_path: str) -> None:
    # Ensure parent directory exists
    db_file = pathlib.Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        
        # 1. Create servers table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                os_name TEXT,
                kernel TEXT,
                arch TEXT
            )
        """)
        
        # 2. Create drift_reports table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS drift_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                findings TEXT NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            )
        """)
        
        # 3. Create settings table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # 4. Create agent_tokens table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS agent_tokens (
                token TEXT PRIMARY KEY,
                description TEXT NOT NULL
            )
        """)
        
        # Seed default settings
        for key, val in DEFAULT_SETTINGS.items():
            await db.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (key, val)
            )

        # Seed a default agent token if table is empty
        async with db.execute("SELECT COUNT(*) FROM agent_tokens") as cursor:
            count = (await cursor.fetchone())[0]
            if count == 0:
                await db.execute(
                    "INSERT INTO agent_tokens (token, description) VALUES (?, ?)",
                    ("default-agent-token", "Default Agent Token")
                )
                await db.execute(
                    "INSERT INTO agent_tokens (token, description) VALUES (?, ?)",
                    ("agent-web-token", "Web Server Agent")
                )
                await db.execute(
                    "INSERT INTO agent_tokens (token, description) VALUES (?, ?)",
                    ("agent-db-token", "Database Server Agent")
                )
            
        await db.commit()
        logger.info(f"Database initialized at {db_path}")


async def verify_agent_token(db_path: str, token: str) -> bool:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT 1 FROM agent_tokens WHERE token = ?", (token,)) as cursor:
            row = await cursor.fetchone()
            return row is not None


async def get_agent_tokens(db_path: str) -> List[Dict[str, str]]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT token, description FROM agent_tokens") as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def add_agent_token(db_path: str, token: str, description: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT OR IGNORE INTO agent_tokens (token, description) VALUES (?, ?)",
            (token, description)
        )
        await db.commit()


async def delete_agent_token(db_path: str, token: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute("DELETE FROM agent_tokens WHERE token = ?", (token,))
        await db.commit()


async def get_servers(db_path: str) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, hostname, last_seen, status, os_name, kernel, arch FROM servers ORDER BY hostname ASC") as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_server(db_path: str, server_id: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, hostname, last_seen, status, os_name, kernel, arch FROM servers WHERE id = ?", (server_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def upsert_server(
    db_path: str,
    server_id: str,
    hostname: str,
    last_seen: str,
    status: str,
    os_name: str = "",
    kernel: str = "",
    arch: str = ""
) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            INSERT INTO servers (id, hostname, last_seen, status, os_name, kernel, arch)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                last_seen = excluded.last_seen,
                status = excluded.status,
                os_name = excluded.os_name,
                kernel = excluded.kernel,
                arch = excluded.arch
        """, (server_id, hostname, last_seen, status, os_name, kernel, arch))
        await db.commit()


async def add_drift_report(db_path: str, server_id: str, timestamp: str, findings: List[Dict[str, Any]]) -> None:
    async with aiosqlite.connect(db_path) as db:
        findings_json = json.dumps(findings)
        await db.execute("""
            INSERT INTO drift_reports (server_id, timestamp, findings)
            VALUES (?, ?, ?)
        """, (server_id, timestamp, findings_json))
        await db.commit()


async def get_server_history(db_path: str, server_id: str) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT timestamp, findings FROM drift_reports 
            WHERE server_id = ? 
            ORDER BY timestamp DESC
        """, (server_id,)) as cursor:
            rows = await cursor.fetchall()
            history = []
            for r in rows:
                findings_list = json.loads(r["findings"])
                history.append({
                    "timestamp": r["timestamp"],
                    "findings": findings_list,
                    "findings_count": len(findings_list)
                })
            return history


async def get_drift_report(db_path: str, server_id: str, timestamp: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT server_id, timestamp, findings FROM drift_reports 
            WHERE server_id = ? AND timestamp = ?
        """, (server_id, timestamp)) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "server_id": row["server_id"],
                    "timestamp": row["timestamp"],
                    "findings": json.loads(row["findings"])
                }
            return None


async def get_settings(db_path: str) -> Dict[str, str]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT key, value FROM settings") as cursor:
            rows = await cursor.fetchall()
            return {r["key"]: r["value"] for r in rows}


async def save_settings(db_path: str, settings_dict: Dict[str, str]) -> None:
    async with aiosqlite.connect(db_path) as db:
        for key, val in settings_dict.items():
            await db.execute("""
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, val))
        await db.commit()


async def get_setting(db_path: str, key: str) -> Optional[str]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            return row["value"] if row else None
