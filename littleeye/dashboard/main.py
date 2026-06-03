import asyncio
import logging
import os
import pathlib
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from littleeye.dashboard.db import (
    init_db,
    get_servers,
    get_server,
    get_server_history,
    get_agent_tokens,
    add_agent_token,
    delete_agent_token
)
from littleeye.dashboard.settings import load_config, update_config, DashboardConfig
from littleeye.dashboard.api import router as api_router
from littleeye.agent.notify import _send_telegram_sync, _send_webhook_sync

logger = logging.getLogger("littleeye.dashboard.main")
DB_PATH = os.environ.get("LITTLEEYE_DB_PATH", "data/littleeye.db")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run database initialization
    await init_db(DB_PATH)
    yield


app = FastAPI(
    title="LittleEye Dashboard",
    lifespan=lifespan
)

# Mount API Router
app.include_router(api_router)

# Mount Static and Templates
current_dir = pathlib.Path(__file__).parent.resolve()
static_dir = current_dir / "static"
templates_dir = current_dir / "templates"

static_dir.mkdir(parents=True, exist_ok=True)
templates_dir.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates = Jinja2Templates(directory=str(templates_dir))


# Custom filter for template formatting
def format_datetime(value: str) -> str:
    try:
        # Standard ISO format: 2026-06-03T20:07:33Z
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return value

templates.env.filters["format_datetime"] = format_datetime


@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    try:
        servers = await get_servers(DB_PATH)
        total_servers = len(servers)
        servers_with_drift_24h = 0
        severity_counts = {"info": 0, "warning": 0, "critical": 0}
        server_findings = []
        
        now = datetime.now(timezone.utc)
        for s in servers:
            is_recent = False
            try:
                # Expect YYYY-MM-DDTHH:MM:SSZ format
                time_str = s["last_seen"]
                if time_str.endswith("Z"):
                    time_str = time_str[:-1] + "+00:00"
                dt = datetime.fromisoformat(time_str)
                if (now - dt).total_seconds() <= 86400:
                    is_recent = True
            except Exception:
                pass
            
            if s["status"] == "drift" and is_recent:
                servers_with_drift_24h += 1
                
            # Get latest findings
            history = await get_server_history(DB_PATH, s["id"])
            latest_count = 0
            if history:
                latest_report = history[0]
                latest_count = len(latest_report.get("findings", []))
                for f in latest_report.get("findings", []):
                    sev = f.get("severity", "info").lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
            
            server_findings.append({
                "hostname": s["hostname"],
                "findings_count": latest_count
            })

        return templates.TemplateResponse(request=request, name="index.html", context={
            "total_servers": total_servers,
            "servers_with_drift_24h": servers_with_drift_24h,
            "severity_counts": severity_counts,
            "server_findings": server_findings
        })
    except Exception as e:
        logger.error(f"Error rendering home dashboard: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/servers", response_class=HTMLResponse)
async def get_servers_page(request: Request):
    try:
        servers = await get_servers(DB_PATH)
        return templates.TemplateResponse(request=request, name="servers.html", context={
            "servers": servers
        })
    except Exception as e:
        logger.error(f"Error rendering servers list page: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/server/{server_id}", response_class=HTMLResponse)
async def get_server_page(request: Request, server_id: str):
    try:
        server_info = await get_server(DB_PATH, server_id)
        if not server_info:
            raise HTTPException(status_code=404, detail="Server not registered")
        history = await get_server_history(DB_PATH, server_id)
        
        # Pre-process findings to add side-by-side diffs for file content changes
        from littleeye.agent.report import get_side_by_side_diff
        for report in history:
            processed_findings = []
            for f in report.get("findings", []):
                f_copy = f.copy()
                category = f.get("category", "").lower()
                field = f.get("field", "")
                if category == "files" and field.endswith(":content"):
                    old_val = f.get("old_value") or ""
                    new_val = f.get("new_value") or ""
                    f_copy["file_diff"] = get_side_by_side_diff(old_val, new_val)
                processed_findings.append(f_copy)
            report["findings"] = processed_findings

        return templates.TemplateResponse(request=request, name="server.html", context={
            "server": server_info,
            "history": history
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rendering server history page: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/server/{server_id}/report/{timestamp}/html")
async def get_server_report_html(server_id: str, timestamp: str):
    try:
        from littleeye.dashboard.db import get_drift_report
        report = await get_drift_report(DB_PATH, server_id, timestamp)
        server_info = await get_server(DB_PATH, server_id)
        if not report or not server_info:
            raise HTTPException(status_code=404, detail="Report not found")
            
        from littleeye.agent.report import get_side_by_side_diff
        processed_findings = []
        counts = {"info": 0, "warning": 0, "critical": 0}
        grouped_findings = {}
        for f in report.get("findings", []):
            f_copy = f.copy()
            category = f.get("category", "other").lower()
            severity = f.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1
            if category == "files" and f.get("field", "").endswith(":content"):
                old_val = f.get("old_value") or ""
                new_val = f.get("new_value") or ""
                f_copy["file_diff"] = get_side_by_side_diff(old_val, new_val)
            processed_findings.append(f_copy)
            grouped_findings.setdefault(category, []).append(f_copy)
            
        current_dir = pathlib.Path(__file__).parent.resolve()
        agent_templates_dir = current_dir.parent / "agent" / "templates"
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(agent_templates_dir)), autoescape=True)
        template = env.get_template("report.html.j2")
        
        formatted_ts = format_datetime(timestamp)
        html_content = template.render(
            hostname=server_info["hostname"],
            timestamp=formatted_ts,
            counts=counts,
            grouped_findings=grouped_findings,
            total_findings=len(report["findings"])
        )
        
        # Set content-disposition to prompt file download or view online
        headers = {
            "Content-Disposition": f"inline; filename=littleeye_report_{server_id}_{timestamp}.html"
        }
        return Response(content=html_content, media_type="text/html", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rendering standalone HTML report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/settings", response_class=HTMLResponse)
async def get_settings_page(request: Request, success: Optional[str] = None):
    try:
        config = await load_config()
        tokens = await get_agent_tokens(DB_PATH)
        return templates.TemplateResponse(request=request, name="settings.html", context={
            "config": config,
            "tokens": tokens,
            "success": success
        })
    except Exception as e:
        logger.error(f"Error rendering settings page: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/settings")
async def post_settings(
    telegram_enabled: bool = Form(False),
    telegram_token: str = Form(""),
    telegram_chat_id: str = Form(""),
    webhook_enabled: bool = Form(False),
    webhook_url: str = Form(""),
    alert_severity_threshold: str = Form("warning")
):
    try:
        new_config = DashboardConfig(
            telegram_enabled=telegram_enabled,
            telegram_token=telegram_token,
            telegram_chat_id=telegram_chat_id,
            webhook_enabled=webhook_enabled,
            webhook_url=webhook_url,
            alert_severity_threshold=alert_severity_threshold
        )
        await update_config(new_config)
        return RedirectResponse(url="/settings?success=saved", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        logger.error(f"Error saving configurations: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/settings/token/add")
async def post_add_token(token: str = Form(...), description: str = Form(...)):
    try:
        if token.strip():
            await add_agent_token(DB_PATH, token.strip(), description.strip())
        return RedirectResponse(url="/settings?success=token_added", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        logger.error(f"Error adding agent token: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/settings/token/delete")
async def post_delete_token(token: str = Form(...)):
    try:
        await delete_agent_token(DB_PATH, token)
        return RedirectResponse(url="/settings?success=token_deleted", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        logger.error(f"Error deleting agent token: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/settings/test/telegram")
async def post_test_telegram(
    telegram_token: str = Form(...),
    telegram_chat_id: str = Form(...)
):
    try:
        text = "<b>LittleEye Test Alert</b>\nThis is a configuration test message from the LittleEye Dashboard."
        await asyncio.to_thread(
            _send_telegram_sync,
            telegram_token,
            telegram_chat_id,
            text
        )
        return {"status": "success", "message": "Test Telegram message sent successfully"}
    except Exception as e:
        logger.error(f"Telegram test failed: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to send test message: {str(e)}")


@app.post("/settings/test/webhook")
async def post_test_webhook(
    webhook_url: str = Form(...)
):
    try:
        test_payload = {
            "hostname": "test-host",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings_by_severity": {
                "info": [{"category": "test", "severity": "info", "field": "test_field", "old_value": "0", "new_value": "1", "timestamp": "now"}],
                "warning": [],
                "critical": []
            },
            "top_critical": []
        }
        await asyncio.to_thread(
            _send_webhook_sync,
            webhook_url,
            test_payload
        )
        return {"status": "success", "message": "Test webhook payload sent successfully"}
    except Exception as e:
        logger.error(f"Webhook test failed: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to send webhook test: {str(e)}")
