import os
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from littleeye.dashboard.auth import get_agent
from littleeye.dashboard.db import (
    upsert_server,
    add_drift_report,
    get_servers,
    get_server_history,
    get_drift_report
)
from littleeye.dashboard.settings import load_config
# We will implement send_alerts in notify.py
from littleeye.agent.notify import send_alerts, check_severity_threshold

logger = logging.getLogger("littleeye.dashboard.api")
DB_PATH = os.environ.get("LITTLEEYE_DB_PATH", "data/littleeye.db")

router = APIRouter(prefix="/api")


class FindingModel(BaseModel):
    category: str
    severity: str
    field: str
    old_value: Any = None
    new_value: Any = None
    timestamp: str


class ReportPayload(BaseModel):
    server_id: str
    hostname: str
    timestamp: str
    findings: List[FindingModel]
    os_info: Optional[Dict[str, str]] = None


@router.post("/agent/report")
async def receive_report(payload: ReportPayload, agent_token: str = Depends(get_agent)):
    try:
        findings_dicts = [f.dict() for f in payload.findings]
        status_val = "drift" if len(findings_dicts) > 0 else "clean"
        
        os_info = payload.os_info or {}
        os_name = os_info.get("os_name", "")
        kernel = os_info.get("kernel", "")
        arch = os_info.get("arch", "")

        # Save to database
        await upsert_server(
            DB_PATH,
            server_id=payload.server_id,
            hostname=payload.hostname,
            last_seen=payload.timestamp,
            status=status_val,
            os_name=os_name,
            kernel=kernel,
            arch=arch
        )
        
        await add_drift_report(
            DB_PATH,
            server_id=payload.server_id,
            timestamp=payload.timestamp,
            findings=findings_dicts
        )
        
        # Trigger notification if there are findings
        if len(findings_dicts) > 0:
            config = await load_config()
            # Filter findings that meet the alert severity threshold
            alertable_findings = [
                f for f in findings_dicts 
                if check_severity_threshold(f["severity"], config.alert_severity_threshold)
            ]
            
            if alertable_findings:
                # Run the notification sender in a non-blocking/handled way
                try:
                    await send_alerts(
                        hostname=payload.hostname,
                        timestamp=payload.timestamp,
                        findings=alertable_findings,
                        config=config
                    )
                except Exception as e:
                    logger.error(f"Failed to send alerts for {payload.hostname}: {e}")

        return {"status": "success", "message": "Report processed successfully"}
    except Exception as e:
        logger.error(f"Error processing agent report: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/servers")
async def list_servers():
    try:
        servers = await get_servers(DB_PATH)
        return servers
    except Exception as e:
        logger.error(f"Error fetching servers list: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/server/{server_id}/history")
async def server_history(server_id: str):
    try:
        history = await get_server_history(DB_PATH, server_id)
        return history
    except Exception as e:
        logger.error(f"Error fetching history for server {server_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/server/{server_id}/report/{timestamp}")
async def server_report(server_id: str, timestamp: str):
    try:
        report = await get_drift_report(DB_PATH, server_id, timestamp)
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )
        return report
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching report for server {server_id} at {timestamp}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
