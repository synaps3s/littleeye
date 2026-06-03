import asyncio
import logging
from typing import Any, Dict, List
import requests

logger = logging.getLogger("littleeye.agent.notify")

SEVERITY_LEVELS = {
    "info": 1,
    "warning": 2,
    "critical": 3
}


def check_severity_threshold(finding_severity: str, threshold: str) -> bool:
    f_val = SEVERITY_LEVELS.get(finding_severity.lower(), 1)
    t_val = SEVERITY_LEVELS.get(threshold.lower(), 2)
    return f_val >= t_val


def _send_telegram_sync(token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Telegram API request failed: {e}")
        raise


def _send_webhook_sync(url: str, payload: Dict[str, Any]) -> None:
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Webhook request failed: {e}")
        raise


async def send_alerts(hostname: str, timestamp: str, findings: List[Dict[str, Any]], config: Any) -> None:
    # 1. Format text for Telegram
    if config.telegram_enabled and config.telegram_token and config.telegram_chat_id:
        text = f"<b>LittleEye Alert: Configuration Drift Detected</b>\n"
        text += f"Server: {hostname}\n"
        text += f"Timestamp: {timestamp}\n\n"
        
        # Group by severity for summary
        counts: Dict[str, int] = {"info": 0, "warning": 0, "critical": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in counts:
                counts[sev] += 1
                
        text += f"Summary:\n"
        text += f"- Critical: {counts['critical']}\n"
        text += f"- Warning: {counts['warning']}\n"
        text += f"- Info: {counts['info']}\n\n"
        
        text += "Top Findings:\n"
        # Sort by severity critical first
        sorted_findings = sorted(
            findings,
            key=lambda x: SEVERITY_LEVELS.get(x["severity"].lower(), 1),
            reverse=True
        )
        for f in sorted_findings[:10]:
            category = f["category"].upper()
            sev = f["severity"].upper()
            field = f["field"]
            text += f"[{sev}] {category} - {field}\n"
            
        if len(findings) > 10:
            text += f"...and {len(findings) - 10} more findings.\n"
            
        logger.info(f"Sending Telegram alert for {hostname}...")
        await asyncio.to_thread(
            _send_telegram_sync,
            config.telegram_token,
            config.telegram_chat_id,
            text
        )

    # 2. Format payload for Webhook
    if config.webhook_enabled and config.webhook_url:
        findings_by_severity: Dict[str, List[Dict[str, Any]]] = {
            "info": [],
            "warning": [],
            "critical": []
        }
        for f in findings:
            sev = f["severity"].lower()
            if sev in findings_by_severity:
                findings_by_severity[sev].append(f)
            else:
                findings_by_severity.setdefault(sev, []).append(f)
                
        # Top critical findings
        top_critical = sorted(
            findings_by_severity.get("critical", []),
            key=lambda x: x.get("field", "")
        )[:10]
        
        webhook_payload = {
            "hostname": hostname,
            "timestamp": timestamp,
            "findings_by_severity": findings_by_severity,
            "top_critical": top_critical
        }
        
        logger.info(f"Sending Webhook alert for {hostname}...")
        await asyncio.to_thread(
            _send_webhook_sync,
            config.webhook_url,
            webhook_payload
        )
