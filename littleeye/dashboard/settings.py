import os
import logging
from dataclasses import dataclass
from typing import Dict, Optional
from littleeye.dashboard.db import get_settings, save_settings

logger = logging.getLogger("littleeye.dashboard.settings")

DB_PATH = os.environ.get("LITTLEEYE_DB_PATH", "data/littleeye.db")


@dataclass
class DashboardConfig:
    telegram_enabled: bool
    telegram_token: str
    telegram_chat_id: str
    webhook_enabled: bool
    webhook_url: str
    alert_severity_threshold: str  # info, warning, critical


async def load_config() -> DashboardConfig:
    raw = await get_settings(DB_PATH)
    return DashboardConfig(
        telegram_enabled=raw.get("telegram_enabled", "false").lower() == "true",
        telegram_token=raw.get("telegram_token", ""),
        telegram_chat_id=raw.get("telegram_chat_id", ""),
        webhook_enabled=raw.get("webhook_enabled", "false").lower() == "true",
        webhook_url=raw.get("webhook_url", ""),
        alert_severity_threshold=raw.get("alert_severity_threshold", "warning")
    )


async def update_config(config: DashboardConfig) -> None:
    settings_dict = {
        "telegram_enabled": "true" if config.telegram_enabled else "false",
        "telegram_token": config.telegram_token,
        "telegram_chat_id": config.telegram_chat_id,
        "webhook_enabled": "true" if config.webhook_enabled else "false",
        "webhook_url": config.webhook_url,
        "alert_severity_threshold": config.alert_severity_threshold
    }
    await save_settings(DB_PATH, settings_dict)
