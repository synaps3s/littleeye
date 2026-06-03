import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List
import yaml

logger = logging.getLogger("littleeye.agent.config")

DEFAULT_WATCHED_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/fstab",
    "/etc/crontab",
    "/etc/iptables/rules.v4"
]

DEFAULT_SEVERITY_THRESHOLDS = {
    "files": "critical",
    "sudo_users": "critical",
    "ports": "warning",
    "services": "warning",
    "packages": "info",
    "env_vars": "info"
}


@dataclass
class AgentConfig:
    check_interval_minutes: int = 60
    dashboard_url: str = "http://localhost:8000"
    agent_token: str = "default-agent-token"
    baseline_dir: str = "data/baselines"
    report_dir: str = "data/reports"
    severity_thresholds: Dict[str, str] = field(default_factory=lambda: DEFAULT_SEVERITY_THRESHOLDS.copy())
    watched_files: List[str] = field(default_factory=lambda: DEFAULT_WATCHED_FILES.copy())


def load_config(config_path: str) -> AgentConfig:
    path = pathlib.Path(config_path)
    if not path.exists():
        logger.warning(f"Configuration file not found at {config_path}. Using default settings.")
        return AgentConfig()

    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            
        severity_thresholds = DEFAULT_SEVERITY_THRESHOLDS.copy()
        if "severity_thresholds" in data and isinstance(data["severity_thresholds"], dict):
            severity_thresholds.update(data["severity_thresholds"])
            
        watched_files = data.get("watched_files", DEFAULT_WATCHED_FILES)
        if not isinstance(watched_files, list):
            watched_files = DEFAULT_WATCHED_FILES

        import os
        config = AgentConfig(
            check_interval_minutes=int(data.get("check_interval_minutes", 60)),
            dashboard_url=data.get("dashboard_url", "http://localhost:8000"),
            agent_token=data.get("agent_token", "default-agent-token"),
            baseline_dir=data.get("baseline_dir", "data/baselines"),
            report_dir=data.get("report_dir", "data/reports"),
            severity_thresholds=severity_thresholds,
            watched_files=watched_files
        )

        # Allow environment variable overrides for Docker/container configuration
        if "LITTLEEYE_AGENT_TOKEN" in os.environ:
            config.agent_token = os.environ["LITTLEEYE_AGENT_TOKEN"]
        if "LITTLEEYE_CHECK_INTERVAL" in os.environ:
            try:
                config.check_interval_minutes = int(os.environ["LITTLEEYE_CHECK_INTERVAL"])
            except ValueError:
                pass
        if "LITTLEEYE_DASHBOARD_URL" in os.environ:
            config.dashboard_url = os.environ["LITTLEEYE_DASHBOARD_URL"]
        if "LITTLEEYE_BASELINE_DIR" in os.environ:
            config.baseline_dir = os.environ["LITTLEEYE_BASELINE_DIR"]
        if "LITTLEEYE_REPORT_DIR" in os.environ:
            config.report_dir = os.environ["LITTLEEYE_REPORT_DIR"]

        return config
    except Exception as e:
        logger.error(f"Error loading configuration from {config_path}: {e}. Using defaults.", exc_info=True)
        import os
        config = AgentConfig()
        if "LITTLEEYE_AGENT_TOKEN" in os.environ:
            config.agent_token = os.environ["LITTLEEYE_AGENT_TOKEN"]
        if "LITTLEEYE_CHECK_INTERVAL" in os.environ:
            try:
                config.check_interval_minutes = int(os.environ["LITTLEEYE_CHECK_INTERVAL"])
            except ValueError:
                pass
        if "LITTLEEYE_DASHBOARD_URL" in os.environ:
            config.dashboard_url = os.environ["LITTLEEYE_DASHBOARD_URL"]
        if "LITTLEEYE_BASELINE_DIR" in os.environ:
            config.baseline_dir = os.environ["LITTLEEYE_BASELINE_DIR"]
        if "LITTLEEYE_REPORT_DIR" in os.environ:
            config.report_dir = os.environ["LITTLEEYE_REPORT_DIR"]
        return config
