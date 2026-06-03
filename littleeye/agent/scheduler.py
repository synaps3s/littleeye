import json
import logging
import pathlib
import socket
import sys
import time
from typing import Any, Dict, List, Tuple
import requests
import schedule

from littleeye.agent.snapshot import take_snapshot
from littleeye.agent.diff import compare_snapshots
from littleeye.agent.config import AgentConfig
from littleeye.agent.report import generate_html_report

logger = logging.getLogger("littleeye.agent.scheduler")


def get_server_info() -> Tuple[str, str]:
    hostname = socket.gethostname()
    server_id = hostname.lower().replace(".", "-")
    return server_id, hostname


def perform_check_flow(config: AgentConfig) -> bool:
    """
    Performs the check flow.
    Returns True if a check was performed, or False if a baseline was initialized and we exited.
    """
    server_id, hostname = get_server_info()
    
    # Ensure baseline and report directories exist
    baseline_dir = pathlib.Path(config.baseline_dir)
    report_dir = pathlib.Path(config.report_dir)
    baseline_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    
    baseline_path = baseline_dir / "baseline.json"
    
    # 1. No baseline: take snapshot, save and exit
    if not baseline_path.exists():
        logger.info("No baseline configuration snapshot found. Initializing baseline...")
        snapshot = take_snapshot(config.watched_files)
        
        try:
            baseline_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            logger.info(f"Baseline configuration snapshot written to {baseline_path}")
        except Exception as e:
            logger.error(f"Failed to write baseline snapshot: {e}", exc_info=True)
            sys.exit(1)
            
        logger.info("Baseline initialized successfully. Exiting.")
        sys.exit(0)

    # 2. Baseline exists: take current snapshot and compare
    logger.info("Starting drift check comparison against baseline...")
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Failed to load baseline snapshot: {e}. Please run 'init' again.", exc_info=True)
        sys.exit(1)

    current = take_snapshot(config.watched_files)
    findings = compare_snapshots(baseline, current, config.severity_thresholds)
    findings_dicts = [f.to_dict() for f in findings]
    
    # Save the latest diff details so 'report' command can run offline
    latest_diff_path = report_dir / "latest_diff.json"
    try:
        diff_payload = {
            "hostname": hostname,
            "timestamp": current["timestamp"],
            "findings": findings_dicts
        }
        latest_diff_path.write_text(json.dumps(diff_payload, indent=2), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to write latest diff file: {e}")

    # Generate HTML report if there is drift
    if len(findings_dicts) > 0:
        logger.info(f"Drift detected: {len(findings_dicts)} findings found.")
        formatted_ts = time.strftime("%Y%m%d-%H%M%S", time.localtime(current["timestamp"]))
        report_html_path = report_dir / f"report_{formatted_ts}.html"
        
        # Write both timestamped and static 'report_latest.html'
        try:
            generate_html_report(
                hostname=hostname,
                timestamp=time.ctime(current["timestamp"]),
                findings=findings_dicts,
                output_file=str(report_html_path)
            )
            # Link/copy to latest
            generate_html_report(
                hostname=hostname,
                timestamp=time.ctime(current["timestamp"]),
                findings=findings_dicts,
                output_file=str(report_dir / "report_latest.html")
            )
        except Exception as e:
            logger.error(f"Failed to generate HTML reports: {e}")
    else:
        logger.info("No configuration drift detected.")

    # 3. Push results to the dashboard
    logger.info(f"Pushing results to dashboard at {config.dashboard_url}...")
    url = f"{config.dashboard_url.rstrip('/')}/api/agent/report"
    headers = {
        "Authorization": f"Bearer {config.agent_token}",
        "Content-Type": "application/json"
    }
    
    # We convert the current timestamp to ISO 8601 string or readable string
    payload = {
        "server_id": server_id,
        "hostname": hostname,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current["timestamp"])),
        "findings": findings_dicts,
        "os_info": current.get("os_info")
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        logger.info("Successfully pushed drift report to central dashboard.")
    except Exception as e:
        logger.error(f"Failed to push drift report to dashboard: {e}")
        
    return True


def start_scheduler(config: AgentConfig) -> None:
    # First execution happens immediately. If first run, it will init baseline and exit process.
    perform_check_flow(config)

    # Subsequent schedules
    schedule.every(config.check_interval_minutes).minutes.do(perform_check_flow, config)
    logger.info(f"Scheduler started. Running drift checks every {config.check_interval_minutes} minutes.")
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Scheduler daemon stopped by user request.")
