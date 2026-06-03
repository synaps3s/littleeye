import argparse
import json
import logging
import pathlib
import sys
import time

from littleeye.agent.config import load_config
from littleeye.agent.snapshot import take_snapshot
from littleeye.agent.scheduler import perform_check_flow, start_scheduler, get_server_info
from littleeye.agent.report import generate_html_report

logger = logging.getLogger("littleeye.agent.cli")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )


def cmd_init(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    baseline_dir = pathlib.Path(config.baseline_dir)
    baseline_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = baseline_dir / "baseline.json"

    logger.info("Taking baseline system snapshot...")
    snapshot = take_snapshot(config.watched_files)
    
    try:
        baseline_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        logger.info(f"Baseline configuration snapshot successfully written to {baseline_path}")
    except Exception as e:
        logger.error(f"Failed to write baseline configuration snapshot: {e}", exc_info=True)
        sys.exit(1)


def cmd_check(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    logger.info("Running manual drift check...")
    perform_check_flow(config)


def cmd_report(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    report_dir = pathlib.Path(config.report_dir)
    latest_diff_path = report_dir / "latest_diff.json"

    if not latest_diff_path.exists():
        logger.error(f"No recent diff findings found at {latest_diff_path}. Run a drift check first.")
        sys.exit(1)

    try:
        diff_data = json.loads(latest_diff_path.read_text(encoding="utf-8"))
        hostname = diff_data["hostname"]
        timestamp = time.ctime(diff_data["timestamp"])
        findings = diff_data["findings"]
    except Exception as e:
        logger.error(f"Failed to load recent diff data: {e}", exc_info=True)
        sys.exit(1)

    output_path = args.output or str(report_dir / "report_latest.html")
    logger.info(f"Generating HTML report from latest diff findings...")
    try:
        generate_html_report(
            hostname=hostname,
            timestamp=timestamp,
            findings=findings,
            output_file=output_path
        )
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}", exc_info=True)
        sys.exit(1)


def cmd_daemon(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    logger.info("Starting LittleEye scheduler daemon...")
    start_scheduler(config)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LittleEye Configuration Drift Detector Agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging output"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Agent subcommands")

    # init parser
    subparsers.add_parser("init", help="Capture baseline snapshot and exit")

    # check parser
    subparsers.add_parser("check", help="Run drift check snapshot comparison and push to dashboard")

    # report parser
    report_parser = subparsers.add_parser("report", help="Generate HTML report from the latest diff")
    report_parser.add_argument(
        "-o", "--output",
        help="Output HTML path (defaults to report_dir/report_latest.html)"
    )

    # daemon parser
    subparsers.add_parser("daemon", help="Run drift watch agent scheduler daemon")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.command == "init":
        cmd_init(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "daemon":
        cmd_daemon(args)


if __name__ == "__main__":
    main()
