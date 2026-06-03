import datetime
import difflib
import logging
import pathlib
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("littleeye.agent.report")


def get_side_by_side_diff(old_text: str, new_text: str) -> List[Dict[str, Any]]:
    old_lines = old_text.splitlines() if old_text else []
    new_lines = new_text.splitlines() if new_text else []
    
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    diff_lines = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            for i, j in zip(range(i1, i2), range(j1, j2)):
                diff_lines.append({
                    "left_no": i + 1, "left_text": old_lines[i],
                    "right_no": j + 1, "right_text": new_lines[j],
                    "type": "equal"
                })
        elif tag == 'replace':
            max_len = max(i2 - i1, j2 - j1)
            for offset in range(max_len):
                o_idx = i1 + offset
                n_idx = j1 + offset
                left_no = o_idx + 1 if o_idx < i2 else None
                left_text = old_lines[o_idx] if o_idx < i2 else ""
                right_no = n_idx + 1 if n_idx < j2 else None
                right_text = new_lines[n_idx] if n_idx < j2 else ""
                diff_lines.append({
                    "left_no": left_no, "left_text": left_text,
                    "right_no": right_no, "right_text": right_text,
                    "type": "replace"
                })
        elif tag == 'delete':
            for i in range(i1, i2):
                diff_lines.append({
                    "left_no": i + 1, "left_text": old_lines[i],
                    "right_no": None, "right_text": "",
                    "type": "delete"
                })
        elif tag == 'insert':
            for j in range(j1, j2):
                diff_lines.append({
                    "left_no": None, "left_text": "",
                    "right_no": j + 1, "right_text": new_lines[j],
                    "type": "insert"
                })
    return diff_lines


def generate_html_report(
    hostname: str,
    timestamp: str,
    findings: List[Dict[str, Any]],
    output_file: str
) -> None:
    # 1. Group findings and count severities
    counts = {"info": 0, "warning": 0, "critical": 0}
    grouped_findings: Dict[str, List[Dict[str, Any]]] = {}

    processed_findings = []
    for f in findings:
        severity = f.get("severity", "info").lower()
        if severity in counts:
            counts[severity] += 1
            
        category = f.get("category", "other").lower()
        
        # Pre-process file content diffs if applicable
        f_copy = f.copy()
        if category == "files" and f.get("field", "").endswith(":content"):
            old_val = f.get("old_value") or ""
            new_val = f.get("new_value") or ""
            f_copy["file_diff"] = get_side_by_side_diff(old_val, new_val)
            
        processed_findings.append(f_copy)
        grouped_findings.setdefault(category, []).append(f_copy)

    # 2. Setup Jinja2 environment
    current_dir = pathlib.Path(__file__).parent.resolve()
    templates_dir = current_dir / "templates"
    
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True
    )
    
    try:
        template = env.get_template("report.html.j2")
        html_out = template.render(
            hostname=hostname,
            timestamp=timestamp,
            counts=counts,
            grouped_findings=grouped_findings,
            total_findings=len(findings)
        )
        
        out_path = pathlib.Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html_out, encoding="utf-8")
        logger.info(f"HTML report successfully generated at {out_path}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}", exc_info=True)
        raise
