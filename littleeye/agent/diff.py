import datetime
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

DEFAULT_SEVERITY_THRESHOLDS = {
    "files": "critical",
    "sudo_users": "critical",
    "ports": "warning",
    "services": "warning",
    "packages": "info",
    "env_vars": "info"
}


@dataclass
class Finding:
    category: str
    severity: str
    field: str
    old_value: Optional[str]
    new_value: Optional[str]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compare_snapshots(
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    severity_thresholds: Optional[Dict[str, str]] = None
) -> List[Finding]:
    thresholds = DEFAULT_SEVERITY_THRESHOLDS.copy()
    if severity_thresholds:
        thresholds.update(severity_thresholds)

    findings: List[Finding] = []
    
    current_ts_raw = current.get("timestamp", datetime.datetime.now().timestamp())
    timestamp = datetime.datetime.fromtimestamp(current_ts_raw, datetime.timezone.utc).isoformat()

    # 1. Compare Files
    base_files = baseline.get("files", {})
    curr_files = current.get("files", {})
    
    all_files = set(base_files.keys()).union(set(curr_files.keys()))
    severity_files = thresholds.get("files", "critical")
    for filepath in sorted(all_files):
        if filepath not in base_files:
            findings.append(Finding(
                category="files",
                severity=severity_files,
                field=f"{filepath}:status",
                old_value=None,
                new_value="present",
                timestamp=timestamp
            ))
        elif filepath not in curr_files:
            findings.append(Finding(
                category="files",
                severity=severity_files,
                field=f"{filepath}:status",
                old_value="present",
                new_value=None,
                timestamp=timestamp
            ))
        else:
            base_meta = base_files[filepath]
            curr_meta = curr_files[filepath]
            
            if base_meta.get("content") != curr_meta.get("content"):
                findings.append(Finding(
                    category="files",
                    severity=severity_files,
                    field=f"{filepath}:content",
                    old_value=base_meta.get("content"),
                    new_value=curr_meta.get("content"),
                    timestamp=timestamp
                ))
            if base_meta.get("permissions") != curr_meta.get("permissions"):
                findings.append(Finding(
                    category="files",
                    severity=severity_files,
                    field=f"{filepath}:permissions",
                    old_value=base_meta.get("permissions"),
                    new_value=curr_meta.get("permissions"),
                    timestamp=timestamp
                ))

    # 2. Compare Ports
    base_ports = baseline.get("ports", [])
    curr_ports = current.get("ports", [])
    
    def make_port_key(p: Dict[str, Any]) -> str:
        return f"{p.get('protocol', '')}:{p.get('address', '')}:{p.get('port', '')}"

    base_ports_dict = {make_port_key(p): p for p in base_ports}
    curr_ports_dict = {make_port_key(p): p for p in curr_ports}
    
    all_ports_keys = set(base_ports_dict.keys()).union(set(curr_ports_dict.keys()))
    severity_ports = thresholds.get("ports", "warning")
    for key in sorted(all_ports_keys):
        if key not in base_ports_dict:
            p_info = curr_ports_dict[key]
            findings.append(Finding(
                category="ports",
                severity=severity_ports,
                field=key,
                old_value=None,
                new_value=f"listening ({p_info.get('process', '')})",
                timestamp=timestamp
            ))
        elif key not in curr_ports_dict:
            p_info = base_ports_dict[key]
            findings.append(Finding(
                category="ports",
                severity=severity_ports,
                field=key,
                old_value=f"listening ({p_info.get('process', '')})",
                new_value=None,
                timestamp=timestamp
            ))
        else:
            bp = base_ports_dict[key]
            cp = curr_ports_dict[key]
            if bp.get("process") != cp.get("process"):
                findings.append(Finding(
                    category="ports",
                    severity=severity_ports,
                    field=f"{key}:process",
                    old_value=bp.get("process"),
                    new_value=cp.get("process"),
                    timestamp=timestamp
                ))

    # 3. Compare Sudo Users
    base_sudo = set(baseline.get("sudo_users", []))
    curr_sudo = set(current.get("sudo_users", []))
    severity_sudo = thresholds.get("sudo_users", "critical")
    
    for u in sorted(base_sudo - curr_sudo):
        findings.append(Finding(
            category="sudo_users",
            severity=severity_sudo,
            field=u,
            old_value="privileged",
            new_value="removed",
            timestamp=timestamp
        ))
    for u in sorted(curr_sudo - base_sudo):
        findings.append(Finding(
            category="sudo_users",
            severity=severity_sudo,
            field=u,
            old_value="none",
            new_value="privileged",
            timestamp=timestamp
        ))

    # 4. Compare Packages
    base_pkgs = baseline.get("packages", {})
    curr_pkgs = current.get("packages", {})
    all_pkgs = set(base_pkgs.keys()).union(set(curr_pkgs.keys()))
    severity_pkgs = thresholds.get("packages", "info")
    for pkg in sorted(all_pkgs):
        if pkg not in base_pkgs:
            findings.append(Finding(
                category="packages",
                severity=severity_pkgs,
                field=pkg,
                old_value=None,
                new_value=curr_pkgs[pkg],
                timestamp=timestamp
            ))
        elif pkg not in curr_pkgs:
            findings.append(Finding(
                category="packages",
                severity=severity_pkgs,
                field=pkg,
                old_value=base_pkgs[pkg],
                new_value=None,
                timestamp=timestamp
            ))
        elif base_pkgs[pkg] != curr_pkgs[pkg]:
            findings.append(Finding(
                category="packages",
                severity=severity_pkgs,
                field=pkg,
                old_value=base_pkgs[pkg],
                new_value=curr_pkgs[pkg],
                timestamp=timestamp
            ))

    # 5. Compare Services
    base_svcs = baseline.get("services", {})
    curr_svcs = current.get("services", {})
    all_svcs = set(base_svcs.keys()).union(set(curr_svcs.keys()))
    severity_svcs = thresholds.get("services", "warning")
    for svc in sorted(all_svcs):
        if svc not in base_svcs:
            findings.append(Finding(
                category="services",
                severity=severity_svcs,
                field=svc,
                old_value=None,
                new_value=curr_svcs[svc],
                timestamp=timestamp
            ))
        elif svc not in curr_svcs:
            findings.append(Finding(
                category="services",
                severity=severity_svcs,
                field=svc,
                old_value=base_svcs[svc],
                new_value=None,
                timestamp=timestamp
            ))
        elif base_svcs[svc] != curr_svcs[svc]:
            findings.append(Finding(
                category="services",
                severity=severity_svcs,
                field=svc,
                old_value=base_svcs[svc],
                new_value=curr_svcs[svc],
                timestamp=timestamp
            ))

    # 6. Compare Process Env Vars
    base_env = baseline.get("env_vars", {})
    curr_env = current.get("env_vars", {})
    shared_procs = set(base_env.keys()).intersection(set(curr_env.keys()))
    severity_env = thresholds.get("env_vars", "info")
    for proc_name in sorted(shared_procs):
        bp_env = base_env[proc_name]
        cp_env = curr_env[proc_name]
        all_vars = set(bp_env.keys()).union(set(cp_env.keys()))
        for var in sorted(all_vars):
            if var not in bp_env:
                findings.append(Finding(
                    category="env_vars",
                    severity=severity_env,
                    field=f"{proc_name}:{var}",
                    old_value=None,
                    new_value=cp_env[var],
                    timestamp=timestamp
                ))
            elif var not in cp_env:
                findings.append(Finding(
                    category="env_vars",
                    severity=severity_env,
                    field=f"{proc_name}:{var}",
                    old_value=bp_env[var],
                    new_value=None,
                    timestamp=timestamp
                ))
            elif bp_env[var] != cp_env[var]:
                findings.append(Finding(
                    category="env_vars",
                    severity=severity_env,
                    field=f"{proc_name}:{var}",
                    old_value=bp_env[var],
                    new_value=cp_env[var],
                    timestamp=timestamp
                ))

    return findings
