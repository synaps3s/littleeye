import pytest
import datetime
from littleeye.agent.snapshot import take_snapshot
from littleeye.agent.diff import compare_snapshots, Finding


@pytest.fixture
def fake_snapshots():
    baseline_timestamp = 1600000000.0
    current_timestamp = 1600003600.0

    baseline = {
        "timestamp": baseline_timestamp,
        "files": {
            "/etc/ssh/sshd_config": {
                "permissions": "0644",
                "content": "PermitRootLogin no\nPasswordAuthentication yes\n"
            },
            "/etc/passwd": {
                "permissions": "0644",
                "content": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ports": [
            {"protocol": "tcp", "address": "0.0.0.0", "port": 22, "process": 'users:(("sshd",pid=100,fd=3))'},
            {"protocol": "tcp", "address": "127.0.0.1", "port": 53, "process": 'users:(("named",pid=101,fd=4))'}
        ],
        "sudo_users": ["root", "davide"],
        "packages": {
            "openssh-server": "1:8.2p1-4ubuntu0.5",
            "nginx": "1.18.0-0ubuntu1"
        },
        "services": {
            "ssh": "running",
            "nginx": "running"
        },
        "env_vars": {
            "nginx": {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "NGINX_VERSION": "1.18.0"
            }
        }
    }

    current = {
        "timestamp": current_timestamp,
        "files": {
            "/etc/ssh/sshd_config": {
                "permissions": "0600",
                "content": "PermitRootLogin yes\nPasswordAuthentication yes\n"
            },
            "/etc/passwd": {
                "permissions": "0644",
                "content": "root:x:0:0:root:/root:/bin/bash\n"
            },
            "/etc/hosts": {
                "permissions": "0644",
                "content": "127.0.0.1 localhost\n"
            }
        },
        "ports": [
            {"protocol": "tcp", "address": "0.0.0.0", "port": 22, "process": 'users:(("sshd",pid=100,fd=3))'},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 80, "process": 'users:(("nginx",pid=102,fd=5))'}
        ],
        "sudo_users": ["root"],
        "packages": {
            "openssh-server": "1:8.2p1-4ubuntu0.6",
            "curl": "7.68.0-1ubuntu2.13"
        },
        "services": {
            "ssh": "running",
            "nginx": "stopped"
        },
        "env_vars": {
            "nginx": {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "NGINX_VERSION": "1.18.0",
                "NEW_VAR": "value"
            }
        }
    }
    
    current["sudo_users"].append("malicious")

    return baseline, current


def test_compare_snapshots(fake_snapshots):
    baseline, current = fake_snapshots
    findings = compare_snapshots(baseline, current)

    findings_dict = [f.to_dict() for f in findings]

    assert any(
        f["category"] == "files" and f["field"] == "/etc/hosts:status" and f["new_value"] == "present"
        for f in findings_dict
    )
    assert any(
        f["category"] == "files" and f["field"] == "/etc/ssh/sshd_config:content" and "PermitRootLogin yes" in f["new_value"]
        for f in findings_dict
    )
    assert any(
        f["category"] == "files" and f["field"] == "/etc/ssh/sshd_config:permissions" and f["old_value"] == "0644" and f["new_value"] == "0600"
        for f in findings_dict
    )

    assert any(
        f["category"] == "ports" and f["field"] == "tcp:127.0.0.1:53" and f["new_value"] is None
        for f in findings_dict
    )
    assert any(
        f["category"] == "ports" and f["field"] == "tcp:0.0.0.0:80" and "nginx" in f["new_value"]
        for f in findings_dict
    )

    assert any(
        f["category"] == "sudo_users" and f["field"] == "davide" and f["new_value"] == "removed"
        for f in findings_dict
    )
    assert any(
        f["category"] == "sudo_users" and f["field"] == "malicious" and f["new_value"] == "privileged"
        for f in findings_dict
    )

    assert any(
        f["category"] == "packages" and f["field"] == "openssh-server" and f["old_value"] == "1:8.2p1-4ubuntu0.5" and f["new_value"] == "1:8.2p1-4ubuntu0.6"
        for f in findings_dict
    )
    assert any(
        f["category"] == "packages" and f["field"] == "nginx" and f["old_value"] == "1.18.0-0ubuntu1" and f["new_value"] is None
        for f in findings_dict
    )
    assert any(
        f["category"] == "packages" and f["field"] == "curl" and f["old_value"] is None and f["new_value"] == "7.68.0-1ubuntu2.13"
        for f in findings_dict
    )

    assert any(
        f["category"] == "services" and f["field"] == "nginx" and f["old_value"] == "running" and f["new_value"] == "stopped"
        for f in findings_dict
    )

    assert any(
        f["category"] == "env_vars" and f["field"] == "nginx:NEW_VAR" and f["old_value"] is None and f["new_value"] == "value"
        for f in findings_dict
    )


def test_snapshot_generation():
    watched = ["/etc/passwd", "/etc/hosts"]
    snap = take_snapshot(watched)
    assert isinstance(snap, dict)
    assert "timestamp" in snap
    assert "files" in snap
    assert "ports" in snap
    assert "sudo_users" in snap
    assert "packages" in snap
    assert "services" in snap
    assert "env_vars" in snap
