import json
import logging
import pathlib
import subprocess
import time
import platform
from typing import Any, Dict, List, Set, Optional

logger = logging.getLogger("littleeye.agent.snapshot")

try:
    import grp
    import pwd
except ImportError:
    grp = None  # type: ignore
    pwd = None  # type: ignore


def get_file_metadata(filepath: pathlib.Path) -> Optional[Dict[str, Any]]:
    try:
        if not filepath.exists():
            return None
        stat_info = filepath.stat()
        permissions = oct(stat_info.st_mode & 0o777)
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Could not read content of {filepath}: {e}")
            content = ""
        return {
            "permissions": permissions,
            "content": content
        }
    except Exception as e:
        logger.error(f"Error accessing metadata for {filepath}: {e}")
        return None


def get_listening_ports() -> List[Dict[str, Any]]:
    ports = []
    # Try ss -tulpn first (Linux standard)
    try:
        res = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True,
            text=True,
            check=True,
            env={"LANG": "C"}
        )
        lines = res.stdout.strip().split("\n")
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            netid = parts[0]
            local = parts[4]
            process_info = ""
            if len(parts) >= 7:
                process_info = parts[6]
            
            if ":" in local:
                addr, port_str = local.rsplit(":", 1)
                try:
                    port = int(port_str)
                    ports.append({
                        "protocol": netid,
                        "address": addr,
                        "port": port,
                        "process": process_info
                    })
                except ValueError:
                    pass
        return ports
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Fallback to lsof (macOS and Linux backup)
    try:
        res = subprocess.run(
            ["lsof", "-i", "-P", "-n"],
            capture_output=True,
            text=True,
            check=True,
            env={"LANG": "C"}
        )
        lines = res.stdout.strip().split("\n")
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 8:
                continue
            proc_name = parts[0]
            pid = parts[1]
            proto = parts[7].lower()
            name_col = parts[8]
            is_listen = "(LISTEN)" in line or proto == "udp"
            if not is_listen:
                continue
            
            if ":" in name_col:
                addr, port_str = name_col.rsplit(":", 1)
                try:
                    port = int(port_str)
                    ports.append({
                        "protocol": proto,
                        "address": addr,
                        "port": port,
                        "process": f'users:(("{proc_name}",pid={pid}))'
                    })
                except ValueError:
                    pass
        return ports
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.warning("Could not execute ss or lsof to retrieve listening ports.")
        return []


def get_sudo_users() -> List[str]:
    users: Set[str] = set()
    if grp is None or pwd is None:
        return []
    
    for group_name in ["sudo", "wheel", "admin"]:
        try:
            g = grp.getgrnam(group_name)
            users.update(g.gr_mem)
        except KeyError:
            pass

    try:
        for p in pwd.getpwall():
            if p.pw_uid == 0:
                users.add(p.pw_name)
    except Exception as e:
        logger.error(f"Error querying local password database: {e}")
        
    return sorted(list(users))


def get_installed_packages() -> Dict[str, str]:
    packages = {}
    try:
        res = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in res.stdout.strip().split("\n"):
            if "\t" in line:
                pkg, ver = line.split("\t", 1)
                packages[pkg] = ver
        return packages
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        res = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in res.stdout.strip().split("\n"):
            if "\t" in line:
                pkg, ver = line.split("\t", 1)
                packages[pkg] = ver
        return packages
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        res = subprocess.run(
            ["brew", "list", "--versions"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in res.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                packages[parts[0]] = parts[1]
        return packages
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    logger.warning("Could not execute a package manager query.")
    return {}


def get_running_services() -> Dict[str, str]:
    services = {}
    try:
        res = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in res.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                srv_name = parts[0]
                if srv_name.endswith(".service"):
                    srv_name = srv_name[:-8]
                sub_state = parts[3]
                services[srv_name] = sub_state
        return services
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        res = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in res.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 3:
                label = parts[2]
                pid_val = parts[0]
                state = "running" if pid_val != "-" else "stopped"
                services[label] = state
        return services
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    logger.warning("Could not execute systemctl or launchctl to get services.")
    return {}


def get_process_env_vars() -> Dict[str, Dict[str, str]]:
    process_envs: Dict[str, Dict[str, str]] = {}
    proc_path = pathlib.Path("/proc")
    if not proc_path.exists():
        return {}

    try:
        for p_dir in proc_path.iterdir():
            if not p_dir.is_dir() or not p_dir.name.isdigit():
                continue
            
            pid = p_dir.name
            try:
                cmdline_path = p_dir / "cmdline"
                if not cmdline_path.exists():
                    continue
                cmd_content = cmdline_path.read_bytes()
                if not cmd_content:
                    continue
                cmd_parts = cmd_content.split(b"\x00")
                proc_name = pathlib.Path(cmd_parts[0].decode("utf-8", errors="ignore")).name
                if not proc_name:
                    continue

                environ_path = p_dir / "environ"
                if not environ_path.exists():
                    continue
                env_content = environ_path.read_bytes()
                env_vars = {}
                for item in env_content.split(b"\x00"):
                    if not item:
                        continue
                    try:
                        decoded_item = item.decode("utf-8", errors="ignore")
                        if "=" in decoded_item:
                            key, val = decoded_item.split("=", 1)
                            env_vars[key] = val
                    except Exception:
                        pass
                
                if env_vars:
                    if proc_name not in process_envs:
                        process_envs[proc_name] = {}
                    process_envs[proc_name].update(env_vars)

            except (PermissionError, FileNotFoundError):
                continue
            except Exception as e:
                logger.debug(f"Error reading process environmental variables for PID {pid}: {e}")
    except Exception as e:
        logger.error(f"Error accessing /proc directory: {e}")

    return process_envs


def get_os_info() -> Dict[str, str]:
    info = {
        "os_name": platform.system(),
        "kernel": platform.release(),
        "arch": platform.machine()
    }
    try:
        os_release = pathlib.Path("/etc/os-release")
        if os_release.exists():
            lines = os_release.read_text(encoding="utf-8").splitlines()
            for line in lines:
                if line.startswith("PRETTY_NAME="):
                    info["os_name"] = line.split("=", 1)[1].strip('"')
                    break
    except Exception:
        pass
    return info


def take_snapshot(watched_files: List[str]) -> Dict[str, Any]:
    timestamp = float(time.time())
    files_snapshot = {}
    for f in watched_files:
        p = pathlib.Path(f)
        meta = get_file_metadata(p)
        if meta is not None:
            files_snapshot[f] = meta

    return {
        "timestamp": timestamp,
        "files": files_snapshot,
        "ports": get_listening_ports(),
        "sudo_users": get_sudo_users(),
        "packages": get_installed_packages(),
        "services": get_running_services(),
        "env_vars": get_process_env_vars(),
        "os_info": get_os_info()
    }
