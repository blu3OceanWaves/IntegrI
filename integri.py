#!/usr/bin/env python3
"""
IntegrI - System Integrity & Change Detection Tool

Features:
 - scan, diff, watch commands
 - recursive / no-recursive support
 - atomic writes for baseline JSON
 - permission error reporting
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pwd
import signal
import subprocess
import sys
import time
from pathlib import Path
from threading import Thread, Event, Lock
from typing import Dict, Any, Iterable, List, Optional

# ────────────── Colors ──────────────
class Colors:
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ORANGE = "\033[33m"
    HEADER = "\033[95m"
    BOLD = "\033[1m"
    ENDC = "\033[0m"

# ────────────── Globals ──────────────
spinner_chars = ["|", "/", "-", "\\"]
print_lock = Lock()  # ensure spinner vs prints don't interleave

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

# ────────────── Exit handling ──────────────
def c_exit(signum=None, frame=None):
    safe_print(f"\n{Colors.HEADER}EXITED{Colors.ENDC}")
    sys.exit(0)

signal.signal(signal.SIGINT, c_exit)
# SIGTERM not available on some platforms? typically available on Unix
try:
    signal.signal(signal.SIGTERM, c_exit)
except Exception:
    pass

# ────────────── Spinner ──────────────
def spinner(msg: str, stop_event: Event):
    i = 0
    while not stop_event.is_set():
        with print_lock:
            sys.stdout.write(f"\r{msg} {spinner_chars[i % len(spinner_chars)]}")
            sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    # clear spinner line
    with print_lock:
        sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r")
        sys.stdout.flush()

# ────────────── Utilities ──────────────
def resolve_path_safe(p: str) -> str:
    pth = Path(p).expanduser()
    try:
        return str(pth.resolve(strict=False))
    except Exception:
        # fallback to absolute
        return str(pth.absolute())

def atomic_write_json(path: str, data: Any) -> None:
    tmp = Path(path).with_suffix(path + ".tmp") if False else (Path(path).with_suffix(".tmp"))
    # ensure parent exists
    tmp_parent = tmp.parent
    tmp_parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    # atomic replace
    os.replace(str(tmp), str(path))

def safe_hash(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ────────────── Scanners ──────────────
def scan_logs(log_dir: str, recursive: bool = True, ignore_files: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
    log_dir_p = Path(log_dir).expanduser()
    try:
        log_dir_res = log_dir_p.resolve(strict=False)
    except Exception:
        log_dir_res = log_dir_p.absolute()
    ignore_set = set(Path(x).resolve(strict=False) for x in (ignore_files or []))
    data: Dict[str, Dict[str, Any]] = {}
    permission_error_seen = False

    try:
        if recursive:
            for root, _, files in os.walk(log_dir_res):
                for f in files:
                    path = Path(root) / f
                    try:
                        if path.resolve(strict=False) in ignore_set:
                            continue
                        stat = path.stat()
                        data[str(path)] = {"size": stat.st_size, "mtime": stat.st_mtime}
                    except PermissionError:
                        permission_error_seen = True
                        continue
                    except FileNotFoundError:
                        # file removed mid-scan
                        continue
        else:
            for f in log_dir_res.iterdir():
                if not f.is_file():
                    continue
                try:
                    if f.resolve(strict=False) in ignore_set:
                        continue
                    stat = f.stat()
                    data[str(f)] = {"size": stat.st_size, "mtime": stat.st_mtime}
                except PermissionError:
                    permission_error_seen = True
                    continue
                except FileNotFoundError:
                    continue
    except Exception:
        # top-level errors should not crash; return what we have
        pass

    if permission_error_seen:
        safe_print(f"{Colors.ORANGE}Warning: some log files could not be read (permission denied).{Colors.ENDC}")
    return data

def scan_files(scan_dir: str, recursive: bool = True, ignore_files: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
    scan_dir_p = Path(scan_dir).expanduser()
    try:
        scan_dir_res = scan_dir_p.resolve(strict=False)
    except Exception:
        scan_dir_res = scan_dir_p.absolute()
    ignore_set = set(Path(x).resolve(strict=False) for x in (ignore_files or []))
    data: Dict[str, Dict[str, Any]] = {}
    permission_error_seen = False

    try:
        if recursive:
            for root, _, files in os.walk(scan_dir_res):
                for f in files:
                    path = Path(root) / f
                    try:
                        if path.resolve(strict=False) in ignore_set:
                            continue
                        stat = path.stat()
                        data[str(path)] = {
                            "hash": safe_hash(path),
                            "mode": stat.st_mode,
                            "uid": stat.st_uid,
                            "gid": stat.st_gid,
                        }
                    except PermissionError:
                        permission_error_seen = True
                        continue
                    except FileNotFoundError:
                        continue
        else:
            for f in scan_dir_res.iterdir():
                if not f.is_file():
                    continue
                try:
                    if f.resolve(strict=False) in ignore_set:
                        continue
                    stat = f.stat()
                    data[str(f)] = {
                        "hash": safe_hash(f),
                        "mode": stat.st_mode,
                        "uid": stat.st_uid,
                        "gid": stat.st_gid,
                    }
                except PermissionError:
                    permission_error_seen = True
                    continue
                except FileNotFoundError:
                    continue
    except Exception:
        pass

    if permission_error_seen:
        safe_print(f"{Colors.ORANGE}Warning: some files could not be read (permission denied).{Colors.ENDC}")
    return data

def scan_users() -> Dict[str, Dict[str, Any]]:
    data: Dict[str, Dict[str, Any]] = {}
    try:
        for p in pwd.getpwall():
            data[p.pw_name] = {
                "uid": p.pw_uid,
                "gid": p.pw_gid,
                "home": p.pw_dir,
                "shell": p.pw_shell,
            }
    except Exception:
        pass
    return data

def scan_packages() -> Dict[str, str]:
    data: Dict[str, str] = {}
    try:
        if Path("/usr/bin/dpkg").exists():
            out = subprocess.check_output(["dpkg-query", "-W", "-f=${Package} ${Version}\n"])
            output = out.decode(errors="ignore")
            for line in output.strip().splitlines():
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name, version = parts[0], " ".join(parts[1:])
                    data[name] = version
        elif Path("/usr/bin/rpm").exists():
            out = subprocess.check_output(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\\n"])
            output = out.decode(errors="ignore")
            for line in output.strip().splitlines():
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name, version = parts[0], " ".join(parts[1:])
                    data[name] = version
    except Exception:
        pass
    return data

# ────────────── Diff helpers ──────────────
def diff_dict(old: Dict[str, Any], new: Dict[str, Any]):
    old_keys = set(old.keys())
    new_keys = set(new.keys())
    added = {k: new[k] for k in new_keys - old_keys}
    removed = {k: old[k] for k in old_keys - new_keys}
    changed = {k: (old[k], new[k]) for k in old_keys & new_keys if old[k] != new[k]}
    return added, removed, changed

# ────────────── Perform scan wrapper ──────────────
def perform_scan(args: argparse.Namespace, ignore_files: Optional[List[str]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    recursive = not getattr(args, "no_recursive", False)
    if getattr(args, "logs", False):
        result["logs"] = {"recursive": recursive, "data": scan_logs(args.logs, recursive, ignore_files=ignore_files)}
    if getattr(args, "files", False):
        result["files"] = {"recursive": recursive, "data": scan_files(args.files, recursive, ignore_files=ignore_files)}
    if getattr(args, "users", False):
        result["users"] = {"recursive": recursive, "data": scan_users()}
    if getattr(args, "packages", False):
        result["packages"] = {"recursive": recursive, "data": scan_packages()}
    return result

# ────────────── CLI & main ──────────────
def print_help():
    help_text = f"""{Colors.BOLD}{Colors.OKGREEN}
IntegrI - System Integrity & Change Detection Tool
===================================================={Colors.ENDC}

Scan your Linux system, save a baseline, compare changes, or monitor continuously.

Usage:
  integri scan [options] -o <baseline.json>
  integri diff [options] -i <baseline.json>
  integri watch [options] -o <baseline.json> -t <interval>

Commands:
  scan        Scan system components and save a baseline
  diff        Compare current system state with a saved baseline
  watch       Continuously monitor system changes

Options:
  -l, --logs [DIR]       Scan logs (default: /var/log)
  -f, --files [DIR]      Scan files/directories (default: /etc)
  --no-recursive          Scan only the specified directory (no recursion)
  -u, --users            Scan user accounts
  -p, --packages         Scan installed packages

Output Options:
  -o, --output FILE      Save baseline to JSON file (scan/watch mode)
  -i, --input FILE       Load baseline JSON for comparison (diff mode)
  -t, --interval N       Time in seconds between checks (watch mode, default: 10s)

Examples:
  integri scan -f /etc -u -p -o baseline.json
  integri diff -i baseline.json -f /etc -u -p
  integri watch -f ~/ -o baseline.json -t 10
"""
    safe_print(help_text)

def validate_components_selected(cmd: str, args: argparse.Namespace) -> None:
    # ensure user selected at least one component
    if not (getattr(args, "files", False) or getattr(args, "logs", False) or getattr(args, "users", False) or getattr(args, "packages", False)):
        safe_print(f"{Colors.FAIL}Error: select at least one component (files, logs, users, packages) for '{cmd}'{Colors.ENDC}")
        sys.exit(2)

def main():
    try:
        # quick help
        if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1:
            print_help()
            sys.exit(0)

        parser = argparse.ArgumentParser(add_help=False)
        subparsers = parser.add_subparsers(dest="command")

        # scan
        scan_p = subparsers.add_parser("scan", add_help=False)
        scan_p.add_argument("-l", "--logs", nargs="?", const="/var/log")
        scan_p.add_argument("-f", "--files", nargs="?", const="/etc")
        scan_p.add_argument("--no-recursive", action="store_true")
        scan_p.add_argument("-u", "--users", action="store_true")
        scan_p.add_argument("-p", "--packages", action="store_true")
        scan_p.add_argument("-o", "--output", required=True)

        # diff
        diff_p = subparsers.add_parser("diff", add_help=False)
        diff_p.add_argument("-i", "--input", required=True)
        diff_p.add_argument("-l", "--logs", nargs="?", const="/var/log")
        diff_p.add_argument("-f", "--files", nargs="?", const="/etc")
        diff_p.add_argument("--no-recursive", action="store_true")
        diff_p.add_argument("-u", "--users", action="store_true")
        diff_p.add_argument("-p", "--packages", action="store_true")

        # watch
        watch_p = subparsers.add_parser("watch", add_help=False)
        watch_p.add_argument("-l", "--logs", nargs="?", const="/var/log")
        watch_p.add_argument("-f", "--files", nargs="?", const="/etc")
        watch_p.add_argument("--no-recursive", action="store_true")
        watch_p.add_argument("-u", "--users", action="store_true")
        watch_p.add_argument("-p", "--packages", action="store_true")
        watch_p.add_argument("-o", "--output", required=True)
        watch_p.add_argument("-t", "--interval", type=int, default=10)

        args = parser.parse_args()

        # Build ignore list (resolve baseline path safely)
        ignore: List[str] = []
        if getattr(args, "output", None):
            try:
                ignore.append(str(Path(args.output).expanduser().resolve(strict=False)))
            except Exception:
                ignore.append(str(Path(args.output).expanduser().absolute()))

        # SCAN
        if args.command == "scan":
            validate_components_selected("scan", args)
            stop_event = Event()
            t = Thread(target=spinner, args=("Scanning...", stop_event))
            t.start()
            baseline_data = perform_scan(args, ignore_files=ignore)
            # annotate baseline
            baseline = {
                "schema_version": 1,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "components": baseline_data
            }
            stop_event.set()
            t.join()
            try:
                atomic_write_json(args.output, baseline)
                safe_print(f"{Colors.OKGREEN}Baseline saved to {args.output}{Colors.ENDC}")
            except Exception as e:
                safe_print(f"{Colors.FAIL}Error saving baseline: {e}{Colors.ENDC}")
                sys.exit(1)

        # DIFF
        elif args.command == "diff":
            validate_components_selected("diff", args)
            try:
                with open(args.input, "r", encoding="utf-8") as f:
                    old_file = json.load(f)
            except Exception as e:
                safe_print(f"{Colors.FAIL}Error reading baseline: {e}{Colors.ENDC}")
                sys.exit(1)

            # support older baseline shapes
            old_components = old_file.get("components", old_file)

            stop_event = Event()
            t = Thread(target=spinner, args=("Comparing...", stop_event))
            t.start()
            new_components = perform_scan(args, ignore_files=ignore)
            stop_event.set()
            t.join()

            total = [0, 0, 0]
            for section in ["logs", "files", "users", "packages"]:
                if section in old_components and section in new_components:
                    old_data = old_components[section].get("data", old_components[section])
                    new_data = new_components[section].get("data", new_components[section])
                    added, removed, changed = diff_dict(old_data, new_data)
                    for k in added:
                        safe_print(f"{Colors.OKGREEN}🟢 {section} added: {k}{Colors.ENDC}")
                    for k in removed:
                        safe_print(f"{Colors.FAIL}🔴 {section} removed: {k}{Colors.ENDC}")
                    for k in changed:
                        safe_print(f"{Colors.ORANGE}🟠 {section} changed: {k}{Colors.ENDC}")
                    total[0] += len(added)
                    total[1] += len(removed)
                    total[2] += len(changed)

            safe_print(f"\n{Colors.BOLD}Summary:{Colors.ENDC} "
                       f"{Colors.OKGREEN}🟢{total[0]} added{Colors.ENDC}, "
                       f"{Colors.FAIL}🔴{total[1]} removed{Colors.ENDC}, "
                       f"{Colors.ORANGE}🟠{total[2]} changed{Colors.ENDC}")

        # WATCH
        elif args.command == "watch":
            validate_components_selected("watch", args)
            # initial baseline
            baseline_components = perform_scan(args, ignore_files=ignore)
            baseline = {
                "schema_version": 1,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "components": baseline_components
            }
            try:
                atomic_write_json(args.output, baseline)
            except Exception as e:
                safe_print(f"{Colors.FAIL}Error saving initial baseline: {e}{Colors.ENDC}")
                sys.exit(1)

            safe_print(f"{Colors.OKGREEN}Initial baseline saved to {args.output}{Colors.ENDC}")
            safe_print(f"{Colors.HEADER}Watching for changes every {args.interval} seconds. "
                       f"All changes will be saved automatically to {args.output}. Press Ctrl+C to stop.{Colors.ENDC}")

            try:
                while True:
                    time.sleep(args.interval)
                    new_components = perform_scan(args, ignore_files=ignore)
                    ts = time.strftime("%Y-%m-%d %H:%M:%S")
                    any_change = False

                    for section in ["logs", "files", "users", "packages"]:
                        if section in baseline_components and section in new_components:
                            old_data = baseline_components[section].get("data", {})
                            new_data = new_components[section].get("data", {})
                            added, removed, changed = diff_dict(old_data, new_data)

                            for k in added:
                                safe_print(f"{Colors.OKGREEN}🟢 {section} added: {k} [{ts}]{Colors.ENDC}")
                                any_change = True
                            for k in removed:
                                safe_print(f"{Colors.FAIL}🔴 {section} removed: {k} [{ts}]{Colors.ENDC}")
                                any_change = True
                            for k in changed:
                                safe_print(f"{Colors.ORANGE}🟠 {section} changed: {k} [{ts}]{Colors.ENDC}")
                                any_change = True

                    # update baseline file and in-memory baseline (always update as requested)
                    baseline_components = new_components
                    baseline = {
                        "schema_version": 1,
                        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "components": baseline_components
                    }
                    try:
                        atomic_write_json(args.output, baseline)
                    except Exception as e:
                        safe_print(f"{Colors.FAIL}Error saving baseline: {e}{Colors.ENDC}")
                        # don't exit; continue watching

            except KeyboardInterrupt:
                c_exit()
            except SystemExit:
                raise
            except Exception:
                c_exit()

        else:
            safe_print(f"{Colors.FAIL}Error: unknown command.{Colors.ENDC}")
            sys.exit(2)

    except KeyboardInterrupt:
        c_exit()
    except SystemExit:
        raise
    except Exception as e:
        # catch-all: still exit but provide short message
        safe_print(f"\n{Colors.FAIL}Fatal error: {e}{Colors.ENDC}")
        safe_print(f"{Colors.HEADER}EXITED.{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
  
