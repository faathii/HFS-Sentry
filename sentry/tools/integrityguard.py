#!/usr/bin/env python3
"""IntegrityGuard - Host-based File Integrity Monitoring (FIM) with SHA-256.

Zero external dependencies (Python 3 standard library only).
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from sentry.core.base import BaseTool
from sentry.core.colors import bold, cyan, green, red, yellow
from sentry.core.registry import register_tool

# Recommended critical files depending on OS
DEFAULT_TARGET_PATHS = {
    "Windows": [
        os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\hosts"),
    ],
    "Linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/hosts",
    ],
    "Darwin": [
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
    ],
}


def compute_sha256(file_path: str, chunk_size: int = 65536) -> Optional[str]:
    """Compute cryptographic SHA-256 hash of a file efficiently in chunks."""
    if not os.path.isfile(file_path):
        return None
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        return None


def collect_file_metadata(file_path: str) -> Optional[Dict[str, Any]]:
    """Gather file hash, size, and modification timestamp."""
    try:
        stat = os.stat(file_path)
        sha = compute_sha256(file_path)
        if sha is None:
            return None
        return {
            "path": os.path.abspath(file_path),
            "sha256": sha,
            "size_bytes": stat.st_size,
            "mtime": stat.st_mtime,
            "mtime_iso": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }
    except Exception:
        return None


def expand_paths(targets: List[str]) -> List[str]:
    """Expand list of files and directories recursively."""
    expanded = set()
    for t in targets:
        p = os.path.abspath(t)
        if os.path.isfile(p):
            expanded.add(p)
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    expanded.add(os.path.abspath(os.path.join(root, f)))
    return sorted(expanded)


def generate_baseline(targets: List[str], baseline_file: str) -> Dict[str, Any]:
    """Create cryptographic baseline snapshot."""
    file_list = expand_paths(targets)
    records: Dict[str, Any] = {}

    for fp in file_list:
        meta = collect_file_metadata(fp)
        if meta:
            records[fp] = meta

    baseline_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "os": platform.system(),
        "targets": targets,
        "total_files": len(records),
        "files": records,
    }

    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)

    return baseline_data


create_baseline = generate_baseline


def verify_integrity(baseline_source: Any) -> Dict[str, Any]:
    """Compare current filesystem against baseline snapshot (path or loaded dict)."""
    if isinstance(baseline_source, dict):
        baseline = baseline_source
    elif isinstance(baseline_source, str):
        if not os.path.isfile(baseline_source):
            raise FileNotFoundError(f"Baseline file '{baseline_source}' not found. Run with --init first.")
        with open(baseline_source, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    else:
        raise TypeError(f"Expected file path string or dict for baseline, got {type(baseline_source).__name__}")

    baseline_files = baseline.get("files", {})

    modified: List[Dict[str, Any]] = []
    deleted: List[str] = []
    unreadable: List[str] = []
    intact_count = 0

    for path, original in baseline_files.items():
        if not os.path.exists(path):
            deleted.append(path)
            continue

        current = collect_file_metadata(path)
        if not current:
            unreadable.append(path)
            continue

        if current["sha256"] != original["sha256"]:
            modified.append({
                "path": path,
                "original_sha256": original["sha256"],
                "current_sha256": current["sha256"],
                "original_size": original["size_bytes"],
                "current_size": current["size_bytes"],
                "original_mtime": original.get("mtime_iso"),
                "current_mtime": current.get("mtime_iso"),
            })
        else:
            intact_count += 1

    new_files: List[str] = []
    targets = baseline.get("targets", [])
    if targets:
        try:
            current_discovered = set(expand_paths(targets))
            new_files = sorted(list(current_discovered - set(baseline_files.keys())))
        except Exception:
            pass

    is_compromised = bool(modified or deleted or new_files)

    return {
        "baseline_created": baseline.get("generated_at"),
        "total_monitored": len(baseline_files),
        "intact_count": intact_count,
        "tampered": is_compromised,
        "modified": modified,
        "deleted": deleted,
        "unreadable": unreadable,
        "new_files": new_files,
    }


def _is_stopped(stop_check: Optional[Any]) -> bool:
    if stop_check is None:
        return False
    if hasattr(stop_check, "is_set"):
        return stop_check.is_set()
    if callable(stop_check):
        return stop_check()
    return bool(stop_check)


def watch_integrity_timeline(
    targets: List[str],
    duration: float = 30.0,
    poll_interval: float = 1.0,
    progress_callback: Optional[Callable[[Dict[str, Any], float], None]] = None,
    stop_check: Optional[Any] = None,
) -> Dict[str, Any]:
    """Watch directory or files continuously over a time window (e.g. 30 seconds).

    Computes initial baseline in memory and continuously compares hashes, detecting
    tampering, modifications or deletions in real-time.
    """
    file_list = expand_paths(targets)
    initial_records: Dict[str, Any] = {}
    for fp in file_list:
        if _is_stopped(stop_check):
            break
        meta = collect_file_metadata(fp)
        if meta:
            initial_records[fp] = meta

    baseline = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "files": initial_records,
    }

    start_time = time.time()
    end_time = start_time + duration if duration > 0 else start_time

    while True:
        now = time.time()
        remaining = max(0.0, end_time - now) if duration < 100000 and duration > 0 else 999999.0

        if _is_stopped(stop_check):
            break

        current_verif = verify_integrity(baseline)
        current_verif["duration_seconds"] = round(now - start_time, 1)

        # Detect newly added files in monitored target directories
        current_files = set(expand_paths(targets))
        new_files = sorted(list(current_files - set(initial_records.keys())))
        if new_files:
            current_verif["new_files"] = new_files
            current_verif["tampered"] = True

        if progress_callback:
            progress_callback(current_verif, remaining)

        if duration <= 0:
            break

        if _is_stopped(stop_check):
            break

        if duration < 100000 and now >= end_time:
            break

        if hasattr(stop_check, "wait"):
            if stop_check.wait(timeout=poll_interval):
                break
        else:
            time.sleep(poll_interval)

    return verify_integrity(baseline)


def print_cli_report(results: Dict[str, Any], baseline_file: str) -> None:
    """Print formatted IntegrityGuard audit report."""
    print("=" * 76)
    print(f" {bold('[IntegrityGuard] Host File Integrity Monitor (SHA-256 FIM)')}")
    print(f" Baseline: {cyan(baseline_file)} | Baseline Created: {results['baseline_created']}")
    print("=" * 76)

    if not results["tampered"]:
        print(f"\n  {green(bold('[✔] INTEGRITY VERIFIED:'))} All {results['total_monitored']} monitored files match cryptographic baseline.")
    else:
        print(f"\n  {red(bold('[!] INTEGRITY ALERT: DISCREPANCIES DETECTED!'))}")
        print(f"  Intact: {results['intact_count']} | Modified: {len(results['modified'])} | Deleted: {len(results['deleted'])}")

        if results["modified"]:
            print(f"\n  {red(bold('--- TAMPERED / MODIFIED FILES ---'))}")
            for m in results["modified"]:
                print(f"  [MODIFIED] {bold(m['path'])}")
                print(f"    Expected SHA-256: {m['original_sha256']}")
                print(f"    Current  SHA-256: {red(m['current_sha256'])}")
                print(f"    Size Diff: {m['original_size']}B -> {m['current_size']}B")

        if results["deleted"]:
            print(f"\n  {yellow(bold('--- DELETED / MISSING FILES ---'))}")
            for d in results["deleted"]:
                print(f"  [MISSING] {yellow(d)}")

        if results.get("unreadable"):
            print(f"\n  {yellow(bold('--- UNREADABLE / LOCKED FILES ---'))}")
            for u in results["unreadable"]:
                print(f"  [LOCKED / PERMISSION DENIED] {yellow(u)}")

    print("\n" + "=" * 76 + "\n")


@register_tool
class IntegrityGuardTool(BaseTool):
    name = "integrityguard"
    description = "Cryptographic host-based file integrity monitoring (FIM) & unauthorized tampering detector"
    author = "Hamza El Fathi Sofyani"
    version = "1.0.0"
    category = "HIDS"

    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--init",
            action="store_true",
            help="Generate cryptographic baseline snapshot",
        )
        group.add_argument(
            "--check",
            action="store_true",
            help="Verify integrity against baseline (default mode)",
        )
        parser.add_argument(
            "-b", "--baseline",
            default="sentry_baseline.json",
            help="Path to baseline database file (default: sentry_baseline.json)",
        )
        parser.add_argument(
            "-t", "--targets",
            nargs="+",
            help="Files or directories to monitor (used with --init). Defaults to system critical files.",
        )
        parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    def run(self, args: argparse.Namespace) -> int:
        if args.init:
            targets = args.targets
            if not targets:
                os_sys = platform.system()
                targets = DEFAULT_TARGET_PATHS.get(os_sys, [DEFAULT_TARGET_PATHS["Linux"][0]])
            data = generate_baseline(targets, args.baseline)
            print(f"{green('[✔] Cryptographic baseline created successfully:')} {bold(args.baseline)} ({data['total_files']} files hashed)")
            return 0
        else:
            try:
                results = verify_integrity(args.baseline)
                if args.json:
                    print(json.dumps(results, indent=2))
                else:
                    print_cli_report(results, args.baseline)
                return 1 if results["tampered"] else 0
            except Exception as e:
                print(f"[!] IntegrityGuard error: {e}", file=sys.stderr)
                return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=IntegrityGuardTool.description)
    tool = IntegrityGuardTool()
    tool.register_arguments(parser)
    sys.exit(tool.run(parser.parse_args()))

