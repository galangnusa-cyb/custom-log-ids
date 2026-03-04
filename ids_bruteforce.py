#!/usr/bin/env python3
import re
import json
import time
import argparse
import datetime as dt
from collections import defaultdict, deque


RE_FAILED = re.compile(
    r"sshd\[\d+\]: Failed (password|publickey) for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
RE_INVALID = re.compile(
    r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def parse_syslog_time(line: str, year: int) -> float:
    """
    auth.log format: 'Mar  4 12:34:56 ...' (no year).
    We'll inject current year so window logic works.
    """
    try:
        ts = line[:15]
        d = dt.datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        return d.timestamp()
    except Exception:
        return time.time()


def iso_utc_now(now: float) -> str:
    """Return ISO8601 UTC timestamp with Z."""
    return dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def emit_event(out_fp, event: dict):
    out_fp.write(json.dumps(event) + "\n")
    out_fp.flush()


def follow(file_path: str):
    """Tail -f implementation."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)  # EOF
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")


def main():
    ap = argparse.ArgumentParser(
        description="Custom brute-force detector for /var/log/auth.log -> JSONL alerts"
    )
    ap.add_argument("--log", default="/var/log/auth.log", help="Path to auth log")
    ap.add_argument("--out", default="/var/log/custom_ids/ids_alerts.json", help="Output JSONL alert file")
    ap.add_argument("--threshold", type=int, default=8, help="Fails within window to trigger alert")
    ap.add_argument("--window", type=int, default=120, help="Window seconds")
    ap.add_argument("--cooldown", type=int, default=300, help="Cooldown seconds per IP after alert")
    ap.add_argument("--mode", choices=["follow", "batch"], default="follow", help="Follow file or batch read")
    args = ap.parse_args()

    import os
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    # Per-IP deque of fail timestamps
    fails = defaultdict(lambda: deque())
    # Per-IP last alert time (epoch)
    last_alert = defaultdict(lambda: 0.0)

    year = dt.datetime.now().year

    def process_line(line: str):
        now = time.time()

        m = RE_FAILED.search(line) or RE_INVALID.search(line)
        if not m:
            return None

        ip = m.group("ip")
        user = m.group("user")

        ts = parse_syslog_time(line, year)

        # Maintain sliding window
        q = fails[ip]
        q.append(ts)
        while q and (ts - q[0]) > args.window:
            q.popleft()

        count = len(q)

        # Trigger alert if threshold hit and not in cooldown
        if count >= args.threshold and (now - last_alert[ip]) > args.cooldown:
            last_alert[ip] = now
            return {
                "time": iso_utc_now(now),
                "event_type": "bruteforce_detected",
                "src_ip": ip,
                "target_service": "ssh",
                "user_last_seen": user,
                "fail_count_in_window": count,
                "window_seconds": args.window,
                "threshold": args.threshold,
                "severity": "high",
                "raw_sample": line,
            }

        # Baseline signal (useful for trending)
        return {
            "time": iso_utc_now(now),
            "event_type": "ssh_fail_observed",
            "src_ip": ip,
            "user": user,
            "fail_count_in_window": count,
            "window_seconds": args.window,
            "severity": "info",
        }

    with open(args.out, "a", encoding="utf-8") as out_fp:
        if args.mode == "batch":
            with open(args.log, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    evt = process_line(line.rstrip("\n"))
                    if evt:
                        emit_event(out_fp, evt)
        else:
            for line in follow(args.log):
                evt = process_line(line)
                if evt:
                    emit_event(out_fp, evt)


if __name__ == "__main__":
    main()
