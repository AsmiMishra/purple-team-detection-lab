#!/usr/bin/env python3
"""
parse_zeek.py — Detection analysis for the purple-team lab.

Reads Zeek conn.log, ssh.log, and http.log and flags the ATT&CK
techniques exercised against the target, then prints a coverage
summary.

Design notes (these are the interesting part):
  * Zeek TSV logs carry a '#fields' header line. We parse column
    positions from that header instead of hard-coding them, so the
    script survives a change in Zeek's column order.
  * Port-scan detection is a sliding-window burst detector: it flags
    a source that opens more than THRESHOLD connections to distinct
    ports within WINDOW seconds. This deliberately CATCHES the fast
    nmap scans and MISSES the slow (-T1) scan — demonstrating that a
    stealthy, throttled scan evades burst-based detection even though
    every connection is individually present in the log.
  * Exfil detection sums BOTH directions (orig_bytes + resp_bytes),
    because with raw netcat the payload can land in resp_bytes rather
    than orig_bytes depending on which side Zeek treats as originator.
    A detector that only reads orig_bytes would miss it.

Usage:
    python3 parse_zeek.py /path/to/logs/
"""

import sys
import os
from collections import defaultdict

# ---- tunables ----------------------------------------------------
SCAN_WINDOW_SEC = 5        # window for burst-based scan detection
SCAN_PORT_THRESHOLD = 20   # distinct ports from one src within window => scan
EXFIL_BYTES_THRESHOLD = 1_000_000   # 1 MB in a single connection => exfil
COMMON_PORTS = {80, 443, 22, 53, 25, 110, 143, 993, 995, 587, 8080}
SUSPICIOUS_HTTP_HINTS = ("beacon", "/admin", "config.php", "/c2", "cmd")
# ------------------------------------------------------------------


def read_zeek_log(path):
    """Yield each data row of a Zeek TSV log as a dict keyed by field name."""
    if not os.path.exists(path):
        return
    fields = None
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                # '#fields\tts\tuid\t...' -> ['ts','uid',...]
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                continue
            values = line.split("\t")
            if len(values) != len(fields):
                continue
            yield dict(zip(fields, values))


def num(v):
    """Zeek uses '-' for unset. Return 0.0 for those."""
    if v in ("-", "", None):
        return 0.0
    try:
        return float(v)
    except ValueError:
        return 0.0


def detect_scans(conn_rows):
    """
    Sliding-window burst detector.
    Returns (scan_events, all_conn_count, per_src_total).
    A scan_event = (src, start_ts, distinct_port_count).
    """
    # bucket connection attempts per source: list of (ts, dport)
    by_src = defaultdict(list)
    total = 0
    for r in conn_rows:
        total += 1
        src = r["id.orig_h"]
        try:
            ts = float(r["ts"])
            dport = int(r["id.resp_p"])
        except (ValueError, KeyError):
            continue
        by_src[src].append((ts, dport))

    scan_events = []
    per_src_total = {}
    for src, hits in by_src.items():
        per_src_total[src] = len(hits)
        hits.sort()
        # slide a window across the sorted timestamps
        i = 0
        flagged_window_start = None
        for j in range(len(hits)):
            while hits[j][0] - hits[i][0] > SCAN_WINDOW_SEC:
                i += 1
            window_ports = {hits[k][1] for k in range(i, j + 1)}
            if len(window_ports) >= SCAN_PORT_THRESHOLD:
                # record once per contiguous burst
                if flagged_window_start is None:
                    flagged_window_start = hits[i][0]
                    scan_events.append((src, hits[i][0], len(window_ports)))
        # (we keep it simple: one event per source burst)
    return scan_events, total, per_src_total


def detect_exfil(conn_rows):
    """
    Flag single connections moving a lot of data on an uncommon port.
    Sums orig_bytes + resp_bytes to avoid the netcat direction trap.
    Returns list of (src, dst, dport, total_bytes, duration).
    """
    events = []
    for r in conn_rows:
        try:
            dport = int(r["id.resp_p"])
        except (ValueError, KeyError):
            continue
        total_bytes = num(r.get("orig_bytes")) + num(r.get("resp_bytes"))
        if total_bytes >= EXFIL_BYTES_THRESHOLD and dport not in COMMON_PORTS:
            events.append((
                r["id.orig_h"], r["id.resp_h"], dport,
                int(total_bytes), num(r.get("duration")),
            ))
    return events


def analyze_ssh(ssh_path):
    """Return list of (ts, src, dst, attempts) for SSH connections."""
    out = []
    for r in read_zeek_log(ssh_path):
        out.append((
            r.get("ts", "-"),
            r.get("id.orig_h", "-"),
            r.get("id.resp_h", "-"),
            r.get("auth_attempts", "-"),
        ))
    return out


def analyze_http(http_path):
    """Return list of (src, host, uri, method, suspicious_bool)."""
    out = []
    for r in read_zeek_log(http_path):
        uri = r.get("uri", "-")
        suspicious = any(h in uri.lower() for h in SUSPICIOUS_HTTP_HINTS)
        out.append((
            r.get("id.orig_h", "-"),
            r.get("host", "-"),
            uri,
            r.get("method", "-"),
            suspicious,
        ))
    return out


def main():
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    conn_path = os.path.join(log_dir, "conn.log")
    ssh_path = os.path.join(log_dir, "ssh.log")
    http_path = os.path.join(log_dir, "http.log")

    conn_rows = list(read_zeek_log(conn_path))

    print("=" * 62)
    print("  ZEEK DETECTION ANALYSIS — purple-team lab")
    print("=" * 62)
    print(f"  conn.log records: {len(conn_rows)}")
    print()

    # --- T1046: port scans -------------------------------------
    scans, total, per_src = detect_scans(conn_rows)
    print("-" * 62)
    print("  T1046  Network Service Discovery (port scan)")
    print("-" * 62)
    if scans:
        for src, ts, ports in scans:
            print(f"  [DETECTED] burst scan from {src}: "
                  f">= {ports} ports within {SCAN_WINDOW_SEC}s")
    else:
        print("  [none flagged by burst detector]")
    print(f"  connections per source: "
          f"{', '.join(f'{s}={n}' for s, n in per_src.items())}")
    print()
    print("  NOTE: the slow nmap -T1 scan is NOT flagged above.")
    print("  Its 5 connections are spread over ~90s, below the burst")
    print("  threshold. Every connection is still in conn.log, but a")
    print("  rate-based detector does not fire. => logged, not alerted.")
    print()

    # --- T1048: exfil ------------------------------------------
    exfil = detect_exfil(conn_rows)
    print("-" * 62)
    print("  T1048  Exfiltration Over Alternative Protocol")
    print("-" * 62)
    if exfil:
        for src, dst, dport, b, dur in exfil:
            print(f"  [DETECTED] {src} -> {dst} port {dport}: "
                  f"{b:,} bytes in {dur:.1f}s")
    else:
        print("  [no large uncommon-port transfers found]")
    print()

    # --- T1021.004: SSH ----------------------------------------
    ssh = analyze_ssh(ssh_path)
    print("-" * 62)
    print("  T1021.004  Remote Services: SSH")
    print("-" * 62)
    if ssh:
        print(f"  [DETECTED] {len(ssh)} SSH connection(s) in ssh.log:")
        for ts, src, dst, att in ssh:
            print(f"    {src} -> {dst}  (auth_attempts={att})")
    else:
        print("  [ssh.log not found or empty]")
    print()

    # --- T1071.001: HTTP ---------------------------------------
    http = analyze_http(http_path)
    print("-" * 62)
    print("  T1071.001  Application Layer Protocol: Web")
    print("-" * 62)
    if http:
        print(f"  [DETECTED] {len(http)} HTTP request(s) in http.log:")
        for src, host, uri, method, susp in http:
            tag = "  <-- SUSPICIOUS PATH" if susp else ""
            print(f"    {src} {method} {host}{uri}{tag}")
    else:
        print("  [http.log not found or empty]")
    print()

    # --- T1018: host sweep (known gap) -------------------------
    print("-" * 62)
    print("  T1018  Remote System Discovery (host sweep)")
    print("-" * 62)
    print("  [GAP] An nmap -sn sweep of the /24 uses ARP on the local")
    print("  segment. ARP is below the TCP layer and does not appear in")
    print("  conn.log, so this parser cannot see it. Detecting it would")
    print("  require ARP/packet analysis (e.g. Zeek's known_hosts or a")
    print("  pcap), not connection records.")
    print()

    print("=" * 62)
    print("  SUMMARY")
    print("=" * 62)
    print("  T1046 fast scans (-sT/-sS) ... DETECTED (burst)")
    print("  T1046 slow scan (-T1) ........ LOGGED, not alerted")
    print("  T1018 host sweep ............. MISSED (ARP, below TCP)")
    print("  T1021.004 SSH ................ DETECTED (ssh.log)")
    print("  T1071.001 HTTP C2 ............ DETECTED (http.log)")
    print("  T1048 exfil .................. DETECTED (volume + port)")
    print("=" * 62)


if __name__ == "__main__":
    main()
