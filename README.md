# Purple-Team Detection Lab — Zeek vs. ATT&CK Techniques

A self-contained, network-isolated lab for measuring what a passive
network sensor (Zeek) does and does not detect when an attacker runs
common MITRE ATT&CK techniques against a target host.

The point of the project is not "run attacks." It is to measure
**detection coverage** honestly, including the cases Zeek misses and
*why* it misses them, which is where the real analysis lives.

## Architecture

```
            VirtualBox "Internal Network" (intnet) — no DHCP, no gateway
   ┌─────────────────────────┐                 ┌─────────────────────────┐
   │   kali-attacker          │                 │   ubuntu-target          │
   │   10.10.10.10  (eth1)    │ ───attacks───►  │   10.10.10.20  (enp0s8)  │
   │   nmap / ssh / curl / nc │                 │   OpenSSH + Zeek sensor  │
   └─────────────────────────┘                 └─────────────────────────┘
```

- **Attacker:** Kali Linux. Runs the techniques using built-in tools
  (`nmap`, `ssh`, `curl`, `nc`).
- **Target:** Ubuntu Server 24.04 LTS running **Zeek 9.0**, sniffing
  its lab interface (`enp0s8`) only.
- **Network:** a VirtualBox *Internal Network* named `intnet`. There
  is no DHCP and no gateway, so the two VMs can reach each other and
  **nothing else**.

### Why this isolation design

Two separate walls, by design:

1. **Network isolation.** The lab interface has a static address and
   **no default route**, so neither VM can route off-subnet. A second
   NAT adapter was used only during setup to install packages, then
   **disconnected** before any attack was run.
2. **File isolation.** No shared folders or clipboard-to-host were
   enabled on the target during testing, so nothing in the VM could
   touch the host filesystem even if a test misbehaved.

## Isolation verification

Before any attack, isolation was proven from both hosts:

| Check | Expected | Result |
|---|---|---|
| `ip route` has a default route | none | no default route on either VM |
| `ping 8.8.8.8` (internet) | fail | "Network is unreachable" |
| `ping <real home router>` | fail | unreachable |
| `ping` the other lab VM | succeed | replies, ~1 ms |

Because there is no default route, the kernel refuses to even emit the
off-subnet packets — isolation enforced by the routing table itself.

## Methodology

A single Zeek log set captures the whole run. The attacker executed
six techniques; the local start time of each was recorded so events
can be correlated with Zeek's (UTC) timestamps.

Techniques, and the exact commands:

| ATT&CK | Technique | Command (from Kali) |
|---|---|---|
| T1046 | Network Service Discovery (connect) | `nmap -sT 10.10.10.20` |
| T1046 | Network Service Discovery (SYN) | `sudo nmap -sS 10.10.10.20` |
| T1046 | Network Service Discovery (slow) | `sudo nmap -sS -T1 -p 22,80,443,3389,8080 10.10.10.20` |
| T1018 | Remote System Discovery | `nmap -sn 10.10.10.0/24` |
| T1021.004 | Remote Services: SSH | `ssh smi@10.10.10.20` (+ failed logins) |
| T1071.001 | Application Layer Protocol: Web | `curl http://10.10.10.20/secret-beacon` |
| T1048 | Exfiltration Over Alternative Protocol | `nc` transfer of a 5 MB file over port 4444 |

## Detection coverage — results

| Technique | Detected? | Zeek evidence | Key finding |
|---|---|---|---|
| T1046 `-sT` connect scan | ✅ Yes | `conn.log` — 1000 records | Loud: a connection logged for every one of 1000 ports, in < 1s |
| T1046 `-sS` SYN scan | ✅ Yes | `conn.log` — +1000 records | "Stealth" half-open scan is *just as visible* to a packet-level sensor |
| T1046 `-sS -T1` slow scan | ⚠️ Logged, not alerted | `conn.log` — 5 records over ~90s | Every connection present, but spread out — **evades a burst detector** |
| T1018 host sweep | ❌ Missed | — | Uses **ARP**, which is below the TCP layer and never reaches `conn.log` |
| T1021.004 SSH | ✅ Yes | `ssh.log` | Attempts + client/server version captured |
| T1071.001 HTTP C2 | ✅ Yes | `http.log` | Full **URI** and **user-agent** (`curl/8.20.0`) reconstructed |
| T1048 exfil | ✅ Yes | `conn.log` — port 4444, ~5.2 MB | Volume landed in `resp_bytes`, not `orig_bytes` |

## Analysis — what the misses teach

A matrix of all green would mean the test wasn't hard enough. The two
non-detections are the most useful results:

**1. The slow scan: logging ≠ alerting.** The `-T1` scan was fully
present in `conn.log` — five connections, one per port. But at ~18
seconds between probes, it never produces the burst that a
rate-based detector keys on. The data was captured; the *alert* would
not fire. This is the gap a patient attacker exploits, and it's why
detection logic matters as much as collection. The parser in this
repo demonstrates it: its 5-second/20-port burst detector catches the
`-sT`/`-sS` scans and stays silent on `-T1`.

**2. The host sweep: wrong layer.** `nmap -sn` on a local subnet
discovers hosts via **ARP**, not TCP. Zeek sees ARP but does not put
it in `conn.log`, so a `conn.log`-based detector is blind to it. The
lesson is that "the sensor saw the packets" and "this log shows the
technique" are different claims — coverage depends on *which* log you
look at.

**3. The direction trap (exfil).** The 5 MB netcat transfer logged its
bytes in `resp_bytes` rather than `orig_bytes`, because Zeek's notion
of "originator" didn't match the data-flow direction. A naive detector
reading only `orig_bytes` would report `0` and miss a textbook exfil.
The parser sums both directions to avoid this.

## The parser

`parse_zeek.py` reads `conn.log`, `ssh.log`, and `http.log` and prints
a coverage report. It reads Zeek's `#fields` header dynamically rather
than hard-coding column positions.

```bash
python3 parse_zeek.py logs/
```

It flags burst scans, large uncommon-port transfers (exfil), SSH
attempts, and suspicious HTTP paths, and it explicitly reports the
slow-scan and host-sweep gaps rather than hiding them.

## Repository layout

```
.
├── README.md          # this file
├── parse_zeek.py      # detection analysis over the Zeek logs
├── logs/              # Zeek logs captured during the run
│   ├── conn.log
│   ├── ssh.log
│   ├── http.log
│   └── ...
└── screenshots/       # isolation proof + per-technique evidence
```

## Notes and honest limitations

- Zeek logs are UTC; attack times were recorded in local (Central)
  time and correlated by hand.
- The target ran with 1 vCPU — a multi-CPU guest hung at boot under
  Windows' Hyper-V layer (VirtualBox running in paravirtualized mode).
- The `conn.log` also contains the operator's own administrative SSH
  traffic, which has to be separated from attack traffic during
  analysis — a realistic SOC problem, not a flaw in the data.
- Detection here is **passive network** only. Host-based telemetry
  (process creation, auth logs) would catch techniques Zeek cannot,
  and vice versa; the two are complementary.

## Tooling

VirtualBox 7.2 · Kali Linux 2026.2 · Ubuntu Server 24.04 LTS ·
Zeek 9.0 · nmap · OpenSSH · curl · netcat
