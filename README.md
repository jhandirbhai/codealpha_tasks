# NetWatch — Network Packet Analyzer

A real-time GUI network sniffer built with Python 3, Scapy, Tkinter and Pandas.  
Built as part of the CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer.

---

## Features

- Live packet capture with color-coded protocol rows (TCP / UDP / ICMP / DNS / HTTP)
- Click any row to view full layer breakdown + hex dump in the detail panel
- Live filters by Source IP, Destination IP, Protocol, and Port
- Per-protocol counters in the status bar (TCP, UDP, ICMP, DNS, HTTP, Other)
- Export filtered or all packets to CSV
- Save raw capture to .pcap (openable in Wireshark)
- Column sorting by clicking any header
- Responsive Stop button — responds within 1 second even on quiet networks

---

## Setup (Windows)

### Step 1 — Install Npcap
Scapy requires Npcap to capture packets on Windows.

1. Download from https://npcap.com (free version)
2. Run the installer
3. During install, check **"Install Npcap in WinPcap API-compatible mode"**

### Step 2 — Install Python dependencies
Open a terminal and run:

```
pip install -r requirements.txt
```

### Step 3 — Run as Administrator
Packet capture requires raw socket access (admin rights).

**Option A — VS Code:**
Right-click VS Code → "Run as administrator" → open `main.py` → press F5

**Option B — Terminal:**
Right-click Command Prompt → "Run as administrator"
```
python main.py
```

---

## Setup (Linux)

```bash
pip install -r requirements.txt
sudo python3 main.py
```

---

## Quick Checklist Before Running

| | Requirement |
|---|---|
| ✅ | Python 3.8+ installed |
| ✅ | `pip install -r requirements.txt` completed |
| ✅ | Npcap installed (Windows only) |
| ✅ | VS Code / terminal opened as **Administrator** (Windows) or using **sudo** (Linux) |

---

## File Structure

```
NetWatch/
├── main.py           ← Full application
├── requirements.txt  ← Python dependencies
└── README.md         ← This file
```

---

## Bug Fixes (v1.1.0)

| # | Severity | Fix |
|---|---|---|
| 1 | Critical | Renamed `"#"` column ID to `"num"` — conflicted with ttk internal `#N` notation |
| 2 | Critical | ICMP `.id`/`.seq` wrapped in try/except — only exist on Echo types 0/8 |
| 3 | Critical | HTTP import guarded with `HTTP_AVAILABLE` flag — fails on some Scapy builds |
| 4 | Critical | `after()` ID saved and cancelled on close — prevented TclError on exit |
| 5 | Important | Queue drained on capture restart — no stale packets from previous session |
| 6 | Important | Packet lookup uses dict `packet_map` — O(1) vs old O(n) linear scan |
| 7 | Important | DNS and HTTP added to counters and status bar — were silently counted as Other |
| 8 | Minor | Sort key uses per-item safe int/str fallback — old try/except broke mixed columns |
| 9 | Minor | CSV export respects active filters — no longer falls back to all packets |
| 10 | Minor | `_stop_capture` guarded — avoids redundant button state resets |

---

## Libraries Used

| Library | Purpose |
|---|---|
| Scapy | Packet capture and protocol parsing |
| Tkinter / ttk | GUI (built into Python — no install needed) |
| Pandas | CSV export |
| threading + queue | Non-blocking capture — GUI stays responsive |

---

## Note on HTTPS / Encrypted Traffic

Most modern web traffic uses HTTPS (TLS encrypted). NetWatch will still capture
these packets but the payload will appear as encrypted binary data, not readable HTTP.
To inspect HTTPS content, a man-in-the-middle proxy (e.g. Burp Suite) is required —
this is outside the scope of this project.
