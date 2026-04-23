"""
NetWatch - Python GUI Network Sniffer
=====================================
A real-time packet capture and analysis tool built with Scapy + Tkinter.

Usage:
    sudo python3 main.py        (Linux  — root required for raw sockets)
    python main.py              (Windows — run as Administrator)

Bugs fixed vs original:
    1. "num" column ID — "#" conflicted with ttk's internal #N column notation
    2. ICMP AttributeError — .id/.seq only exist on Echo types (0/8)
    3. HTTP import guarded separately — scapy.layers.http can fail independently
    4. after() ID saved & cancelled — prevents TclError on window close
    5. pkt_queue drained on restart — no stale packets from previous session
    6. O(1) packet_map lookup — replaces O(n) linear scan in _on_row_select
    7. DNS/HTTP added to counters — were silently bucketed as "OTHER"
    8. Sort key safe lambda — prevents empty-string ValueError mid-sort
    9. Export CSV honours active filters — no longer falls back to all packets
   10. _stop_capture guarded — avoids double button state reset
"""

# ─────────────────────────────────────────────────────────────────────────────
# Standard Library Imports
# ─────────────────────────────────────────────────────────────────────────────
import queue
import threading
import datetime
import sys
import platform
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ─────────────────────────────────────────────────────────────────────────────
# Third-Party Imports
# ─────────────────────────────────────────────────────────────────────────────
try:
    import pandas as pd
except ImportError:
    print("[ERROR] pandas not found. Run: pip install pandas")
    sys.exit(1)

try:
    from scapy.all import (
        sniff, get_if_list, wrpcap,
        Ether, IP, IPv6, TCP, UDP, ICMP, DNS, Raw,
    )
except ImportError:
    print("[ERROR] scapy not found. Run: pip install scapy")
    sys.exit(1)

# FIX 3 — HTTP layer is optional; older Scapy builds ship without it.
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False
    HTTPRequest = HTTPResponse = None   # guards below use HTTP_AVAILABLE flag


# ─────────────────────────────────────────────────────────────────────────────
# Constants & Color Palette
# ─────────────────────────────────────────────────────────────────────────────
APP_TITLE   = "NetWatch  —  Network Packet Analyzer"
APP_VERSION = "1.1.0"

PROTOCOL_COLORS = {
    "TCP":   "#dce8f7",
    "UDP":   "#d6f0dd",
    "ICMP":  "#fde8c8",
    "DNS":   "#ead6f5",
    "HTTP":  "#fdd6d6",
    "OTHER": "#f0f0f0",
}

TAG_COLORS = {
    "TCP":   {"background": PROTOCOL_COLORS["TCP"],   "foreground": "#1a3a5c"},
    "UDP":   {"background": PROTOCOL_COLORS["UDP"],   "foreground": "#1a4a28"},
    "ICMP":  {"background": PROTOCOL_COLORS["ICMP"],  "foreground": "#7a3b00"},
    "DNS":   {"background": PROTOCOL_COLORS["DNS"],   "foreground": "#4a1a6a"},
    "HTTP":  {"background": PROTOCOL_COLORS["HTTP"],  "foreground": "#6a0000"},
    "OTHER": {"background": PROTOCOL_COLORS["OTHER"], "foreground": "#333333"},
}

# FIX 1 — Renamed first column ID from "#" to "num".
#          ttk reserves the "#N" syntax internally (#0 = tree column).
#          Using "#" as a custom ID caused tree.set(iid, "#") and
#          heading("#", ...) to behave incorrectly / silently return wrong data.
COLUMNS = [
    ("num",   "#",        55,  False),   # ← was "#" — now "num"
    ("time",  "Time",     110, False),
    ("src",   "Src IP",   160, True),
    ("dst",   "Dst IP",   160, True),
    ("proto", "Protocol", 80,  False),
    ("len",   "Length",   70,  False),
    ("info",  "Info",     320, True),
]


# ─────────────────────────────────────────────────────────────────────────────
# Packet Parser
# ─────────────────────────────────────────────────────────────────────────────
def parse_packet(pkt, index: int) -> dict:
    """Decompose a Scapy packet into a display-ready dict."""
    ts       = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src      = "?"
    dst      = "?"
    protocol = "OTHER"
    length   = len(pkt)
    info     = ""
    layers   = []

    # ── Ethernet ─────────────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        layers.append(
            f"[Ethernet]  src={eth.src}  dst={eth.dst}  type=0x{eth.type:04x}"
        )

    # ── Network layer ─────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip  = pkt[IP]
        src, dst = ip.src, ip.dst
        layers.append(
            f"[IP]  src={ip.src}  dst={ip.dst}  ttl={ip.ttl}  "
            f"proto={ip.proto}  id={ip.id}  len={ip.len}"
        )
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src, dst = ip6.src, ip6.dst
        layers.append(f"[IPv6]  src={ip6.src}  dst={ip6.dst}  nh={ip6.nh}")

    # ── Transport layer ───────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp      = pkt[TCP]
        flags    = _tcp_flags(tcp.flags)
        protocol = "TCP"
        info     = (
            f"{tcp.sport} → {tcp.dport}  [{flags}]  "
            f"seq={tcp.seq}  ack={tcp.ack}  win={tcp.window}"
        )
        layers.append(
            f"[TCP]  sport={tcp.sport}  dport={tcp.dport}  flags={flags}  "
            f"seq={tcp.seq}  ack={tcp.ack}  win={tcp.window}"
        )

    elif pkt.haslayer(UDP):
        udp      = pkt[UDP]
        protocol = "UDP"
        info     = f"{udp.sport} → {udp.dport}  len={udp.len}"
        layers.append(
            f"[UDP]  sport={udp.sport}  dport={udp.dport}  len={udp.len}"
        )

    elif pkt.haslayer(ICMP):
        icmp     = pkt[ICMP]
        protocol = "ICMP"

        # FIX 2 — ICMP types other than Echo (0) / Echo-Reply (8) have no
        #          .id or .seq fields.  Accessing them raises AttributeError
        #          (e.g. Type 3 Destination-Unreachable, Type 11 TTL-Exceeded).
        try:
            icmp_id  = icmp.id
            icmp_seq = icmp.seq
            id_seq   = f"  id={icmp_id}  seq={icmp_seq}"
        except AttributeError:
            id_seq   = ""

        info = f"type={icmp.type}  code={icmp.code}{id_seq}"
        layers.append(f"[ICMP]  type={icmp.type}  code={icmp.code}{id_seq}")

    # ── Application layer ─────────────────────────────────────────────────────
    if pkt.haslayer(DNS):
        dns      = pkt[DNS]
        protocol = "DNS"
        qname    = (
            dns.qd.qname.decode(errors="replace") if dns.qd else "?"
        )
        info = f"DNS {'Query' if dns.qr == 0 else 'Response'}  {qname}"
        layers.append(
            f"[DNS]  id={dns.id}  qr={dns.qr}  opcode={dns.opcode}  qname={qname}"
        )

    # FIX 3 — Guard HTTP parsing behind HTTP_AVAILABLE flag so that missing
    #          scapy.layers.http doesn't crash parse_packet at runtime.
    if HTTP_AVAILABLE:
        if pkt.haslayer(HTTPRequest):
            req      = pkt[HTTPRequest]
            protocol = "HTTP"
            method   = req.Method.decode(errors="replace") if req.Method else "?"
            path     = req.Path.decode(errors="replace")   if req.Path   else "?"
            host     = req.Host.decode(errors="replace")   if req.Host   else "?"
            info     = f"HTTP {method} {host}{path}"
            layers.append(f"[HTTP Request]  {method} {host}{path}")

        elif pkt.haslayer(HTTPResponse):
            resp     = pkt[HTTPResponse]
            protocol = "HTTP"
            status   = (
                resp.Status_Code.decode(errors="replace")
                if resp.Status_Code else "?"
            )
            info = f"HTTP Response {status}"
            layers.append(f"[HTTP Response]  Status={status}")

    # ── Raw payload ───────────────────────────────────────────────────────────
    payload_hex = ""
    if pkt.haslayer(Raw):
        raw_bytes   = bytes(pkt[Raw])
        payload_hex = _hex_dump(raw_bytes)
        layers.append(f"[Payload]  {len(raw_bytes)} bytes")

    layers_text = "\n".join(layers)
    if payload_hex:
        layers_text += (
            f"\n\n── Hex Dump ─────────────────────────────────\n{payload_hex}"
            f"\n\n── ASCII ────────────────────────────────────\n"
            f"{_safe_ascii(bytes(pkt[Raw]))}"
        )

    return {
        "index":       index,
        "timestamp":   ts,
        "src":         src,
        "dst":         dst,
        "protocol":    protocol,
        "length":      length,
        "info":        info,
        "layers_text": layers_text,
        "_pkt":        pkt,       # raw packet kept for .pcap export
    }


def _tcp_flags(flags) -> str:
    flag_map = {
        "F": "FIN", "S": "SYN", "R": "RST",
        "P": "PSH", "A": "ACK", "U": "URG",
        "E": "ECE", "C": "CWR",
    }
    try:
        s = str(flags)
        return "|".join(flag_map.get(c, c) for c in s if c in flag_map) or "NONE"
    except Exception:
        return str(flags)


def _hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk    = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{i:04x}   {hex_part:<{width * 3}}  {_safe_ascii(chunk)}")
    return "\n".join(lines)


def _safe_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


# ─────────────────────────────────────────────────────────────────────────────
# Sniffer Thread
# ─────────────────────────────────────────────────────────────────────────────
class SnifferThread(threading.Thread):
    """
    Runs Scapy sniff() in a background daemon thread.
    Parsed packet dicts (or error sentinels) are pushed into pkt_queue.
    The GUI drains the queue via a periodic after() timer — thread-safe.

    timeout=1 on each sniff() call means the stop event is checked every
    second, so the Stop button responds promptly even on quiet networks.
    """

    def __init__(self, iface: str, pkt_queue: queue.Queue):
        super().__init__(daemon=True)
        self.iface     = iface
        self.pkt_queue = pkt_queue
        self._stop_evt = threading.Event()
        self._counter  = 0

    def run(self):
        try:
            while not self._stop_evt.is_set():
                sniff(
                    iface   = self.iface,
                    prn     = self._handle_packet,
                    store   = False,
                    timeout = 1,
                    stop_filter = lambda _: self._stop_evt.is_set(),
                )
        except PermissionError as exc:
            self.pkt_queue.put({"_error": "permission", "message": str(exc)})
        except OSError as exc:
            self.pkt_queue.put({"_error": "oserror", "message": str(exc)})

    def _handle_packet(self, pkt):
        self._counter += 1
        self.pkt_queue.put(parse_packet(pkt, self._counter))

    def stop(self):
        self._stop_evt.set()


# ─────────────────────────────────────────────────────────────────────────────
# Main Application Window
# ─────────────────────────────────────────────────────────────────────────────
class NetWatchApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1280x780")
        self.minsize(900, 600)
        self.configure(bg="#1e1e2e")

        # ── State ─────────────────────────────────────────────────────────────
        self.all_packets      = []   # ordered list of every packet dict
        self.filtered_packets = []   # currently visible subset
        self.packet_map       = {}   # FIX 6: index → pkt_data for O(1) lookup
        self.sniffer          = None
        self.pkt_queue        = queue.Queue()
        self._polling         = False
        self._after_id        = None  # FIX 4: track pending after() callback

        # FIX 7 — DNS and HTTP added to counters (were silently counted as OTHER)
        self.counters = {
            "TCP": 0, "UDP": 0, "ICMP": 0,
            "DNS": 0, "HTTP": 0, "OTHER": 0,
        }

        # ── Build UI ──────────────────────────────────────────────────────────
        self._build_menu()
        self._build_toolbar()
        self._build_filter_bar()
        self._build_main_pane()
        self._build_status_bar()

        for tag, cfg in TAG_COLORS.items():
            self.tree.tag_configure(
                tag,
                background=cfg["background"],
                foreground=cfg["foreground"],
            )

        self._populate_interfaces()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─────────────────────────────────────────────────────────────────────────
    # UI Builders
    # ─────────────────────────────────────────────────────────────────────────

    def _build_menu(self):
        menubar   = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export to CSV…", command=self._export_csv)
        file_menu.add_command(label="Save as .pcap…", command=self._save_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Exit",           command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _build_toolbar(self):
        bar = tk.Frame(self, bg="#2a2a3e", pady=6, padx=8)
        bar.pack(fill="x", side="top")

        tk.Label(bar, text="Interface:", bg="#2a2a3e", fg="#cccccc",
                 font=("Segoe UI", 10)).pack(side="left", padx=(0, 4))

        self.iface_var = tk.StringVar()
        self.iface_cb  = ttk.Combobox(
            bar, textvariable=self.iface_var, width=26, state="readonly"
        )
        self.iface_cb.pack(side="left", padx=(0, 14))

        btn = {"font": ("Segoe UI", 10, "bold"), "relief": "flat",
               "cursor": "hand2", "padx": 12, "pady": 4}

        self.btn_start = tk.Button(bar, text="▶  Start", bg="#2ecc71",
                                   fg="white", command=self._start_capture, **btn)
        self.btn_start.pack(side="left", padx=4)

        self.btn_stop = tk.Button(bar, text="■  Stop", bg="#e74c3c",
                                  fg="white", command=self._stop_capture,
                                  state="disabled", **btn)
        self.btn_stop.pack(side="left", padx=4)

        self.btn_clear = tk.Button(bar, text="✕  Clear", bg="#7f8c8d",
                                   fg="white", command=self._clear_packets, **btn)
        self.btn_clear.pack(side="left", padx=4)

        tk.Frame(bar, bg="#2a2a3e").pack(side="left", fill="x", expand=True)

        tk.Button(bar, text="⬇ Export CSV", bg="#3498db", fg="white",
                  command=self._export_csv, **btn).pack(side="left", padx=4)
        tk.Button(bar, text="💾 Save PCAP", bg="#9b59b6", fg="white",
                  command=self._save_pcap, **btn).pack(side="left", padx=4)

    def _build_filter_bar(self):
        bar = tk.Frame(self, bg="#252535", pady=5, padx=8)
        bar.pack(fill="x", side="top")

        tk.Label(bar, text="🔍 Filters:", bg="#252535", fg="#aaaaaa",
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))

        def add_entry(label, width=18):
            tk.Label(bar, text=label, bg="#252535", fg="#cccccc",
                     font=("Segoe UI", 9)).pack(side="left", padx=(6, 2))
            var = tk.StringVar()
            ttk.Entry(bar, textvariable=var, width=width).pack(side="left")
            var.trace_add("write", lambda *_: self._apply_filters())
            return var

        self.filter_src   = add_entry("Src IP")
        self.filter_dst   = add_entry("Dst IP")
        self.filter_proto = add_entry("Protocol", 10)
        self.filter_port  = add_entry("Port", 8)

        tk.Button(bar, text="Reset", bg="#555566", fg="white",
                  font=("Segoe UI", 9), relief="flat", padx=8,
                  command=self._reset_filters).pack(side="left", padx=(12, 0))

    def _build_main_pane(self):
        paned = tk.PanedWindow(self, orient="vertical", bg="#1e1e2e",
                               sashwidth=5, sashrelief="flat", sashpad=2)
        paned.pack(fill="both", expand=True, padx=6, pady=(4, 0))

        # ── Top: packet list ──────────────────────────────────────────────────
        top_frame = tk.Frame(paned, bg="#1e1e2e")
        paned.add(top_frame, minsize=200)

        vsb = ttk.Scrollbar(top_frame, orient="vertical")
        hsb = ttk.Scrollbar(top_frame, orient="horizontal")

        self.tree = ttk.Treeview(
            top_frame,
            columns    = [c[0] for c in COLUMNS],
            show       = "headings",
            yscrollcommand = vsb.set,
            xscrollcommand = hsb.set,
            selectmode = "browse",
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        for col_id, heading, width, stretch in COLUMNS:
            self.tree.heading(col_id, text=heading,
                              command=lambda c=col_id: self._sort_column(c))
            self.tree.column(col_id, width=width, stretch=stretch, anchor="w")

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        top_frame.rowconfigure(0, weight=1)
        top_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

        # ── Bottom: detail panel ──────────────────────────────────────────────
        # detail_label uses pack on bottom_frame.
        # Text + scrollbars use grid on grid_frame (separate child).
        # Mixing pack/grid on the same parent crashes Tkinter.
        bottom_frame = tk.Frame(paned, bg="#1e1e2e")
        paned.add(bottom_frame, minsize=120)

        tk.Label(bottom_frame, text="Packet Detail", bg="#2a2a3e",
                 fg="#cccccc", font=("Segoe UI", 9, "bold"),
                 anchor="w", padx=8).pack(fill="x", side="top")

        grid_frame = tk.Frame(bottom_frame, bg="#1e1e2e")
        grid_frame.pack(fill="both", expand=True, side="top")

        dvsb = ttk.Scrollbar(grid_frame, orient="vertical")
        dhsb = ttk.Scrollbar(grid_frame, orient="horizontal")

        self.detail_text = tk.Text(
            grid_frame,
            bg="#0d1117", fg="#e6edf3",
            font=("Courier New", 9),
            wrap="none", state="disabled",
            yscrollcommand=dvsb.set,
            xscrollcommand=dhsb.set,
            insertbackground="#e6edf3",
        )
        dvsb.config(command=self.detail_text.yview)
        dhsb.config(command=self.detail_text.xview)

        self.detail_text.grid(row=0, column=0, sticky="nsew")
        dvsb.grid(row=0, column=1, sticky="ns")
        dhsb.grid(row=1, column=0, sticky="ew")
        grid_frame.rowconfigure(0, weight=1)
        grid_frame.columnconfigure(0, weight=1)

    def _build_status_bar(self):
        bar = tk.Frame(self, bg="#2a2a3e", pady=3, padx=8, relief="sunken")
        bar.pack(fill="x", side="bottom")

        def lbl(text, fg, side="left", padx=8):
            w = tk.Label(bar, text=text, bg="#2a2a3e", fg=fg,
                         font=("Segoe UI", 9))
            w.pack(side=side, padx=padx)
            return w

        self.status_total = tk.Label(bar, text="Packets: 0", bg="#2a2a3e",
                                     fg="#ffffff", font=("Segoe UI", 9, "bold"))
        self.status_total.pack(side="left", padx=(0, 16))

        # FIX 7 — DNS and HTTP status labels added to match their counters
        self.status_tcp   = lbl("TCP: 0",   "#5dade2")
        self.status_udp   = lbl("UDP: 0",   "#58d68d")
        self.status_icmp  = lbl("ICMP: 0",  "#f0a500")
        self.status_dns   = lbl("DNS: 0",   "#c39bd3")   # ← new
        self.status_http  = lbl("HTTP: 0",  "#ec7063")   # ← new
        self.status_other = lbl("Other: 0", "#aaaaaa")

        self.status_state = tk.Label(bar, text="● Idle", bg="#2a2a3e",
                                     fg="#888888", font=("Segoe UI", 9, "bold"))
        self.status_state.pack(side="right", padx=8)

    # ─────────────────────────────────────────────────────────────────────────
    # Interface Detection
    # ─────────────────────────────────────────────────────────────────────────

    def _populate_interfaces(self):
        try:
            ifaces = get_if_list()
        except Exception as e:
            ifaces = []
            messagebox.showwarning("Interface Detection",
                                   f"Could not list interfaces:\n{e}")

        if not ifaces:
            ifaces = ["eth0", "wlan0", "lo"]

        self.iface_cb["values"] = ifaces
        default = next((i for i in ifaces if "lo" not in i.lower()), ifaces[0])
        self.iface_var.set(default)

    # ─────────────────────────────────────────────────────────────────────────
    # Capture Control
    # ─────────────────────────────────────────────────────────────────────────

    def _start_capture(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showerror("No Interface",
                                 "Please select a network interface.")
            return

        if self.sniffer and self.sniffer.is_alive():
            return  # already running

        # FIX 5 — Drain any stale packets left from a previous capture session
        #          so they don't appear as if captured in this new session.
        while not self.pkt_queue.empty():
            try:
                self.pkt_queue.get_nowait()
            except queue.Empty:
                break

        # Reset counters for the new session
        self.counters = {k: 0 for k in self.counters}

        self.sniffer = SnifferThread(iface, self.pkt_queue)
        self.sniffer.start()

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        self._polling  = True
        self._after_id = self.after(50, self._poll_queue)   # FIX 4: save ID

        self.status_state.config(text="● Capturing", fg="#2ecc71")

    def _stop_capture(self):
        # FIX 10 — Guard: only reset UI if capture was actually running
        was_running = self.sniffer is not None or self._polling

        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

        self._polling = False

        # FIX 4 — Cancel the pending after() callback so it cannot fire
        #          after the window has been destroyed (would raise TclError).
        if self._after_id is not None:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

        if was_running:
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")
            self.status_state.config(text="● Idle", fg="#888888")

    def _clear_packets(self):
        self._stop_capture()
        self.all_packets.clear()
        self.filtered_packets.clear()
        self.packet_map.clear()                   # FIX 6: clear lookup dict
        self.tree.delete(*self.tree.get_children())
        self._set_detail("")
        self.counters = {k: 0 for k in self.counters}
        self._update_status()

    # ─────────────────────────────────────────────────────────────────────────
    # Queue Polling
    # ─────────────────────────────────────────────────────────────────────────

    def _poll_queue(self):
        if not self._polling:
            return

        processed = 0
        while not self.pkt_queue.empty() and processed < 100:
            try:
                pkt_data = self.pkt_queue.get_nowait()
                self._ingest_packet(pkt_data)
                processed += 1
            except queue.Empty:
                break

        # FIX 4 — Save the new after() ID so it can be cancelled if needed
        self._after_id = self.after(50, self._poll_queue)

    def _ingest_packet(self, pkt_data: dict):
        # ── Error sentinel from SnifferThread ─────────────────────────────────
        if "_error" in pkt_data:
            self._stop_capture()
            if pkt_data["_error"] == "permission":
                messagebox.showerror(
                    "Permission Denied",
                    "Raw socket access requires elevated privileges.\n\n"
                    "  Linux:   sudo python3 main.py\n"
                    "  Windows: run VS Code / terminal as Administrator\n\n"
                    f"Detail: {pkt_data['message']}"
                )
            else:
                messagebox.showerror(
                    "Capture Error",
                    f"The sniffer stopped unexpectedly:\n\n{pkt_data['message']}"
                )
            return

        # ── Normal packet ──────────────────────────────────────────────────────
        self.all_packets.append(pkt_data)
        self.packet_map[pkt_data["index"]] = pkt_data   # FIX 6

        proto = pkt_data["protocol"]
        key   = proto if proto in self.counters else "OTHER"
        self.counters[key] += 1
        self._update_status()

        if self._packet_matches_filters(pkt_data):
            self.filtered_packets.append(pkt_data)
            self._insert_tree_row(pkt_data)

    def _insert_tree_row(self, pkt_data: dict):
        proto = pkt_data["protocol"]
        tag   = proto if proto in TAG_COLORS else "OTHER"

        self.tree.insert(
            "", "end",
            iid    = str(pkt_data["index"]),
            values = (
                pkt_data["index"],
                pkt_data["timestamp"],
                pkt_data["src"],
                pkt_data["dst"],
                proto,
                pkt_data["length"],
                pkt_data["info"],
            ),
            tags = (tag,),
        )
        self.tree.yview_moveto(1.0)

    # ─────────────────────────────────────────────────────────────────────────
    # Live Filtering
    # ─────────────────────────────────────────────────────────────────────────

    def _packet_matches_filters(self, pkt_data: dict) -> bool:
        src_f   = self.filter_src.get().strip().lower()
        dst_f   = self.filter_dst.get().strip().lower()
        proto_f = self.filter_proto.get().strip().lower()
        port_f  = self.filter_port.get().strip()

        if src_f   and src_f   not in pkt_data["src"].lower():      return False
        if dst_f   and dst_f   not in pkt_data["dst"].lower():      return False
        if proto_f and proto_f not in pkt_data["protocol"].lower(): return False
        if port_f  and port_f  not in pkt_data["info"]:             return False
        return True

    def _apply_filters(self):
        self.tree.delete(*self.tree.get_children())
        self.filtered_packets = []
        for p in self.all_packets:
            if self._packet_matches_filters(p):
                self.filtered_packets.append(p)
                self._insert_tree_row(p)

    def _reset_filters(self):
        self.filter_src.set("")
        self.filter_dst.set("")
        self.filter_proto.set("")
        self.filter_port.set("")

    # ─────────────────────────────────────────────────────────────────────────
    # Row Selection → Detail Panel
    # ─────────────────────────────────────────────────────────────────────────

    def _on_row_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0])
        except ValueError:
            return

        # FIX 6 — O(1) dict lookup replaces O(n) linear scan
        pkt_data = self.packet_map.get(idx)
        if pkt_data:
            self._set_detail(pkt_data["layers_text"])

    def _set_detail(self, text: str):
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.config(state="disabled")

    # ─────────────────────────────────────────────────────────────────────────
    # Status Bar
    # ─────────────────────────────────────────────────────────────────────────

    def _update_status(self):
        c = self.counters
        self.status_total.config(text=f"Packets: {len(self.all_packets)}")
        self.status_tcp.config(text=f"TCP: {c['TCP']}")
        self.status_udp.config(text=f"UDP: {c['UDP']}")
        self.status_icmp.config(text=f"ICMP: {c['ICMP']}")
        self.status_dns.config(text=f"DNS: {c['DNS']}")    # FIX 7
        self.status_http.config(text=f"HTTP: {c['HTTP']}") # FIX 7
        self.status_other.config(text=f"Other: {c['OTHER']}")

    # ─────────────────────────────────────────────────────────────────────────
    # Export / Save
    # ─────────────────────────────────────────────────────────────────────────

    def _export_csv(self):
        # FIX 9 — If filters are active, export only filtered packets.
        #          Previous code used "filtered or all", meaning active filters
        #          with zero matches would silently export ALL packets instead.
        filters_active = any([
            self.filter_src.get().strip(),
            self.filter_dst.get().strip(),
            self.filter_proto.get().strip(),
            self.filter_port.get().strip(),
        ])
        packets = self.filtered_packets if filters_active else self.all_packets

        if not packets:
            msg = ("No packets match the current filters."
                   if filters_active else "No packets captured yet.")
            messagebox.showinfo("Export CSV", msg)
            return

        path = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not path:
            return

        rows = [
            {
                "#":        p["index"],
                "Time":     p["timestamp"],
                "Src IP":   p["src"],
                "Dst IP":   p["dst"],
                "Protocol": p["protocol"],
                "Length":   p["length"],
                "Info":     p["info"],
            }
            for p in packets
        ]
        try:
            pd.DataFrame(rows).to_csv(path, index=False)
            messagebox.showinfo("Export CSV",
                                f"Saved {len(rows)} packets to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export CSV", f"Failed to save:\n{e}")

    def _save_pcap(self):
        if not self.all_packets:
            messagebox.showinfo("Save PCAP", "No packets captured yet.")
            return

        path = filedialog.asksaveasfilename(
            title="Save PCAP",
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")],
        )
        if not path:
            return

        raw_pkts = [p["_pkt"] for p in self.all_packets if "_pkt" in p]
        try:
            wrpcap(path, raw_pkts)
            messagebox.showinfo("Save PCAP",
                                f"Saved {len(raw_pkts)} packets to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save PCAP", f"Failed to save:\n{e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Column Sort
    # ─────────────────────────────────────────────────────────────────────────

    def _sort_column(self, col: str):
        items   = [(self.tree.set(iid, col), iid)
                   for iid in self.tree.get_children("")]
        reverse = getattr(self, f"_sort_rev_{col}", False)

        # FIX 8 — Safe key: try int per-item, fall back to lower-string.
        #          Old code wrapped the entire sort in try/except, meaning a
        #          single non-numeric cell switched ALL rows to string sort.
        def safe_key(x):
            try:
                return (0, int(x[0]), "")
            except (ValueError, TypeError):
                return (1, 0, x[0].lower())

        items.sort(key=safe_key, reverse=reverse)

        for pos, (_, iid) in enumerate(items):
            self.tree.move(iid, "", pos)

        setattr(self, f"_sort_rev_{col}", not reverse)

    # ─────────────────────────────────────────────────────────────────────────
    # About / Close
    # ─────────────────────────────────────────────────────────────────────────

    def _show_about(self):
        http_note = "HTTP layer: available" if HTTP_AVAILABLE else "HTTP layer: not available (older Scapy)"
        messagebox.showinfo(
            "About NetWatch",
            f"NetWatch v{APP_VERSION}\n\n"
            "Real-time GUI Network Packet Analyzer\n"
            "Python 3 · Scapy · Tkinter · Pandas\n\n"
            f"{http_note}\n\n"
            "Run with root / Administrator privileges."
        )

    def _on_close(self):
        # FIX 4 — Cancel pending after() before destroying the window.
        #          Without this, the scheduled _poll_queue fires on a destroyed
        #          Tk widget and raises TclError / RuntimeError.
        self._stop_capture()    # sets _polling=False and cancels _after_id
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if platform.system() == "Windows":
        print("[INFO] Windows detected — Npcap required: https://npcap.com")
        print("[INFO] Run VS Code / this terminal as Administrator.")

    if not HTTP_AVAILABLE:
        print("[WARN] scapy.layers.http not available — HTTP parsing disabled.")

    app = NetWatchApp()

    style = ttk.Style(app)
    for theme in ("clam", "alt", "default"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break

    app.mainloop()