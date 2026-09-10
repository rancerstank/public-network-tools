#!/usr/bin/env python3
"""
diag_fgt_sniffer_ssh_standalone_v1.py (ARCHIVED / LEGACY)

Standalone FortiGate packet sniffer over direct SSH (asyncssh-based).
SUPERSEDED BY: diag_fgt_sniffer_ssh_standalone_v2.py

Note:
    This v1 script is archived and preserved for historical/reference purposes.
    Use diag_fgt_sniffer_ssh_standalone_v2.py for active production troubleshooting,
    which features Paramiko worker threads, Wireshark text2pcap integration,
    live dark console output with per-host color coding, live Boolean/Regex filtering,
    structured JSON exports, and AES-256-GCM encrypted profiles.

Requirements (v1):
    Python 3.10+
    pip install asyncssh

No NFP internal libraries, FortiManager, Microsoft Graph, SharePoint, or netaddr.
Targets must be an IP address or DNS-resolvable hostname. Output is written to
"local-output" beside this script.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

try:
    import asyncssh
except ImportError:
    raise SystemExit(
        "Missing dependency: asyncssh\n"
        "Install it with: py -m pip install asyncssh"
    )

SSH_PORT = 2222
SSH_USERNAME_ENV = "ns_fmg_gate_user"
SSH_PASSWORD_ENV = "ns_fmg_gate_pass"
KEEPALIVE_INTERVAL = 30
KEEPALIVE_COUNT_MAX = 5
IDLE_HEARTBEAT_SECONDS = 25
MAX_DURATION_SECONDS = 24 * 60 * 60
MAX_PARALLEL_DEVICES = 8

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = SCRIPT_DIR / "local-output"
OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

DEBUG = "debug"
INFO = "info"
WARNING = "warning"
ERROR = "error"


class LocalText:
    """Small thread-safe replacement for the internal text_file writer."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._file = None
        self._lock = threading.Lock()

    def set_path(self, path: Path):
        with self._lock:
            self.close()
            self.path = Path(path)

    def writeline(self, message, level=INFO, show_level=True):
        text = str(message)
        prefix = f"({level}) " if show_level else ""
        line = prefix + text
        with self._lock:
            if self._file is None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._file = self.path.open("a", encoding="utf-8")
            self._file.write(line + ("" if line.endswith("\n") else "\n"))
            self._file.flush()
        print(line)

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None


text_file = LocalText(OUTPUT_PATH / f"sniffer-log-{datetime.now():%Y%m%d-%H%M%S}.txt")


@dataclass
class RunArgs:
    action: str = "start"
    device: str = ""
    ssh_username: str = ""
    ssh_password: str = ""
    interface: str = "any"
    protocol: str = ""
    host: str = ""
    port: str = ""
    net: str = ""
    src_host: str = ""
    src_port: str = ""
    src_net: str = ""
    dst_host: str = ""
    dst_port: str = ""
    dst_net: str = ""
    custom_filter: str = ""
    count: int = 300
    duration_seconds: int = 1800
    verbose: int = 6
    capture_name: str | None = None
    create_pcap: bool = False


def timestamp_token():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def sanitize_component(value: str, fallback: str):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip())
    return cleaned.strip("-_.") or fallback


def parse_devices(raw: str):
    result, seen = [], set()
    for item in str(raw or "").split(","):
        value = item.strip()
        if value and value.casefold() not in seen:
            seen.add(value.casefold())
            result.append(value)
    return result


def split_values(raw: str):
    return [x.strip() for x in re.split(r"\s+and\s+|,|;", raw or "", flags=re.I) if x.strip()]


def validate_target(value: str):
    if not value or any(c.isspace() for c in value):
        raise ValueError(f"Invalid IP address or hostname: {value!r}")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(r"(?i)(?=.{1,253}\.?$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?", value):
        raise ValueError(f"Invalid IP address or hostname: {value}")


def validate_ip(value: str):
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def validate_net(value: str):
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR network: {value}") from exc


def validate_port(value: str):
    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid port: {value}") from exc
    if not 1 <= number <= 65535:
        raise ValueError(f"Port out of range (1-65535): {value}")
    return number


def build_filter(args: RunArgs):
    clauses = []
    for value in split_values(args.protocol):
        value = value.lower()
        if value not in {"tcp", "udp", "icmp"}:
            raise ValueError(f"Invalid protocol: {value}")
        clauses.append(value)
    for field, prefix, validator in (
        (args.host, "host", validate_ip),
        (args.src_host, "src host", validate_ip),
        (args.dst_host, "dst host", validate_ip),
        (args.port, "port", validate_port),
        (args.src_port, "src port", validate_port),
        (args.dst_port, "dst port", validate_port),
        (args.net, "net", validate_net),
        (args.src_net, "src net", validate_net),
        (args.dst_net, "dst net", validate_net),
    ):
        for value in split_values(field):
            validator(value)
            clauses.append(f"{prefix} {value}")
    if args.custom_filter.strip():
        clauses.append(f"({args.custom_filter.strip()})" if clauses else args.custom_filter.strip())
    return " and ".join(clauses)


def quote_filter(value: str):
    return '"' + value.replace('"', '\\"') + '"'


def build_sniffer_command(args: RunArgs):
    return f"diagnose sniffer packet {args.interface} {quote_filter(build_filter(args))} {args.verbose} {args.count} l"


def credentials(args: RunArgs):
    username = (args.ssh_username or os.getenv(SSH_USERNAME_ENV, "")).strip()
    password = args.ssh_password or os.getenv(SSH_PASSWORD_ENV, "")
    if "\\" in username:
        username = username.split("\\", 1)[1]
    if not username or not password:
        raise ValueError(
            f"SSH credentials are required. Use --ssh-username/--ssh-password or "
            f"environment variables {SSH_USERNAME_ENV}/{SSH_PASSWORD_ENV}."
        )
    return username, password


class StopFanout:
    def __init__(self, upstream=None):
        self.upstream = upstream
        self.local = threading.Event()
        self._lock = threading.Lock()
        self.source = None
        self.reason = None

    def is_set(self):
        return self.local.is_set() or bool(self.upstream and self.upstream.is_set())

    def set(self, source=None, reason=None):
        with self._lock:
            self.source = self.source or source
            self.reason = self.reason or reason
        self.local.set()


async def run_simple_command(host, username, password, command):
    try:
        async with asyncssh.connect(
            host,
            username=username,
            password=password,
            port=SSH_PORT,
            known_hosts=None,
            keepalive_interval=KEEPALIVE_INTERVAL,
            keepalive_count_max=KEEPALIVE_COUNT_MAX,
        ) as conn:
            result = await conn.run(command, check=False)
            return result.exit_status, result.stdout, result.stderr
    except Exception as exc:
        return 1, "", str(exc)


async def run_live_sniffer(host, username, password, command, expected_count=0, duration=0, stop_event=None):
    stdout_chunks, stderr_chunks = [], []
    packet_pattern = re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\b")
    try:
        async with asyncssh.connect(
            host,
            username=username,
            password=password,
            port=SSH_PORT,
            known_hosts=None,
            keepalive_interval=KEEPALIVE_INTERVAL,
            keepalive_count_max=KEEPALIVE_COUNT_MAX,
        ) as conn:
            process = await conn.create_process(term_type="vt100")
            process.stdin.write(command + "\n")
            started = last_activity = time.monotonic()
            scan_buffer = ""
            packet_count = 0
            stop_reason = ""
            ctrl_c_sent = False
            quiet_after_stop = 0

            while True:
                had_output = False
                try:
                    chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=0.4)
                except asyncio.TimeoutError:
                    chunk = ""
                if chunk:
                    stdout_chunks.append(chunk)
                    scan_buffer += chunk
                    had_output = True
                    last_activity = time.monotonic()
                    while "\n" in scan_buffer:
                        line, scan_buffer = scan_buffer.split("\n", 1)
                        packet_count += len(packet_pattern.findall(line))

                try:
                    err = await asyncio.wait_for(process.stderr.read(2048), timeout=0.05)
                except asyncio.TimeoutError:
                    err = ""
                if err:
                    stderr_chunks.append(err)
                    had_output = True
                    last_activity = time.monotonic()

                if expected_count > 0 and packet_count >= expected_count and not ctrl_c_sent:
                    process.stdin.write("\x03")
                    ctrl_c_sent = True
                    stop_reason = "packet_count"
                elif duration > 0 and time.monotonic() - started >= duration and not ctrl_c_sent:
                    process.stdin.write("\x03")
                    ctrl_c_sent = True
                    stop_reason = "duration_limit"
                elif stop_event and stop_event.is_set() and not ctrl_c_sent:
                    process.stdin.write("\x03")
                    ctrl_c_sent = True
                    stop_reason = "manual_stop"

                if time.monotonic() - last_activity >= IDLE_HEARTBEAT_SECONDS and not ctrl_c_sent:
                    process.stdin.write("\n")
                    last_activity = time.monotonic()

                if process.exit_status is not None:
                    break
                quiet_after_stop = quiet_after_stop + 1 if ctrl_c_sent and not had_output else 0
                if quiet_after_stop >= 5:
                    break

            try:
                process.stdin.write("exit\n")
            except Exception:
                pass
            if scan_buffer:
                packet_count += len(packet_pattern.findall(scan_buffer))
            return process.exit_status or 0, "".join(stdout_chunks), "".join(stderr_chunks), stop_reason or "completed", packet_count
    except Exception as exc:
        return 1, "", str(exc), "connection_error", 0


def find_text2pcap():
    for candidate in (
        shutil.which("text2pcap"),
        r"C:\Program Files\Wireshark\text2pcap.exe",
        r"C:\Program Files\Ethereal\text2pcap.exe",
    ):
        if candidate and Path(candidate).exists():
            return str(candidate)
    return None


def normalize_for_text2pcap(raw_text: str):
    output, packet = [], []
    timestamp = None

    def flush():
        nonlocal packet, timestamp
        if packet:
            if timestamp:
                output.append(timestamp)
            output.extend(packet)
            output.append("")
        packet, timestamp = [], None

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        absolute = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+", line)
        if absolute:
            flush()
            timestamp = absolute.group(1)
            continue
        hex_row = re.match(r"^0x([0-9a-fA-F]{4})\s+(.+)$", line)
        if not hex_row:
            continue
        groups = re.findall(r"[0-9a-fA-F]+", hex_row.group(2).split("\t", 1)[0])
        octets = []
        for group in groups:
            if len(group) >= 2 and len(group) % 2 == 0:
                octets.extend(group[i:i+2] for i in range(0, len(group), 2))
            if len(octets) >= 16:
                break
        if octets:
            packet.append(f"00{hex_row.group(1).lower()} " + " ".join(octets[:16]))
    flush()
    return "\n".join(output).strip() + ("\n" if output else "")


def create_pcap(text_path: Path):
    executable = find_text2pcap()
    if not executable:
        return None, "text2pcap not found. Install Wireshark to enable PCAP conversion."
    normalized = normalize_for_text2pcap(text_path.read_text(encoding="utf-8", errors="replace"))
    if not normalized.strip():
        return None, "No timestamp and hex packet rows were detected."
    temp_path = text_path.with_suffix(".text2pcap.txt")
    pcap_path = text_path.with_suffix(".pcap")
    try:
        temp_path.write_text(normalized, encoding="utf-8")
        proc = subprocess.run(
            [executable, "-q", "-t", "ISO", str(temp_path), str(pcap_path)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            return None, (proc.stderr or proc.stdout or "text2pcap failed").strip()
        return pcap_path, ""
    finally:
        temp_path.unlink(missing_ok=True)


def execute_device(args: RunArgs, target: str, stop_event=None):
    validate_target(target)
    username, password = credentials(args)
    safe_target = sanitize_component(target, "firewall")
    label = sanitize_component(args.capture_name or "sniffer", "sniffer")
    stem = f"{safe_target}-{label}-{timestamp_token()}"
    capture_path = OUTPUT_PATH / f"{stem}.txt"
    text_file.writeline(f"[{target}] Connecting to {target}:{SSH_PORT} as {username}.", INFO)

    if args.action == "stop":
        code, stdout, stderr = asyncio.run(
            run_simple_command(target, username, password, "diagnose sniffer packet stop")
        )
        if stdout:
            capture_path.write_text(stdout + ("\n--- STDERR ---\n" + stderr if stderr else ""), encoding="utf-8")
        if code:
            text_file.writeline(f"[{target}] Stop action failed: {stderr or code}", ERROR)
        else:
            text_file.writeline(f"[{target}] Stop action completed.", INFO)
        return {"target": target, "had_error": bool(code), "reason": "stop_action", "packets": 0}

    if not 0 <= args.verbose <= 6:
        raise ValueError("Verbose must be between 0 and 6.")
    if args.count < 0:
        raise ValueError("Count must be 0 or greater.")
    if not 0 <= args.duration_seconds <= MAX_DURATION_SECONDS:
        raise ValueError(f"Duration must be 0 through {MAX_DURATION_SECONDS} seconds.")
    if args.create_pcap:
        args.verbose = 6

    command = build_sniffer_command(args)
    text_file.writeline(f"[{target}] SSH command: {command}", DEBUG)
    code, stdout, stderr, reason, packets = asyncio.run(
        run_live_sniffer(target, username, password, command, args.count, args.duration_seconds, stop_event)
    )
    content = stdout or ""
    if stderr:
        content += "\n\n--- STDERR ---\n" + stderr
    capture_path.write_text(content, encoding="utf-8", errors="replace")
    text_file.writeline(f"[{target}] Saved capture: {capture_path}", INFO)

    if args.create_pcap:
        pcap_path, error = create_pcap(capture_path)
        if pcap_path:
            text_file.writeline(f"[{target}] Created PCAP: {pcap_path}", INFO)
        else:
            text_file.writeline(f"[{target}] PCAP not created: {error}", WARNING)

    coordinated = reason in {"packet_count", "duration_limit", "manual_stop"}
    had_error = bool(code) and not coordinated
    text_file.writeline(
        f"[{target}] Completed: reason={reason}; packet_markers={packets}; error={had_error}",
        ERROR if had_error else INFO,
    )
    return {"target": target, "had_error": had_error, "reason": reason, "packets": packets}


def execute_run(args: RunArgs, stop_event=None):
    devices = parse_devices(args.device)
    if not devices:
        raise ValueError("At least one IP address or resolvable hostname is required.")
    text_file.set_path(OUTPUT_PATH / f"sniffer-log-{timestamp_token()}.txt")
    shared_stop = StopFanout(stop_event)
    results = []
    with ThreadPoolExecutor(max_workers=min(len(devices), MAX_PARALLEL_DEVICES)) as pool:
        futures = {pool.submit(execute_device, replace(args, device=device), device, shared_stop): device for device in devices}
        for future in as_completed(futures):
            device = futures[future]
            try:
                result = future.result()
                results.append(result)
                if result["reason"] in {"packet_count", "duration_limit"} and not shared_stop.is_set():
                    shared_stop.set(device, result["reason"])
            except Exception as exc:
                text_file.writeline(f"[{device}] Worker failed: {exc}", ERROR)
                results.append({"target": device, "had_error": True, "reason": "worker_error", "packets": 0})
    text_file.close()
    return any(item["had_error"] for item in results)


def parse_args():
    parser = argparse.ArgumentParser(description="Standalone FortiGate packet sniffer over direct SSH port 2222.")
    parser.add_argument("action", nargs="?", choices=["start", "stop"])
    parser.add_argument("--device", help="IP/FQDN, or comma-separated targets")
    parser.add_argument("--ssh-username", default=os.getenv(SSH_USERNAME_ENV, ""))
    parser.add_argument("--ssh-password", default=os.getenv(SSH_PASSWORD_ENV, ""))
    parser.add_argument("--interface", default="any")
    parser.add_argument("--protocol", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", default="")
    parser.add_argument("--net", default="")
    parser.add_argument("--src-host", default="")
    parser.add_argument("--src-port", default="")
    parser.add_argument("--src-net", default="")
    parser.add_argument("--dst-host", default="")
    parser.add_argument("--dst-port", default="")
    parser.add_argument("--dst-net", default="")
    parser.add_argument("--custom-filter", "--options", default="")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--verbose", type=int, default=6)
    parser.add_argument("--capture-name")
    parser.add_argument("--create-pcap", action="store_true")
    parser.add_argument("--gui", action="store_true")
    ns = parser.parse_args()
    return ns, RunArgs(**{k: v for k, v in vars(ns).items() if k in RunArgs.__dataclass_fields__})


GUI_FIELDS = [
    ("device", "Target IP/FQDN (comma-separated)"),
    ("ssh_username", "SSH Username"),
    ("ssh_password", "SSH Password"),
    ("interface", "Interface"),
    ("protocol", "Protocol"),
    ("host", "Host"),
    ("port", "Port"),
    ("net", "Net/CIDR"),
    ("src_host", "Source Host"),
    ("src_port", "Source Port"),
    ("src_net", "Source Net/CIDR"),
    ("dst_host", "Destination Host"),
    ("dst_port", "Destination Port"),
    ("dst_net", "Destination Net/CIDR"),
    ("custom_filter", "Custom Filter"),
    ("count", "Packet Count (0 unlimited)"),
    ("duration_seconds", "Duration Seconds (0 unlimited)"),
    ("verbose", "Verbose (0-6)"),
    ("capture_name", "Capture Label"),
]


def run_gui(initial: RunArgs):
    root = tk.Tk()
    root.title("Standalone FortiGate Sniffer via SSH")
    entries = {}
    for row, (field, label) in enumerate(GUI_FIELDS):
        ttk.Label(root, text=label + ":").grid(row=row, column=0, sticky="w", padx=6, pady=2)
        entry = ttk.Entry(root, width=58, show="*" if field == "ssh_password" else "")
        entry.grid(row=row, column=1, padx=6, pady=2)
        value = getattr(initial, field)
        entry.insert(0, "" if value is None else str(value))
        entries[field] = entry

    row = len(GUI_FIELDS)
    pcap_var = tk.BooleanVar(value=initial.create_pcap)
    ttk.Checkbutton(root, text="Create PCAP (requires Wireshark text2pcap)", variable=pcap_var).grid(row=row, column=1, sticky="w", padx=6)
    row += 1
    status = tk.StringVar(value=f"Output: {OUTPUT_PATH}")
    ttk.Label(root, textvariable=status, wraplength=650).grid(row=row, column=0, columnspan=2, sticky="w", padx=6, pady=6)
    row += 1
    state = {"running": False, "stop": None}

    def collect(action):
        values = {name: entry.get().strip() for name, entry in entries.items()}
        try:
            return RunArgs(
                action=action,
                device=values["device"],
                ssh_username=values["ssh_username"],
                ssh_password=values["ssh_password"],
                interface=values["interface"] or "any",
                protocol=values["protocol"], host=values["host"], port=values["port"], net=values["net"],
                src_host=values["src_host"], src_port=values["src_port"], src_net=values["src_net"],
                dst_host=values["dst_host"], dst_port=values["dst_port"], dst_net=values["dst_net"],
                custom_filter=values["custom_filter"], count=int(values["count"] or 0),
                duration_seconds=int(values["duration_seconds"] or 0), verbose=int(values["verbose"] or 6),
                capture_name=values["capture_name"] or None, create_pcap=pcap_var.get(),
            )
        except ValueError as exc:
            raise ValueError(f"Count, duration, and verbose must be whole numbers: {exc}") from exc

    def worker(run_args):
        try:
            failed = execute_run(run_args, state["stop"])
            root.after(0, lambda: finish("Completed with errors." if failed else "Completed successfully."))
        except Exception as exc:
            root.after(0, lambda msg=str(exc): finish(f"Run failed: {msg}"))

    def finish(message):
        state["running"] = False
        state["stop"] = None
        start_button.state(["!disabled"])
        stop_button.state(["disabled"])
        status.set(message + f" Output: {OUTPUT_PATH}")

    def start():
        if state["running"]:
            return
        try:
            args = collect("start")
            build_filter(args)
        except Exception as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        state["running"] = True
        state["stop"] = threading.Event()
        start_button.state(["disabled"])
        stop_button.state(["!disabled"])
        status.set("Capture running...")
        threading.Thread(target=worker, args=(args,), daemon=True).start()

    def stop():
        if state["running"] and state["stop"]:
            state["stop"].set()
            stop_button.state(["disabled"])
            status.set("Stopping active capture...")

    def open_output():
        try:
            if os.name == "nt":
                os.startfile(OUTPUT_PATH)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(OUTPUT_PATH)])
            else:
                subprocess.Popen(["xdg-open", str(OUTPUT_PATH)])
        except Exception as exc:
            messagebox.showerror("Open output folder", str(exc))

    start_button = ttk.Button(root, text="Start Sniffer", command=start)
    start_button.grid(row=row, column=0, sticky="ew", padx=6, pady=6)
    stop_button = ttk.Button(root, text="Stop Active Capture", command=stop)
    stop_button.grid(row=row, column=1, sticky="ew", padx=6, pady=6)
    stop_button.state(["disabled"])
    row += 1
    ttk.Button(root, text="Open Local Output Folder", command=open_output).grid(row=row, column=0, columnspan=2, sticky="ew", padx=6, pady=4)
    root.mainloop()


def main():
    ns, args = parse_args()
    if ns.gui or not args.action or not args.device:
        run_gui(args)
        return
    try:
        failed = execute_run(args)
    except KeyboardInterrupt:
        text_file.writeline("Interrupted by user.", WARNING)
        failed = True
    except Exception as exc:
        text_file.writeline(f"Run failed: {exc}", ERROR)
        failed = True
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
