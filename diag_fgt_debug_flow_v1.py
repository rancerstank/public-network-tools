"""
diag_fgt_debug_flow_ssh_standalone_v2.py

Standalone FortiGate Debug Flow utility using SSH instead of the FortiOS REST API.

Adds:
- Python requirements check.
- GUI button to check/install missing Python packages.
- Start button automatically blocks with a clear message if requirements are missing.

Dependency:
- paramiko

Install manually if preferred:
    py -m pip install --upgrade paramiko
"""

from __future__ import annotations

import importlib.util
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Callable

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except Exception:
    tk = None
    ttk = None
    filedialog = None
    messagebox = None
    scrolledtext = None

REQUIRED_PACKAGES = {
    "paramiko": "paramiko",
}

paramiko = None

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"
DEFAULT_SSH_PORT = 22
DEFAULT_TIMEOUT_SECONDS = 20
MAX_TIMER_SECONDS = 24 * 60 * 60

LOG_INFO = "info"
LOG_WARN = "warning"
LOG_ERROR = "error"


class DebugFlowError(Exception):
    pass


class ValidationError(DebugFlowError):
    pass


def missing_requirements() -> list[str]:
    missing = []
    for import_name, package_name in REQUIRED_PACKAGES.items():
        if importlib.util.find_spec(import_name) is None:
            missing.append(package_name)
    return missing


def load_optional_modules() -> None:
    global paramiko
    try:
        import paramiko as _paramiko
        paramiko = _paramiko
    except Exception:
        paramiko = None


def install_requirements(logger: Callable[[str, str], None] | None = None) -> bool:
    missing = missing_requirements()
    if not missing:
        load_optional_modules()
        if logger:
            logger(LOG_INFO, "All required Python packages are already installed.")
        return True

    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", *missing]
    if logger:
        logger(LOG_INFO, "Installing missing Python package(s): " + ", ".join(missing))
        logger(LOG_INFO, "Running: " + " ".join(cmd))

    try:
        process = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        if logger:
            logger(LOG_ERROR, f"Failed to run pip: {exc}")
        return False

    if logger:
        if process.stdout.strip():
            logger(LOG_INFO, process.stdout.strip())
        if process.stderr.strip():
            logger(LOG_WARN if process.returncode == 0 else LOG_ERROR, process.stderr.strip())

    load_optional_modules()
    remaining = missing_requirements()
    if remaining:
        if logger:
            logger(LOG_ERROR, "Still missing Python package(s): " + ", ".join(remaining))
        return False
    return True


load_optional_modules()


@dataclass
class DebugFlowSshArgs:
    hosts: list[str]
    username: str
    password: str
    ssh_port: int = DEFAULT_SSH_PORT
    num_packets: int = 100
    timer_seconds: int = 0
    file_label: str = "run"
    output_dir: Path = DEFAULT_OUTPUT_DIR
    addr_from: str | None = None
    addr_to: str | None = None
    daddr_from: str | None = None
    daddr_to: str | None = None
    saddr_from: str | None = None
    saddr_to: str | None = None
    port_from: int | None = None
    port_to: int | None = None
    dport_from: int | None = None
    dport_to: int | None = None
    sport_from: int | None = None
    sport_to: int | None = None
    proto: int | None = None
    show_function_name: bool = True
    show_iprope: bool = True
    console_timestamp: bool = True
    timeout: int = DEFAULT_TIMEOUT_SECONDS


def timestamp_token() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def sanitize_component(value: str | None, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip())
    cleaned = cleaned.strip("-_.")
    return cleaned or fallback


def parse_host_list(raw_hosts: str) -> list[str]:
    hosts = []
    seen = set()
    for item in str(raw_hosts or "").split(","):
        value = item.strip()
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        hosts.append(value)
    return hosts


def validate_int_range(name: str, raw_value: str | int | None, default: int, minimum: int, maximum: int) -> int:
    if raw_value is None or str(raw_value).strip() == "":
        return default
    try:
        value = int(str(raw_value).strip())
    except Exception as exc:
        raise ValidationError(f"Invalid integer value for {name}: {raw_value}") from exc
    if value < minimum or value > maximum:
        raise ValidationError(f"{name} out of range {minimum}-{maximum}: {value}")
    return value


def validate_ip(name: str, raw_value: str | None) -> str | None:
    if raw_value is None or str(raw_value).strip() == "":
        return None
    value = str(raw_value).strip()
    try:
        ip_address(value)
    except Exception as exc:
        raise ValidationError(f"Invalid IP value for {name}: {value}") from exc
    return value


def validate_port(name: str, raw_value: str | None) -> int | None:
    if raw_value is None or str(raw_value).strip() == "":
        return None
    return validate_int_range(name, raw_value, 0, 1, 65535)


def validate_proto(raw_value: str | None) -> int | None:
    if raw_value is None or str(raw_value).strip() == "":
        return None
    return validate_int_range("Protocol Number", raw_value, 0, 0, 255)


def build_filter_commands(args: DebugFlowSshArgs) -> list[str]:
    commands = [
        "diagnose debug reset",
        "diagnose debug disable",
        "diagnose debug flow trace stop",
        "diagnose debug flow filter clear",
    ]
    for cli_name, start_value, end_value in [
        ("addr", args.addr_from, args.addr_to),
        ("daddr", args.daddr_from, args.daddr_to),
        ("saddr", args.saddr_from, args.saddr_to),
        ("port", args.port_from, args.port_to),
        ("dport", args.dport_from, args.dport_to),
        ("sport", args.sport_from, args.sport_to),
    ]:
        if start_value is None and end_value is None:
            continue
        if start_value is not None and end_value is not None:
            commands.append(f"diagnose debug flow filter {cli_name} {start_value} {end_value}")
        else:
            value = start_value if start_value is not None else end_value
            commands.append(f"diagnose debug flow filter {cli_name} {value}")
    if args.proto is not None:
        commands.append(f"diagnose debug flow filter proto {args.proto}")
    commands.append("diagnose debug flow show function-name enable" if args.show_function_name else "diagnose debug flow show function-name disable")
    commands.append("diagnose debug flow show iprope enable" if args.show_iprope else "diagnose debug flow show iprope disable")
    if args.console_timestamp:
        commands.append("diagnose debug console timestamp enable")
    commands.append(f"diagnose debug flow trace start {args.num_packets}")
    commands.append("diagnose debug enable")
    return commands


def active_filters(args: DebugFlowSshArgs) -> list[str]:
    values = []
    for name in ["addr", "daddr", "saddr", "port", "dport", "sport"]:
        start_value = getattr(args, f"{name}_from")
        end_value = getattr(args, f"{name}_to")
        if start_value is None and end_value is None:
            continue
        if start_value is not None and end_value is not None:
            values.append(f"{name}={start_value}-{end_value}")
        else:
            values.append(f"{name}={start_value if start_value is not None else end_value}")
    if args.proto is not None:
        values.append(f"proto={args.proto}")
    return values


class SshDebugSession:
    def __init__(self, host: str, args: DebugFlowSshArgs, logger: Callable[[str, str], None]) -> None:
        if paramiko is None:
            raise DebugFlowError("Missing dependency: paramiko. Use the Check/Install Requirements button.")
        self.host = host
        self.args = args
        self.logger = logger
        self.client = None
        self.channel = None
        self.stop_requested = threading.Event()
        self.completed = threading.Event()
        self.output_chunks = []
        self.error_text = ""
        self.result_file: Path | None = None
        self.started_at = 0.0
        self.ended_at = 0.0

    def log(self, level: str, message: str) -> None:
        self.logger(level, f"[{self.host}] {message}")

    def send_line(self, command: str) -> None:
        if not self.channel:
            return
        self.output_chunks.append(f"\n>>> {command}\n")
        self.channel.send(command + "\n")

    def send_ctrl_c(self) -> None:
        if self.channel:
            self.log(LOG_INFO, "Sending Ctrl+C to SSH session.")
            try:
                self.channel.send("\x03")
            except Exception as exc:
                self.log(LOG_WARN, f"Failed to send Ctrl+C: {exc}")
        self.stop_requested.set()

    def cleanup_remote_debug(self) -> None:
        for command in [
            "diagnose debug disable",
            "diagnose debug flow trace stop",
            "diagnose debug flow filter clear",
            "diagnose debug reset",
        ]:
            try:
                self.send_line(command)
                time.sleep(0.15)
            except Exception:
                pass

    def connect(self) -> None:
        self.log(LOG_INFO, f"Connecting to SSH port {self.args.ssh_port}.")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.args.ssh_port,
            username=self.args.username,
            password=self.args.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=self.args.timeout,
            banner_timeout=self.args.timeout,
            auth_timeout=self.args.timeout,
        )
        self.client = client
        self.channel = client.invoke_shell(width=240, height=1000)
        self.channel.settimeout(0.0)
        time.sleep(0.5)
        self.drain_channel()
        self.log(LOG_INFO, "SSH session established.")

    def drain_channel(self) -> None:
        if not self.channel:
            return
        while True:
            try:
                if not self.channel.recv_ready():
                    break
                data = self.channel.recv(65535).decode("utf-8", errors="replace")
                if not data:
                    break
                self.output_chunks.append(data)
                for line in data.splitlines():
                    if line.strip():
                        self.logger(LOG_INFO, f"[{self.host}] {line}")
            except socket.timeout:
                break
            except Exception:
                break

    def write_file(self) -> Path:
        self.args.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.args.output_dir / f"{sanitize_component(self.host, 'fortigate')}_ssh_debug_flow_{sanitize_component(self.args.file_label, 'run')}_{timestamp_token()}.txt"
        elapsed = self.ended_at - self.started_at if self.ended_at and self.started_at else 0.0
        lines = [
            "=== FortiGate SSH Debug Flow Result ===",
            f"Host: {self.host}",
            f"SSH Port: {self.args.ssh_port}",
            f"Elapsed Seconds: {elapsed:.2f}",
            f"Trace Count Requested: {self.args.num_packets}",
            f"Timer Seconds: {self.args.timer_seconds}",
            f"Active Filters: {'; '.join(active_filters(self.args)) if active_filters(self.args) else 'none'}",
            f"Stop Requested: {self.stop_requested.is_set()}",
            "",
            "=== Commands Sent ===",
            *build_filter_commands(self.args),
            "",
            "=== SSH Session Output ===",
            "".join(self.output_chunks),
        ]
        if self.error_text:
            lines.extend(["", "=== Error ===", self.error_text])
        path.write_text("\n".join(lines), encoding="utf-8")
        self.result_file = path
        self.log(LOG_INFO, f"Result file created: {path}")
        return path

    def run(self) -> None:
        self.started_at = time.monotonic()
        try:
            self.connect()
            for command in build_filter_commands(self.args):
                if self.stop_requested.is_set():
                    break
                self.send_line(command)
                time.sleep(0.2)
                self.drain_channel()
            timer_deadline = None
            if self.args.timer_seconds > 0:
                timer_deadline = time.monotonic() + self.args.timer_seconds
                self.log(LOG_INFO, f"Timer enabled for {self.args.timer_seconds} seconds.")
            while not self.stop_requested.is_set():
                self.drain_channel()
                if self.channel and self.channel.exit_status_ready():
                    self.log(LOG_INFO, "SSH channel reported exit status ready.")
                    break
                if timer_deadline is not None and time.monotonic() >= timer_deadline:
                    self.log(LOG_INFO, "Timer expired. Stopping debug session.")
                    self.send_ctrl_c()
                    break
                time.sleep(0.25)
            self.drain_channel()
            self.cleanup_remote_debug()
            time.sleep(0.5)
            self.drain_channel()
        except Exception as exc:
            self.error_text = str(exc)
            self.log(LOG_ERROR, str(exc))
        finally:
            self.ended_at = time.monotonic()
            try:
                self.write_file()
            except Exception as exc:
                self.log(LOG_ERROR, f"Failed to write result file: {exc}")
            try:
                if self.channel:
                    self.channel.close()
            except Exception:
                pass
            try:
                if self.client:
                    self.client.close()
            except Exception:
                pass
            self.completed.set()
            self.log(LOG_INFO, "SSH debug session complete.")


class DebugFlowSshGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Debug Flow SSH Standalone")
        self.vars = {}
        self.sessions = []
        self.threads = []
        self.manager_thread = None
        self.install_thread = None
        self.log_queue = queue.Queue()
        self.start_button = None
        self.stop_button = None
        self.req_button = None
        self.build_ui()
        self.drain_log_queue()
        self.root.after(250, self.check_requirements_startup)

    def str_var(self, name: str, value: str = "") -> tk.StringVar:
        var = tk.StringVar(value=value)
        self.vars[name] = var
        return var

    def bool_var(self, name: str, value: bool = False) -> tk.BooleanVar:
        var = tk.BooleanVar(value=value)
        self.vars[name] = var
        return var

    def add_labeled_entry(self, parent, row, label, name, value="", show=None, col=0, width=60):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=4, pady=2)
        entry = ttk.Entry(parent, textvariable=self.str_var(name, value), show=show, width=width)
        entry.grid(row=row, column=col + 1, sticky="ew", padx=4, pady=2)
        return entry

    def build_ui(self) -> None:
        self.canvas = tk.Canvas(self.root, borderwidth=0, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.content_frame = ttk.Frame(self.canvas, padding=10)
        self.content_window = self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw")
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.rowconfigure(5, weight=1)

        def _on_canvas_configure(event):
            self.canvas.itemconfig(self.content_window, width=event.width)
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.bind("<Configure>", _on_canvas_configure)
        self.content_frame.bind("<Configure>", lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        req = ttk.LabelFrame(self.content_frame, text="Python Requirements")
        req.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        req.columnconfigure(0, weight=1)
        self.req_status = ttk.Label(req, text="Checking requirements...")
        self.req_status.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        self.req_button = ttk.Button(req, text="Check / Install Requirements", command=self.install_requirements_clicked)
        self.req_button.grid(row=0, column=1, sticky="e", padx=4, pady=2)

        conn = ttk.LabelFrame(self.content_frame, text="SSH Connection")
        conn.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        conn.columnconfigure(1, weight=1)
        self.add_labeled_entry(conn, 0, "Hostnames or IPs (Seperated by commas)", "hosts")
        self.add_labeled_entry(conn, 1, "SSH Username", "username")
        self.add_labeled_entry(conn, 2, "SSH Password", "password", show="*")
        self.add_labeled_entry(conn, 3, "SSH Port", "ssh_port", str(DEFAULT_SSH_PORT), width=12)
        self.add_labeled_entry(conn, 4, "Output Directory", "output_dir", str(DEFAULT_OUTPUT_DIR))
        ttk.Button(conn, text="Browse", command=self.browse_output_dir).grid(row=4, column=2, sticky="w", padx=4, pady=2)

        opts = ttk.LabelFrame(self.content_frame, text="Debug Flow Options")
        opts.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        for col in range(4):
            opts.columnconfigure(col, weight=1)
        self.add_labeled_entry(opts, 0, "Trace Count", "num_packets", "100", col=0, width=20)
        self.add_labeled_entry(opts, 0, "Timer Seconds", "timer_seconds", "0", col=2, width=20)
        self.add_labeled_entry(opts, 1, "Add label to filename", "file_label", "run", col=0, width=30)
        ttk.Checkbutton(opts, text="Show function-name", variable=self.bool_var("show_function_name", True)).grid(row=1, column=2, sticky="w", padx=4, pady=2)
        ttk.Checkbutton(opts, text="Show iprope", variable=self.bool_var("show_iprope", True)).grid(row=1, column=3, sticky="w", padx=4, pady=2)
        ttk.Checkbutton(opts, text="Console timestamp", variable=self.bool_var("console_timestamp", True)).grid(row=2, column=2, sticky="w", padx=4, pady=2)

        filters = ttk.LabelFrame(self.content_frame, text="Filters")
        filters.grid(row=3, column=0, sticky="ew", padx=4, pady=4)
        filters.columnconfigure(0, weight=1)
        filters.rowconfigure(0, weight=1)
        filters_canvas = tk.Canvas(filters, height=260, borderwidth=0, highlightthickness=0)
        filters_canvas.grid(row=0, column=0, sticky="nsew")
        filters_scrollbar = ttk.Scrollbar(filters, orient="vertical", command=filters_canvas.yview)
        filters_scrollbar.grid(row=0, column=1, sticky="ns")
        filters_canvas.configure(yscrollcommand=filters_scrollbar.set)

        filter_fields = ttk.Frame(filters_canvas)
        filter_window = filters_canvas.create_window((0, 0), window=filter_fields, anchor="nw")

        def _on_filter_canvas_configure(event):
            filters_canvas.itemconfig(filter_window, width=max(event.width, 1))
            filters_canvas.configure(scrollregion=filters_canvas.bbox("all"))
        filters_canvas.bind("<Configure>", _on_filter_canvas_configure)
        filter_fields.bind("<Configure>", lambda event: filters_canvas.configure(scrollregion=filters_canvas.bbox("all")))

        for row, (label, start_name, end_name) in enumerate([
            ("Addr", "addr_from", "addr_to"),
            ("Src Addr", "saddr_from", "saddr_to"),
            ("Dst Addr", "daddr_from", "daddr_to"),
            ("Port", "port_from", "port_to"),
            ("Src Port", "sport_from", "sport_to"),
            ("Dst Port", "dport_from", "dport_to"),
        ]):
            ttk.Label(filter_fields, text=label).grid(row=row, column=0, sticky="w", padx=4, pady=2)
            ttk.Entry(filter_fields, textvariable=self.str_var(start_name), width=18).grid(row=row, column=1, sticky="ew", padx=4, pady=2)
            ttk.Label(filter_fields, text="to").grid(row=row, column=2, sticky="w", padx=4, pady=2)
            ttk.Entry(filter_fields, textvariable=self.str_var(end_name), width=18).grid(row=row, column=3, sticky="ew", padx=4, pady=2)
        proto_row = 6
        ttk.Label(filter_fields, text="Protocol Number 1=ICMP, 6=TCP, 17=UDP").grid(row=proto_row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(filter_fields, textvariable=self.str_var("proto"), width=18).grid(row=proto_row, column=1, sticky="ew", padx=4, pady=2)

        actions = ttk.Frame(self.content_frame)
        actions.grid(row=4, column=0, sticky="ew", padx=4, pady=4)
        self.start_button = ttk.Button(actions, text="Start", command=self.start)
        self.start_button.grid(row=0, column=0, padx=4, pady=4)
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=4, pady=4)
        ttk.Button(actions, text="Clear Log", command=self.clear_log).grid(row=0, column=2, padx=4, pady=4)

        log_frame = ttk.LabelFrame(self.content_frame, text="Live SSH Output / Log")
        log_frame.grid(row=5, column=0, sticky="nsew", padx=4, pady=4)
        self.content_frame.rowconfigure(5, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew")

    def check_requirements_startup(self):
        missing = missing_requirements()
        if missing:
            self.req_status.configure(text="Missing required package(s): " + ", ".join(missing))
            self.logger(LOG_WARN, "Missing required package(s): " + ", ".join(missing))
        else:
            load_optional_modules()
            self.req_status.configure(text="All Python requirements are installed.")
            self.logger(LOG_INFO, "All Python requirements are installed.")

    def install_requirements_clicked(self):
        if self.install_thread and self.install_thread.is_alive():
            return
        if self.req_button:
            self.req_button.configure(state="disabled")
        self.req_status.configure(text="Checking/installing requirements...")
        def worker():
            success = install_requirements(self.logger)
            def done():
                self.req_status.configure(text="All Python requirements are installed." if success else "Requirement installation failed. See log.")
                if self.req_button:
                    self.req_button.configure(state="normal")
            self.root.after(0, done)
        self.install_thread = threading.Thread(target=worker, daemon=True)
        self.install_thread.start()

    def browse_output_dir(self):
        selected = filedialog.askdirectory(initialdir=self.vars["output_dir"].get() or str(DEFAULT_OUTPUT_DIR))
        if selected:
            self.vars["output_dir"].set(selected)

    def clear_log(self):
        self.log_text.delete("1.0", "end")

    def logger(self, level, message):
        self.log_queue.put((level, message))

    def drain_log_queue(self):
        try:
            while True:
                level, message = self.log_queue.get_nowait()
                stamp = datetime.now().strftime("%H:%M:%S")
                self.log_text.insert("end", f"{stamp} ({level}) {message}\n")
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.root.after(100, self.drain_log_queue)

    def collect_args(self) -> DebugFlowSshArgs:
        hosts = parse_host_list(self.vars["hosts"].get())
        username = self.vars["username"].get().strip()
        password = self.vars["password"].get()
        if not hosts:
            raise ValidationError("At least one hostname or IP is required.")
        if not username:
            raise ValidationError("SSH Username is required.")
        if not password:
            raise ValidationError("SSH Password is required.")
        return DebugFlowSshArgs(
            hosts=hosts,
            username=username,
            password=password,
            ssh_port=validate_int_range("SSH Port", self.vars["ssh_port"].get(), DEFAULT_SSH_PORT, 1, 65535),
            num_packets=validate_int_range("Trace Count", self.vars["num_packets"].get(), 100, 1, 1000000),
            timer_seconds=validate_int_range("Timer Seconds", self.vars["timer_seconds"].get(), 0, 0, MAX_TIMER_SECONDS),
            file_label=self.vars["file_label"].get() or "run",
            output_dir=Path(self.vars["output_dir"].get() or str(DEFAULT_OUTPUT_DIR)),
            addr_from=validate_ip("addr_from", self.vars["addr_from"].get()),
            addr_to=validate_ip("addr_to", self.vars["addr_to"].get()),
            daddr_from=validate_ip("daddr_from", self.vars["daddr_from"].get()),
            daddr_to=validate_ip("daddr_to", self.vars["daddr_to"].get()),
            saddr_from=validate_ip("saddr_from", self.vars["saddr_from"].get()),
            saddr_to=validate_ip("saddr_to", self.vars["saddr_to"].get()),
            port_from=validate_port("port_from", self.vars["port_from"].get()),
            port_to=validate_port("port_to", self.vars["port_to"].get()),
            dport_from=validate_port("dport_from", self.vars["dport_from"].get()),
            dport_to=validate_port("dport_to", self.vars["dport_to"].get()),
            sport_from=validate_port("sport_from", self.vars["sport_from"].get()),
            sport_to=validate_port("sport_to", self.vars["sport_to"].get()),
            proto=validate_proto(self.vars["proto"].get()),
            show_function_name=bool(self.vars["show_function_name"].get()),
            show_iprope=bool(self.vars["show_iprope"].get()),
            console_timestamp=bool(self.vars["console_timestamp"].get()),
        )

    def set_running_state(self, running):
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

    def start(self):
        if missing_requirements():
            messagebox.showerror("Missing Requirements", "Missing required Python package(s). Use Check / Install Requirements first.")
            return
        load_optional_modules()
        if self.manager_thread and self.manager_thread.is_alive():
            messagebox.showwarning("Busy", "Debug sessions are already running.")
            return
        try:
            args = self.collect_args()
        except Exception as exc:
            messagebox.showerror("Input Error", str(exc))
            return
        self.sessions = [SshDebugSession(host, args, self.logger) for host in args.hosts]
        self.threads = []
        self.set_running_state(True)
        self.logger(LOG_INFO, f"Starting SSH debug flow on {len(self.sessions)} host(s).")
        def manager():
            try:
                for session in self.sessions:
                    thread = threading.Thread(target=session.run, daemon=True)
                    self.threads.append(thread)
                    thread.start()
                for thread in self.threads:
                    thread.join()
            finally:
                self.logger(LOG_INFO, "All SSH debug sessions are complete.")
                self.root.after(0, lambda: self.set_running_state(False))
        self.manager_thread = threading.Thread(target=manager, daemon=True)
        self.manager_thread.start()

    def stop(self):
        if not self.sessions:
            return
        self.logger(LOG_INFO, "Stop requested. Sending Ctrl+C to active SSH session(s).")
        for session in self.sessions:
            if not session.completed.is_set():
                session.send_ctrl_c()
        self.stop_button.configure(state="disabled")


def run_gui():
    if tk is None:
        raise RuntimeError("Tkinter is not available in this Python environment.")
    root = tk.Tk()
    root.geometry("1120x900")
    DebugFlowSshGui(root)
    root.mainloop()


def main() -> int:
    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
