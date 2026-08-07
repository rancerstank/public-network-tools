"""
diag_fgt_debug_flow_v2.py

Standalone FortiGate Debug Flow utility using SSH instead of the FortiOS REST API.
Supersedes diag_fgt_debug_flow_v1.py in this same folder.

Adds on top of v1:
- Reliable auto-stop on trace count: watches the live output for trace_id= and
  stops right after the requested number of distinct trace_id values finish
  printing, since FortiGate trace IDs do not start at 0 and each trace_id can
  span multiple output lines.
- Once any target host reaches its own trace count, every other still-running
  host in the same run is stopped too. Each session logs, and records in its
  output file, whether it stopped on its own trace count or because another
  host reached its count first.
- Hover help text on every GUI field, checkbox, and button.
- SSH host keys are trusted automatically on first connection and persisted to
  a local known_hosts file, so later runs verify against the saved key instead
  of trusting blindly every time.
- SSH Password or SSH Private Key authentication, selectable per run with a
  radio button that enables/disables the fields that do not apply.
- Per-filter "Not" checkboxes on every range filter that send FortiOS's
  'diagnose debug flow filter negate <field>' to invert that filter.

Carried over from v1:
- Python requirements check.
- GUI button to check/install missing Python packages.
- Start button automatically blocks with a clear message if requirements are missing.

Dependency:
- paramiko

Install manually if preferred:
    py -m pip install --upgrade paramiko
"""

from __future__ import annotations

# This script is a standalone FortiGate troubleshooting tool. The design is split
# into three layers so the GUI never has to think about low-level SSH details:
# 1. Validation and command-building helpers near the top of the file.
# 2. The SshDebugSession class, which manages one SSH session per target host.
# 3. The Tkinter-based DebugFlowSshGui, which collects user input and launches
# the worker threads that run the SSH sessions.

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
KNOWN_HOSTS_PATH = SCRIPT_DIR / "known_hosts"
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
    auth_method: str = "password"
    password: str | None = None
    key_path: str | None = None
    key_passphrase: str | None = None
    ssh_port: int = DEFAULT_SSH_PORT
    num_packets: int = 100
    timer_seconds: int = 0
    file_label: str = "run"
    output_dir: Path = DEFAULT_OUTPUT_DIR
    addr_from: str | None = None
    addr_to: str | None = None
    addr_negate: bool = False
    daddr_from: str | None = None
    daddr_to: str | None = None
    daddr_negate: bool = False
    saddr_from: str | None = None
    saddr_to: str | None = None
    saddr_negate: bool = False
    port_from: int | None = None
    port_to: int | None = None
    port_negate: bool = False
    dport_from: int | None = None
    dport_to: int | None = None
    dport_negate: bool = False
    sport_from: int | None = None
    sport_to: int | None = None
    sport_negate: bool = False
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
    for cli_name, start_value, end_value, negate in [
        ("addr", args.addr_from, args.addr_to, args.addr_negate),
        ("daddr", args.daddr_from, args.daddr_to, args.daddr_negate),
        ("saddr", args.saddr_from, args.saddr_to, args.saddr_negate),
        ("port", args.port_from, args.port_to, args.port_negate),
        ("dport", args.dport_from, args.dport_to, args.dport_negate),
        ("sport", args.sport_from, args.sport_to, args.sport_negate),
    ]:
        if start_value is None and end_value is None:
            continue
        if start_value is not None and end_value is not None:
            commands.append(f"diagnose debug flow filter {cli_name} {start_value} {end_value}")
        else:
            value = start_value if start_value is not None else end_value
            commands.append(f"diagnose debug flow filter {cli_name} {value}")
        if negate:
            commands.append(f"diagnose debug flow filter negate {cli_name}")
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
        prefix = "NOT " if getattr(args, f"{name}_negate") else ""
        if start_value is not None and end_value is not None:
            values.append(f"{prefix}{name}={start_value}-{end_value}")
        else:
            values.append(f"{prefix}{name}={start_value if start_value is not None else end_value}")
    if args.proto is not None:
        values.append(f"proto={args.proto}")
    return values


TRACE_ID_PATTERN = re.compile(r"trace_id=(\d+)")


def extract_trace_id(line: str) -> int | None:
    match = TRACE_ID_PATTERN.search(line)
    if match is None:
        return None
    return int(match.group(1))


_known_hosts_lock = threading.Lock()


def persist_host_key(hostname: str, key: paramiko.PKey) -> None:
    """Merge a newly-trusted host key into the shared known_hosts file.

    Multiple SshDebugSession threads can each accept a first-seen key at the
    same time (one thread per target host). Paramiko's own save_host_keys()
    only writes that one client's in-memory copy of the file, so two
    concurrent saves would clobber each other's new entries. Re-reading the
    file under a lock immediately before writing avoids that.
    """
    with _known_hosts_lock:
        merged = paramiko.HostKeys()
        if KNOWN_HOSTS_PATH.exists():
            try:
                merged.load(str(KNOWN_HOSTS_PATH))
            except Exception:
                pass
        merged.add(hostname, key.get_name(), key)
        KNOWN_HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        merged.save(str(KNOWN_HOSTS_PATH))


class TrustOnFirstUsePolicy:
    """Paramiko missing-host-key policy: silently trust and persist a host
    key the first time it is seen for a given host, so repeat runs need no
    prompt and no manual known_hosts setup.

    This is only consulted for a host with no existing known_hosts entry. If
    a host already has an entry and the key presented no longer matches it,
    paramiko raises BadHostKeyException itself before this policy is ever
    consulted, which is what protects against a host key changing later
    (re-image, or a man-in-the-middle) instead of it being silently
    re-trusted.
    """

    def __init__(self, logger: Callable[[str, str], None]) -> None:
        self.logger = logger

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)
        persist_host_key(hostname, key)
        self.logger(
            LOG_WARN,
            f"New SSH host key for {hostname} trusted on first connection and "
            f"saved to {KNOWN_HOSTS_PATH.name}: {key.get_name()} {key.get_fingerprint().hex()}",
        )


class RunCoordinator:
    """Shared state across every SshDebugSession started from one Start click.

    Used so that as soon as any single target host reaches its own requested
    trace count, every other host that is still running gets told to stop too
    instead of continuing to collect on its own.
    """

    def __init__(self) -> None:
        self.trace_stop_event = threading.Event()
        self.trace_stop_host: str | None = None
        self._lock = threading.Lock()

    def claim_trace_stop(self, host: str) -> bool:
        """Record which host first reached its trace count. Returns True only
        for the first caller, so only that host is recorded as the cause."""
        with self._lock:
            if self.trace_stop_event.is_set():
                return False
            self.trace_stop_host = host
            self.trace_stop_event.set()
            return True


# The worker session object represents one SSH connection to a single FortiGate.
# It owns the Paramiko client/channel, sends the debug-flow commands, captures
# the live output stream, and writes a final text report after the session ends.
class SshDebugSession:
    def __init__(
        self,
        host: str,
        args: DebugFlowSshArgs,
        logger: Callable[[str, str], None],
        coordinator: RunCoordinator,
    ) -> None:
        if paramiko is None:
            raise DebugFlowError("Missing dependency: paramiko. Use the Check/Install Requirements button.")
        self.host = host
        self.args = args
        self.logger = logger
        self.coordinator = coordinator
        self.client = None
        self.channel = None
        self.stop_requested = threading.Event()
        self.completed = threading.Event()
        self.output_chunks = []
        self.error_text = ""
        self.result_file: Path | None = None
        self.started_at = 0.0
        self.ended_at = 0.0
        self.start_trace_id: int | None = None
        self.target_trace_id: int | None = None
        self.trace_count_reached = False
        self.stop_reason = "n/a"

    def log(self, level: str, message: str) -> None:
        self.logger(level, f"[{self.host}] {message}")

    def send_line(self, command: str) -> None:
        if not self.channel:
            return
        self.output_chunks.append(f"\n>>> {command}\n")
        self.channel.send(command + "\n")

    def send_ctrl_c(self, reason: str = "Manual stop (Stop button clicked).") -> None:
        if self.stop_reason == "n/a":
            self.stop_reason = reason
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
        with _known_hosts_lock:
            if KNOWN_HOSTS_PATH.exists():
                try:
                    client.load_host_keys(str(KNOWN_HOSTS_PATH))
                except Exception as exc:
                    self.log(LOG_WARN, f"Could not read {KNOWN_HOSTS_PATH.name}: {exc}")
        client.set_missing_host_key_policy(TrustOnFirstUsePolicy(self.log))
        connect_kwargs = dict(
            hostname=self.host,
            port=self.args.ssh_port,
            username=self.args.username,
            look_for_keys=False,
            allow_agent=False,
            timeout=self.args.timeout,
            banner_timeout=self.args.timeout,
            auth_timeout=self.args.timeout,
        )
        if self.args.auth_method == "key":
            connect_kwargs["key_filename"] = self.args.key_path
            if self.args.key_passphrase:
                connect_kwargs["passphrase"] = self.args.key_passphrase
            self.log(LOG_INFO, f"Authenticating with private key: {self.args.key_path}")
        else:
            connect_kwargs["password"] = self.args.password
        try:
            client.connect(**connect_kwargs)
        except paramiko.PasswordRequiredException as exc:
            raise DebugFlowError(
                f"Private key {self.args.key_path} is encrypted and requires a passphrase. "
                "Enter it in the Key Passphrase field."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise DebugFlowError(
                f"SSH host key for {self.host} does not match the key saved in "
                f"{KNOWN_HOSTS_PATH}. Either the device was reimaged/re-keyed, or "
                "this could be a man-in-the-middle attack. Remove the stale entry "
                "for this host from that file only once you have confirmed the "
                "change is expected, then run again."
            ) from exc
        self.client = client
        self.channel = client.invoke_shell(width=240, height=1000)
        self.channel.settimeout(0.0)
        time.sleep(0.5)
        self.drain_channel()
        self.log(LOG_INFO, "SSH session established.")

    def note_trace_line(self, line: str) -> None:
        # stop_requested also guards this: once any stop path has fired (own
        # trace count, another host's trace count, timer, or manual Stop),
        # trailing buffered lines drained during cleanup must not retroactively
        # flip trace_count_reached or overwrite an already-decided stop reason.
        if self.trace_count_reached or self.stop_requested.is_set() or self.args.num_packets <= 0:
            return
        trace_id = extract_trace_id(line)
        if trace_id is None:
            return
        if self.start_trace_id is None:
            self.start_trace_id = trace_id
            self.target_trace_id = trace_id + self.args.num_packets - 1
            self.log(
                LOG_INFO,
                f"First trace_id observed: {trace_id}. Session will stop once "
                f"trace_id {self.target_trace_id} finishes ({self.args.num_packets} trace(s) requested).",
            )
            return
        if trace_id > self.target_trace_id:
            self.trace_count_reached = True
            self.coordinator.claim_trace_stop(self.host)

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
                        self.note_trace_line(line)
            except socket.timeout:
                break
            except Exception:
                break

    def write_file(self) -> Path:
        self.args.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.args.output_dir / f"{sanitize_component(self.host, 'fortigate')}_ssh_debug_flow_{sanitize_component(self.args.file_label, 'run')}_{timestamp_token()}.txt"
        elapsed = self.ended_at - self.started_at if self.ended_at and self.started_at else 0.0
        trace_id_range = (
            f"{self.start_trace_id}-{self.target_trace_id}" if self.start_trace_id is not None else "n/a"
        )
        lines = [
            "=== FortiGate SSH Debug Flow Result ===",
            f"Host: {self.host}",
            f"SSH Port: {self.args.ssh_port}",
            f"Auth Method: {self.args.auth_method}" + (f" ({self.args.key_path})" if self.args.key_path else ""),
            f"Elapsed Seconds: {elapsed:.2f}",
            f"Trace Count Requested: {self.args.num_packets}",
            f"Trace Count Reached: {self.trace_count_reached}",
            f"Trace ID Range Captured: {trace_id_range}",
            f"Timer Seconds: {self.args.timer_seconds}",
            f"Active Filters: {'; '.join(active_filters(self.args)) if active_filters(self.args) else 'none'}",
            f"Stop Requested: {self.stop_requested.is_set()}",
            f"Stop Reason: {self.stop_reason}",
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
                if self.trace_count_reached:
                    reason = (
                        f"Stopped by trace count (trace_id {self.start_trace_id}-{self.target_trace_id}, "
                        f"{self.args.num_packets} trace(s) requested)."
                    )
                    self.log(LOG_INFO, reason)
                    self.send_ctrl_c(reason)
                    break
                if self.coordinator.trace_stop_event.is_set():
                    reason = f"Stopped by {self.coordinator.trace_stop_host} (that host reached its trace count first)."
                    self.log(LOG_INFO, reason)
                    self.send_ctrl_c(reason)
                    break
                if self.channel and self.channel.exit_status_ready():
                    self.stop_reason = "SSH channel exit status ready."
                    self.log(LOG_INFO, "SSH channel reported exit status ready.")
                    break
                if timer_deadline is not None and time.monotonic() >= timer_deadline:
                    reason = "Stopped by timer expiration."
                    self.log(LOG_INFO, reason)
                    self.send_ctrl_c(reason)
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


class ToolTip:
    """Small hover popup used to show help text for a GUI control.

    Tkinter/ttk has no built-in tooltip widget, so this binds a delayed
    Toplevel popup to <Enter>/<Leave> on the given widget.
    """

    def __init__(self, widget, text: str, delay_ms: int = 500, wraplength: int = 360) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self.wraplength = wraplength
        self.tip_window = None
        self.after_id = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self.after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        if self.after_id is not None:
            self.widget.after_cancel(self.after_id)
            self.after_id = None

    def _show(self) -> None:
        if self.tip_window is not None or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        try:
            tw.wm_attributes("-topmost", True)
        except Exception:
            pass
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(
            tw,
            text=self.text,
            justify="left",
            background="#ffffe0",
            foreground="#000000",
            relief="solid",
            borderwidth=1,
            wraplength=self.wraplength,
            padx=6,
            pady=4,
            font=("Segoe UI", 9),
        ).pack()

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self.tip_window is not None:
            self.tip_window.destroy()
            self.tip_window = None


# Hover help text for GUI controls, keyed by the same field "name" used in
# self.vars / str_var / bool_var where the control has one, or a *_button key
# otherwise. Edit these strings directly to change what a control's tooltip says.
FIELD_HELP = {
    "hosts": (
        "One or more FortiGate hostnames or IP addresses to connect to, separated by commas "
        "(e.g. 10.0.0.1, 10.0.0.2, fw-branch2.example.com). Each host gets its own independent "
        "SSH session, running at the same time as the others, and its own output file. Duplicate "
        "entries (case-insensitive) are ignored automatically."
    ),
    "username": (
        "SSH login username used to authenticate to every target FortiGate listed above. The same "
        "username is used for all hosts, so the account needs enough admin privilege on each device "
        "to run 'diagnose debug' commands."
    ),
    "auth_method": (
        "Chooses how the SSH session authenticates to every target host. 'Password' uses the SSH "
        "Password field below. 'Private Key' uses the Private Key File (and Key Passphrase, if the "
        "key is encrypted) instead. Switching this disables whichever fields do not apply."
    ),
    "password": (
        "SSH login password for the username above, used when Authentication Method is set to "
        "'Password'. The same password is used for every target host, so all devices must share this "
        "login. The field is masked on screen and is never written to disk; it only lives in memory "
        "for the duration of the run."
    ),
    "key_path": (
        "Path to a private key file (for example id_rsa or id_ed25519) used to authenticate when "
        "Authentication Method is set to 'Private Key'. The same key and username are used for every "
        "target host. Disabled and unused in 'Password' mode."
    ),
    "key_browse_button": "Open a file picker to choose the Private Key File instead of typing a path.",
    "key_passphrase": (
        "Passphrase that decrypts the Private Key File, if it is encrypted. Leave blank if the key "
        "has no passphrase. Disabled and unused in 'Password' mode."
    ),
    "ssh_port": (
        "TCP port used for the SSH connection to each FortiGate (default 22). Change this only if SSH "
        "access has been moved to a non-standard port on the target devices."
    ),
    "output_dir": (
        "Folder where the result .txt files are saved. One file is written per host per run, named "
        "'<host>_ssh_debug_flow_<label>_<timestamp>.txt'. The folder is created automatically if it "
        "does not already exist."
    ),
    "browse_button": "Open a folder picker to choose the Output Directory instead of typing a path.",
    "num_packets": (
        "How many distinct flow traces to capture on each firewall, equivalent to the FortiOS command "
        "'diagnose debug flow trace start <N>'. FortiOS labels each traced flow with a trace_id, and a "
        "single trace_id can print several output lines, so this counts distinct trace_id values, not "
        "output lines. The session watches the live output, remembers the first trace_id it sees "
        "(FortiGate trace IDs do not start at 0), and automatically stops right after the Nth trace_id "
        "finishes printing. As soon as any one target host reaches its own trace count, every other "
        "still-running host in this run is stopped too, so all the output files line up around the "
        "same event instead of running independently."
    ),
    "timer_seconds": (
        "Optional safety-net time limit, in seconds, after which the session is force-stopped even if "
        "the Trace Count above has not been reached yet (for example, if the filters never match any "
        "traffic). Set to 0 to disable the timer and rely only on Trace Count or the Stop button."
    ),
    "file_label": (
        "Free-text label inserted into the output filename for this run (for example a ticket number "
        "or short description), so results from different runs are easy to tell apart. Characters "
        "that are not valid in filenames are automatically replaced with '-'."
    ),
    "show_function_name": (
        "Toggles 'diagnose debug flow show function-name enable/disable'. When enabled, each debug "
        "line includes the internal FortiOS function name that produced it, which helps when reading "
        "the trace in detail but adds extra text to every line."
    ),
    "show_iprope": (
        "Toggles 'diagnose debug flow show iprope enable/disable'. When enabled, policy lookup "
        "(iprope) details are included in the debug output, showing how the firewall matched the "
        "traffic against policies."
    ),
    "console_timestamp": (
        "Toggles 'diagnose debug console timestamp enable'. When enabled, the FortiGate prefixes each "
        "debug line with its own console timestamp, which makes it easier to correlate timing across "
        "multiple devices."
    ),
    "addr": (
        "Matches traffic where either the source or the destination address is in this range (FortiOS "
        "'diagnose debug flow filter addr'). Fill in only 'from' for a single exact address, or both "
        "'from' and 'to' for an address range. Leave both blank to skip this filter."
    ),
    "saddr": (
        "Matches traffic only by source address (FortiOS 'diagnose debug flow filter saddr'). Fill in "
        "only 'from' for a single exact address, or both 'from' and 'to' for a range. Leave both blank "
        "to skip this filter."
    ),
    "daddr": (
        "Matches traffic only by destination address (FortiOS 'diagnose debug flow filter daddr'). "
        "Fill in only 'from' for a single exact address, or both 'from' and 'to' for a range. Leave "
        "both blank to skip this filter."
    ),
    "port": (
        "Matches traffic where either the source or the destination port is in this range (FortiOS "
        "'diagnose debug flow filter port'). Fill in only 'from' for a single exact port, or both "
        "'from' and 'to' for a range. Leave both blank to skip this filter."
    ),
    "sport": (
        "Matches traffic only by source port (FortiOS 'diagnose debug flow filter sport'). Fill in "
        "only 'from' for a single exact port, or both 'from' and 'to' for a range. Leave both blank to "
        "skip this filter."
    ),
    "dport": (
        "Matches traffic only by destination port (FortiOS 'diagnose debug flow filter dport'). Fill "
        "in only 'from' for a single exact port, or both 'from' and 'to' for a range. Leave both blank "
        "to skip this filter."
    ),
    "proto": (
        "IP protocol number to filter on (FortiOS 'diagnose debug flow filter proto'). Common values: "
        "1 = ICMP, 6 = TCP, 17 = UDP. Leave blank to match all protocols."
    ),
    "negate": (
        "Inverts this filter so it matches traffic that does NOT match the value(s) to the left "
        "(FortiOS 'diagnose debug flow filter negate <field>'). Only has an effect if that filter has "
        "a value set; checking it with a blank filter does nothing."
    ),
    "start_button": (
        "Validates the fields above and starts one SSH debug session per host at the same time. Each "
        "session applies the filters, starts the flow trace, and streams live output into the log "
        "below until its Trace Count is reached, its Timer expires, or Stop is clicked. Disabled while "
        "a run is already in progress."
    ),
    "stop_button": (
        "Sends Ctrl+C to every SSH session that is still running, which interrupts the live FortiOS "
        "debug output immediately. Each session still runs its normal cleanup commands and writes its "
        "output file before finishing. Only enabled while sessions are active."
    ),
    "clear_log_button": (
        "Clears the live log pane below. This only affects what is shown on screen; it does not "
        "change or delete any saved output files."
    ),
    "req_button": (
        "Checks whether the required Python packages (currently just 'paramiko') are installed, and "
        "installs anything missing with 'pip install --upgrade'. The Start button is blocked until all "
        "requirements are satisfied."
    ),
}


# The GUI layer is intentionally thin. It collects user input, validates it,
# converts it into a DebugFlowSshArgs structure, and then launches one worker
# thread per host so the Tk event loop remains responsive while SSH work runs.
class DebugFlowSshGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Debug Flow SSH Standalone (v2)")
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

    def add_labeled_entry(self, parent, row, label, name, value="", show=None, col=0, width=60, tooltip=None):
        label_widget = ttk.Label(parent, text=label)
        label_widget.grid(row=row, column=col, sticky="w", padx=4, pady=2)
        entry = ttk.Entry(parent, textvariable=self.str_var(name, value), show=show, width=width)
        entry.grid(row=row, column=col + 1, sticky="ew", padx=4, pady=2)
        if tooltip:
            ToolTip(label_widget, tooltip)
            ToolTip(entry, tooltip)
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
        ToolTip(self.req_button, FIELD_HELP["req_button"])

        conn = ttk.LabelFrame(self.content_frame, text="SSH Connection")
        conn.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        conn.columnconfigure(1, weight=1)
        self.add_labeled_entry(conn, 0, "Hostnames or IPs (Separated by commas)", "hosts", tooltip=FIELD_HELP["hosts"])
        self.add_labeled_entry(conn, 1, "SSH Username", "username", tooltip=FIELD_HELP["username"])

        ttk.Label(conn, text="Authentication Method").grid(row=2, column=0, sticky="w", padx=4, pady=2)
        auth_method_var = self.str_var("auth_method", "password")
        password_radio = ttk.Radiobutton(
            conn, text="Password", variable=auth_method_var, value="password", command=self.update_auth_method_state
        )
        password_radio.grid(row=2, column=1, sticky="w", padx=4, pady=2)
        key_radio = ttk.Radiobutton(
            conn, text="Private Key", variable=auth_method_var, value="key", command=self.update_auth_method_state
        )
        key_radio.grid(row=2, column=2, sticky="w", padx=4, pady=2)
        ToolTip(password_radio, FIELD_HELP["auth_method"])
        ToolTip(key_radio, FIELD_HELP["auth_method"])

        self.password_entry = self.add_labeled_entry(conn, 3, "SSH Password", "password", show="*", tooltip=FIELD_HELP["password"])
        self.key_path_entry = self.add_labeled_entry(conn, 4, "Private Key File", "key_path", tooltip=FIELD_HELP["key_path"])
        self.key_browse_button = ttk.Button(conn, text="Browse", command=self.browse_key_file)
        self.key_browse_button.grid(row=4, column=2, sticky="w", padx=4, pady=2)
        ToolTip(self.key_browse_button, FIELD_HELP["key_browse_button"])
        self.key_passphrase_entry = self.add_labeled_entry(
            conn, 5, "Key Passphrase (if encrypted)", "key_passphrase", show="*", tooltip=FIELD_HELP["key_passphrase"]
        )

        self.add_labeled_entry(conn, 6, "SSH Port", "ssh_port", str(DEFAULT_SSH_PORT), width=12, tooltip=FIELD_HELP["ssh_port"])
        self.add_labeled_entry(conn, 7, "Output Directory", "output_dir", str(DEFAULT_OUTPUT_DIR), tooltip=FIELD_HELP["output_dir"])
        browse_button = ttk.Button(conn, text="Browse", command=self.browse_output_dir)
        browse_button.grid(row=7, column=2, sticky="w", padx=4, pady=2)
        ToolTip(browse_button, FIELD_HELP["browse_button"])
        self.update_auth_method_state()

        opts = ttk.LabelFrame(self.content_frame, text="Debug Flow Options")
        opts.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        for col in range(4):
            opts.columnconfigure(col, weight=1)
        self.add_labeled_entry(opts, 0, "Trace Count", "num_packets", "100", col=0, width=20, tooltip=FIELD_HELP["num_packets"])
        self.add_labeled_entry(opts, 0, "Timer Seconds", "timer_seconds", "0", col=2, width=20, tooltip=FIELD_HELP["timer_seconds"])
        self.add_labeled_entry(opts, 1, "Add label to filename", "file_label", "run", col=0, width=30, tooltip=FIELD_HELP["file_label"])
        show_fn_cb = ttk.Checkbutton(opts, text="Show function-name", variable=self.bool_var("show_function_name", True))
        show_fn_cb.grid(row=1, column=2, sticky="w", padx=4, pady=2)
        ToolTip(show_fn_cb, FIELD_HELP["show_function_name"])
        show_iprope_cb = ttk.Checkbutton(opts, text="Show iprope", variable=self.bool_var("show_iprope", True))
        show_iprope_cb.grid(row=1, column=3, sticky="w", padx=4, pady=2)
        ToolTip(show_iprope_cb, FIELD_HELP["show_iprope"])
        console_ts_cb = ttk.Checkbutton(opts, text="Console timestamp", variable=self.bool_var("console_timestamp", True))
        console_ts_cb.grid(row=2, column=2, sticky="w", padx=4, pady=2)
        ToolTip(console_ts_cb, FIELD_HELP["console_timestamp"])

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

        for row, (label, start_name, end_name, help_key) in enumerate([
            ("Addr", "addr_from", "addr_to", "addr"),
            ("Src Addr", "saddr_from", "saddr_to", "saddr"),
            ("Dst Addr", "daddr_from", "daddr_to", "daddr"),
            ("Port", "port_from", "port_to", "port"),
            ("Src Port", "sport_from", "sport_to", "sport"),
            ("Dst Port", "dport_from", "dport_to", "dport"),
        ]):
            filter_label = ttk.Label(filter_fields, text=label)
            filter_label.grid(row=row, column=0, sticky="w", padx=4, pady=2)
            entry_from = ttk.Entry(filter_fields, textvariable=self.str_var(start_name), width=18)
            entry_from.grid(row=row, column=1, sticky="ew", padx=4, pady=2)
            ttk.Label(filter_fields, text="to").grid(row=row, column=2, sticky="w", padx=4, pady=2)
            entry_to = ttk.Entry(filter_fields, textvariable=self.str_var(end_name), width=18)
            entry_to.grid(row=row, column=3, sticky="ew", padx=4, pady=2)
            negate_cb = ttk.Checkbutton(filter_fields, text="Not", variable=self.bool_var(f"{help_key}_negate", False))
            negate_cb.grid(row=row, column=4, sticky="w", padx=4, pady=2)
            help_text = FIELD_HELP[help_key]
            ToolTip(filter_label, help_text)
            ToolTip(entry_from, help_text)
            ToolTip(entry_to, help_text)
            ToolTip(negate_cb, FIELD_HELP["negate"])
        proto_row = 6
        proto_label = ttk.Label(filter_fields, text="Protocol Number 1=ICMP, 6=TCP, 17=UDP")
        proto_label.grid(row=proto_row, column=0, sticky="w", padx=4, pady=2)
        proto_entry = ttk.Entry(filter_fields, textvariable=self.str_var("proto"), width=18)
        proto_entry.grid(row=proto_row, column=1, sticky="ew", padx=4, pady=2)
        ToolTip(proto_label, FIELD_HELP["proto"])
        ToolTip(proto_entry, FIELD_HELP["proto"])

        actions = ttk.Frame(self.content_frame)
        actions.grid(row=4, column=0, sticky="ew", padx=4, pady=4)
        self.start_button = ttk.Button(actions, text="Start", command=self.start)
        self.start_button.grid(row=0, column=0, padx=4, pady=4)
        ToolTip(self.start_button, FIELD_HELP["start_button"])
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=4, pady=4)
        ToolTip(self.stop_button, FIELD_HELP["stop_button"])
        clear_log_button = ttk.Button(actions, text="Clear Log", command=self.clear_log)
        clear_log_button.grid(row=0, column=2, padx=4, pady=4)
        ToolTip(clear_log_button, FIELD_HELP["clear_log_button"])

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

    def browse_key_file(self):
        ssh_dir = Path.home() / ".ssh"
        initial_dir = str(ssh_dir) if ssh_dir.is_dir() else str(SCRIPT_DIR)
        selected = filedialog.askopenfilename(initialdir=initial_dir, title="Select Private Key File")
        if selected:
            self.vars["key_path"].set(selected)

    def update_auth_method_state(self):
        is_key = self.vars["auth_method"].get() == "key"
        self.password_entry.configure(state="disabled" if is_key else "normal")
        self.key_path_entry.configure(state="normal" if is_key else "disabled")
        self.key_browse_button.configure(state="normal" if is_key else "disabled")
        self.key_passphrase_entry.configure(state="normal" if is_key else "disabled")

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
        auth_method = self.vars["auth_method"].get()
        password = self.vars["password"].get()
        key_path = self.vars["key_path"].get().strip()
        key_passphrase = self.vars["key_passphrase"].get()
        if not hosts:
            raise ValidationError("At least one hostname or IP is required.")
        if not username:
            raise ValidationError("SSH Username is required.")
        if auth_method == "key":
            if not key_path:
                raise ValidationError("Private Key File is required when Authentication Method is 'Private Key'.")
            if not Path(key_path).is_file():
                raise ValidationError(f"Private Key File not found: {key_path}")
        elif not password:
            raise ValidationError("SSH Password is required.")
        return DebugFlowSshArgs(
            hosts=hosts,
            username=username,
            auth_method=auth_method,
            password=password or None,
            key_path=key_path or None,
            key_passphrase=key_passphrase or None,
            ssh_port=validate_int_range("SSH Port", self.vars["ssh_port"].get(), DEFAULT_SSH_PORT, 1, 65535),
            num_packets=validate_int_range("Trace Count", self.vars["num_packets"].get(), 100, 1, 1000000),
            timer_seconds=validate_int_range("Timer Seconds", self.vars["timer_seconds"].get(), 0, 0, MAX_TIMER_SECONDS),
            file_label=self.vars["file_label"].get() or "run",
            output_dir=Path(self.vars["output_dir"].get() or str(DEFAULT_OUTPUT_DIR)),
            addr_from=validate_ip("addr_from", self.vars["addr_from"].get()),
            addr_to=validate_ip("addr_to", self.vars["addr_to"].get()),
            addr_negate=bool(self.vars["addr_negate"].get()),
            daddr_from=validate_ip("daddr_from", self.vars["daddr_from"].get()),
            daddr_to=validate_ip("daddr_to", self.vars["daddr_to"].get()),
            daddr_negate=bool(self.vars["daddr_negate"].get()),
            saddr_from=validate_ip("saddr_from", self.vars["saddr_from"].get()),
            saddr_to=validate_ip("saddr_to", self.vars["saddr_to"].get()),
            saddr_negate=bool(self.vars["saddr_negate"].get()),
            port_from=validate_port("port_from", self.vars["port_from"].get()),
            port_to=validate_port("port_to", self.vars["port_to"].get()),
            port_negate=bool(self.vars["port_negate"].get()),
            dport_from=validate_port("dport_from", self.vars["dport_from"].get()),
            dport_to=validate_port("dport_to", self.vars["dport_to"].get()),
            dport_negate=bool(self.vars["dport_negate"].get()),
            sport_from=validate_port("sport_from", self.vars["sport_from"].get()),
            sport_to=validate_port("sport_to", self.vars["sport_to"].get()),
            sport_negate=bool(self.vars["sport_negate"].get()),
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
        coordinator = RunCoordinator()
        self.sessions = [SshDebugSession(host, args, self.logger, coordinator) for host in args.hosts]
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
                session.send_ctrl_c("Manual stop (Stop button clicked).")
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
