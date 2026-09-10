"""
diag_fgt_debug_flow_v3.py

Standalone FortiGate Debug Flow utility using SSH instead of the FortiOS REST API.
Supersedes diag_fgt_debug_flow_v2.py in archive folder.

Adds on top of v2:
- Loads host keys from both local known_hosts and ~/.ssh/known_hosts.
- Strict host-key checking mode toggle and interactive Host Key Verification Wizard.
- Known Hosts Manager dialog for viewing and removing known host entries.
- Per-host color-coded live log output on a dark console terminal.
- Live output Boolean & Regex filter chaining (AND/OR/NOT/parentheses).
- Structured JSON trace export (Per-Host and Combined Multi-Host).
- Fully encrypted session profiles: all network topology, hostnames, IPs, ports,
  filter rules, and credentials are 100% encrypted with AES-256-GCM (PBKDF2-HMAC-SHA256).
- Standardized cross-platform os.path and lightweight file I/O helpers.

Carried over from v2 & v1:
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
- Trace output is now assembled from full lines only (buffered across SSH
  recv() chunks), fixing trace_id detection being missed when a chunk
  boundary split a trace_id= line in two.
- One run report per Start click (run_report_<label>_<timestamp>.txt),
  covering every host in that run: connections, stop reasons, errors, and
  warnings, with the raw trace output left out.
- Python requirements check and installer.

Carried over from v1:
- Python requirements check.
- GUI button to check/install missing Python packages.
- Start button automatically blocks with a clear message if requirements are missing.

Dependency:
- paramiko

Install manually if preferred:
    py -m pip install --upgrade paramiko

License:
    Copyright (c) 2026 RancerStank. All rights reserved.
    Licensed under the Fair Source / Commercial Tiered License.
    - Free for individual, educational, and single-consultant use.
    - Multi-user business/enterprise use requires an annual commercial subscription tier.
    - See LICENSE.md for complete terms and commercial inquiry details.
"""

from __future__ import annotations

# This script is a standalone FortiGate troubleshooting tool. The design is split
# into three layers so the GUI never has to think about low-level SSH details:
# 1. Validation and command-building helpers near the top of the file.
# 2. The SshDebugSession class, which manages one SSH session per target host.
# 3. The Tkinter-based DebugFlowSshGui, which collects user input and launches
# the worker threads that run the SSH sessions.

import base64
import hashlib
import importlib.util
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from ipaddress import ip_address
from typing import Callable, Any

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
    "cryptography": "cryptography",
}

paramiko = None
AESGCM = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
KNOWN_HOSTS_PATH = os.path.join(SCRIPT_DIR, "known_hosts")
DEFAULT_SSH_PORT = 22
DEFAULT_TIMEOUT_SECONDS = 20
MAX_TIMER_SECONDS = 24 * 60 * 60

PROFILE_AAD = b"diag_fgt_debug_flow_profile_v3"

LOG_INFO = "info"
LOG_WARN = "warning"
LOG_ERROR = "error"

# Log "kind" - distinguishes program/meta events (connections, stop reasons,
# errors, warnings) from raw FortiOS trace passthrough, so the run report can
# include the former and exclude the latter.
LOG_KIND_PROGRAM = "program"
LOG_KIND_TRACE = "trace"


def _read_text(filepath: str, encoding: str = "utf-8") -> str:
    """Read full text content of a file."""
    with open(filepath, "r", encoding=encoding) as f:
        return f.read()


def _write_text(filepath: str, content: str, encoding: str = "utf-8") -> None:
    """Write text content to a file, automatically creating parent directories if needed."""
    parent_dir = os.path.dirname(filepath)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(filepath, "w", encoding=encoding) as f:
        f.write(content)


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
    global paramiko, AESGCM
    try:
        import paramiko as _paramiko
        paramiko = _paramiko
    except Exception:
        paramiko = None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
        AESGCM = _AESGCM
    except Exception:
        AESGCM = None


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
    output_dir: str = DEFAULT_OUTPUT_DIR
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
    proto_negate: bool = False
    show_function_name: bool = True
    show_iprope: bool = True
    console_timestamp: bool = True
    strict_host_key_checking: bool = True
    save_text_output: bool = True
    save_combined_text: bool = True
    save_json_separate: bool = True
    save_json_combined: bool = True
    save_json_output: bool = True
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
        if args.proto_negate:
            commands.append("diagnose debug flow filter negate proto")
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
        prefix = "NOT " if args.proto_negate else ""
        values.append(f"{prefix}proto={args.proto}")
    return values


TRACE_ID_PATTERN = re.compile(r"trace_id=(\d+)")


def extract_trace_id(line: str) -> int | None:
    match = TRACE_ID_PATTERN.search(line)
    if match is None:
        return None
    return int(match.group(1))


class BooleanRegexFilter:
    """Evaluates boolean logic expressions over regex patterns for live output filtering.
    
    Supports:
    - Boolean operators: AND, &&, OR, ||, NOT, !, -
    - Grouping with parentheses: (10.0.0.1 OR 10.0.0.2) AND NOT drop
    - Quoted strings with spaces: "vd-root:0" AND NOT "drop packet"
    - Implicit AND between adjacent terms: 10.0.0.1 NOT drop
    - Plain single regex patterns: 10\\.0\\.0\\.\\d+, trace_id=\\d+
    """

    def __init__(self, expr: str) -> None:
        self.raw_expr = expr.strip()
        self.matcher = self._parse(self.raw_expr)

    def matches(self, line: str) -> bool:
        if not self.matcher:
            return True
        return self.matcher(line)

    def _parse(self, expr: str) -> Callable[[str], bool] | None:
        if not expr:
            return None
        tokens = self._tokenize(expr)
        if not tokens:
            return None
        ast = self._parse_or(tokens)
        if tokens:
            raise ValidationError(f"Unexpected token near '{tokens[0]}'")
        return ast

    def _tokenize(self, expr: str) -> list[str]:
        pattern = r'\(|\)|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s()]+'
        raw_tokens = re.findall(pattern, expr)
        tokens = []
        for t in raw_tokens:
            if len(t) >= 2 and ((t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'"))):
                tokens.append(t[1:-1].replace(r'\"', '"').replace(r"\'", "'"))
            else:
                tokens.append(t)
        return tokens

    def _parse_or(self, tokens: list[str]) -> Callable[[str], bool]:
        left = self._parse_and(tokens)
        while tokens and tokens[0].upper() in ("OR", "||", "|"):
            tokens.pop(0)
            right = self._parse_and(tokens)
            l_fn, r_fn = left, right
            left = lambda s, l=l_fn, r=r_fn: l(s) or r(s)
        return left

    def _parse_and(self, tokens: list[str]) -> Callable[[str], bool]:
        left = self._parse_not(tokens)
        while tokens and tokens[0] != ")" and tokens[0].upper() not in ("OR", "||", "|"):
            if tokens[0].upper() in ("AND", "&&"):
                tokens.pop(0)
            right = self._parse_not(tokens)
            l_fn, r_fn = left, right
            left = lambda s, l=l_fn, r=r_fn: l(s) and r(s)
        return left

    def _parse_not(self, tokens: list[str]) -> Callable[[str], bool]:
        if not tokens:
            raise ValidationError("Unexpected end of filter expression.")
        if tokens[0].upper() in ("NOT", "!", "-"):
            tokens.pop(0)
            sub = self._parse_atom(tokens)
            return lambda s, fn=sub: not fn(s)
        return self._parse_atom(tokens)

    def _parse_atom(self, tokens: list[str]) -> Callable[[str], bool]:
        if not tokens:
            raise ValidationError("Unexpected end of filter expression.")
        token = tokens.pop(0)
        if token == "(":
            sub = self._parse_or(tokens)
            if not tokens or tokens.pop(0) != ")":
                raise ValidationError("Unmatched open parenthesis '(' in filter expression.")
            return sub
        elif token == ")":
            raise ValidationError("Unexpected closing parenthesis ')' in filter expression.")
        else:
            try:
                rx = re.compile(token, re.IGNORECASE)
                return lambda s, r=rx: bool(r.search(s))
            except re.error as exc:
                raise ValidationError(f"Invalid regex pattern '{token}': {exc}")


PROTO_MAP: dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    112: "VRRP",
}

ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

DEBUG_FLOW_TS_RE = re.compile(
    r"^(?:\[(?P<host>[^\]]+)\]\s+)?"
    r"(?P<timestamp>"
    r"(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}/\d{2}/\d{4})\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{1,2}:\d{2}:\d{2}(?:\.\d+)?"
    r")\b"
)


def parse_trace_timestamp_sort_key(ts_str: str, base_epoch: float = 0.0) -> float:
    """Parse a trace timestamp string into a float epoch timestamp for chronological sorting."""
    ts_clean = ANSI_ESCAPE_RE.sub("", ts_str).strip()
    if not ts_clean:
        return base_epoch

    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(ts_clean, fmt).timestamp()
        except ValueError:
            pass

    for fmt in ("%H:%M:%S.%f", "%H:%M:%S"):
        try:
            t = datetime.strptime(ts_clean, fmt).time()
            base_date = datetime.fromtimestamp(base_epoch).date() if base_epoch > 0 else date.today()
            return datetime.combine(base_date, t).timestamp()
        except ValueError:
            pass

    try:
        val = float(ts_clean)
        return (base_epoch if base_epoch > 0 else 0.0) + val
    except ValueError:
        pass

    return base_epoch


def merge_debug_flow_texts_chronologically(session_outputs: list[tuple[Any, ...]]) -> tuple[str, int]:
    """Merge debug-flow outputs from multiple hosts into a single chronologically sorted text stream.
    
    Interleaves lines strictly chronologically by parsed timestamp. Any line lacking an explicit
    timestamp is written directly after whatever line came before it on that firewall by inheriting
    that firewall's last-seen timestamp and monotonic line index.
    
    Each line is prepended with '[hostname] ' if not already tagged.
    Accepts list of (host, raw_text) or (host, raw_text, started_wall_time).
    """
    all_lines: list[tuple[tuple[float, str, int], str]] = []
    
    for item in session_outputs:
        if len(item) == 3:
            host, raw_text, started_wall_time = item
        else:
            host, raw_text = item
            started_wall_time = 0.0
            
        last_ts = started_wall_time
        line_idx = 0
        for raw_line in raw_text.splitlines():
            clean_line = ANSI_ESCAPE_RE.sub("", raw_line).rstrip("\r\n")
            stripped = clean_line.strip()
            if not stripped:
                continue
            
            line_idx += 1
            m = DEBUG_FLOW_TS_RE.match(stripped)
            if m:
                ts_found = m.group("timestamp")
                last_ts = parse_trace_timestamp_sort_key(ts_found, base_epoch=started_wall_time)
            
            # Ensure line has host tag
            if stripped.startswith("[") and "]" in stripped:
                formatted_line = clean_line
            else:
                formatted_line = f"[{host}] {clean_line}"
                
            sort_key = (last_ts, host, line_idx)
            all_lines.append((sort_key, formatted_line))
            
    all_lines.sort(key=lambda x: x[0])
    
    result_lines = [item[1] for item in all_lines]
    return "\n".join(result_lines).strip(), len(result_lines)


TRACE_LINE_RE = re.compile(
    r'^(?:(?P<timestamp>(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}/\d{2}/\d{4})\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?|\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?'
    r'(?:id=(?P<id>\d+)\s+)?'
    r'trace_id=(?P<trace_id>\d+)'
    r'(?:\s+func=(?P<func>[\w_]+))?'
    r'(?:\s+line=(?P<line>\d+))?'
    r'(?:\s+msg="(?P<msg>.*?)")?\s*$'
)

PKT_DETAIL_RE = re.compile(
    r'vd-(?P<vdom>[^:]+):\d+\s+received a packet\(proto=(?P<proto>\d+),\s+'
    r'(?P<src_ip>[0-9a-fA-F\.:]+?)(?::(?P<src_port>\d+))?->'
    r'(?P<dst_ip>[0-9a-fA-F\.:]+?)(?::(?P<dst_port>\d+))?\)'
    r'(?:.*?from\s+(?P<in_iface>[a-zA-Z0-9._-]+))?'
    r'(?:.*?flag\s+\[(?P<tcp_flags>[^\]]+)\])?'
)

SESSION_RE = re.compile(r'(?:allocate a new|Find an existing)\s+session-(?P<session_id>[0-9a-fA-F]+)')
ROUTE_RE = re.compile(r'find a route:\s*(?:flag=[0-9a-fA-F]+\s+)?(?:gw-(?P<gateway>[^\s]+)\s+)?via\s+(?P<out_iface>[a-zA-Z0-9._-]+)')
POLICY_ALLOWED_RE = re.compile(r'Allowed by Policy-(?P<policy_id>\d+)(?::\s*(?P<details>.*))?', re.IGNORECASE)
POLICY_DENIED_RE = re.compile(r'Denied by Policy-(?P<policy_id>\d+)', re.IGNORECASE)
IPROPE_DROP_RE = re.compile(r'iprope_in_check\(\)\s+check failed on policy\s+(?P<policy_id>\d+),\s*(?P<action>drop|deny)', re.IGNORECASE)
SNAT_RE = re.compile(r'(?:SNAT|Source NAT):\s*(?P<snat>[^\s\"]+->[^\s\"]+)')
DNAT_RE = re.compile(r'(?:DNAT|Destination NAT):\s*(?P<dnat>[^\s\"]+->[^\s\"]+)')


def parse_debug_flow_text(raw_text: str, host: str | None = None, base_epoch: float = 0.0) -> dict[str, Any]:
    """Parse raw FortiOS debug-flow output into a structured dictionary for programmatic analysis."""
    traces_dict: dict[tuple[str | None, int], dict[str, Any]] = {}
    
    for raw_line in raw_text.splitlines():
        clean_line = ANSI_ESCAPE_RE.sub("", raw_line).strip()
        if not clean_line or "trace_id=" not in clean_line:
            continue
            
        line_host = host
        if clean_line.startswith("[") and "]" in clean_line:
            prefix_host, line_body = clean_line[1:].split("]", 1)
            if not line_host:
                line_host = prefix_host.strip()
            cleaned_line = line_body.strip()
        else:
            cleaned_line = clean_line
            
        m = TRACE_LINE_RE.search(cleaned_line)
        if not m:
            continue
            
        gd = m.groupdict()
        trace_id = int(gd["trace_id"])
        trace_key = (line_host, trace_id)
        
        if trace_key not in traces_dict:
            ts_str = gd.get("timestamp") or ""
            sort_epoch = parse_trace_timestamp_sort_key(ts_str, base_epoch=base_epoch) if ts_str else base_epoch
            traces_dict[trace_key] = {
                "trace_id": trace_id,
                "host": line_host,
                "first_timestamp": gd.get("timestamp"),
                "_sort_timestamp": sort_epoch,
                "vdom": None,
                "protocol": None,
                "protocol_name": None,
                "src_ip": None,
                "src_port": None,
                "dst_ip": None,
                "dst_port": None,
                "in_interface": None,
                "out_interface": None,
                "gateway": None,
                "session_id": None,
                "policy_id": None,
                "policy_action": None,
                "action": "in_progress",
                "snat": None,
                "dnat": None,
                "tcp_flags": None,
                "steps": [],
            }
            
        trace = traces_dict[trace_key]
        msg = gd.get("msg") or ""
        
        step = {
            "timestamp": gd.get("timestamp"),
            "id": int(gd["id"]) if gd.get("id") else None,
            "func": gd.get("func"),
            "line": int(gd["line"]) if gd.get("line") else None,
            "message": msg,
        }
        trace["steps"].append(step)
        
        # 1. Packet details
        pkt_m = PKT_DETAIL_RE.search(msg)
        if pkt_m:
            trace["vdom"] = pkt_m.group("vdom")
            proto_num = int(pkt_m.group("proto"))
            trace["protocol"] = proto_num
            trace["protocol_name"] = PROTO_MAP.get(proto_num, str(proto_num))
            trace["src_ip"] = pkt_m.group("src_ip")
            trace["src_port"] = int(pkt_m.group("src_port")) if pkt_m.group("src_port") else None
            trace["dst_ip"] = pkt_m.group("dst_ip")
            trace["dst_port"] = int(pkt_m.group("dst_port")) if pkt_m.group("dst_port") else None
            if pkt_m.group("in_iface"):
                trace["in_interface"] = pkt_m.group("in_iface").rstrip(".")
            trace["tcp_flags"] = pkt_m.group("tcp_flags")
            
        # 2. Session
        sess_m = SESSION_RE.search(msg)
        if sess_m:
            trace["session_id"] = sess_m.group("session_id")
            
        # 3. Route
        route_m = ROUTE_RE.search(msg)
        if route_m:
            if route_m.group("gateway"):
                trace["gateway"] = route_m.group("gateway")
            if route_m.group("out_iface"):
                trace["out_interface"] = route_m.group("out_iface").rstrip(".")
                
        # 4. Policy allowed
        pol_allow_m = POLICY_ALLOWED_RE.search(msg)
        if pol_allow_m:
            trace["policy_id"] = int(pol_allow_m.group("policy_id"))
            trace["policy_action"] = "Allow"
            trace["action"] = "allowed"
            
        # 5. Policy denied / drop
        pol_deny_m = POLICY_DENIED_RE.search(msg)
        if pol_deny_m:
            trace["policy_id"] = int(pol_deny_m.group("policy_id"))
            trace["policy_action"] = "Deny"
            trace["action"] = "denied"
            
        # 6. iprope drop
        iprope_m = IPROPE_DROP_RE.search(msg)
        if iprope_m:
            trace["policy_id"] = int(iprope_m.group("policy_id"))
            trace["policy_action"] = iprope_m.group("action").capitalize()
            trace["action"] = "dropped"
            
        # 7. SNAT / DNAT
        snat_m = SNAT_RE.search(msg)
        if snat_m:
            trace["snat"] = snat_m.group("snat")
        dnat_m = DNAT_RE.search(msg)
        if dnat_m:
            trace["dnat"] = dnat_m.group("dnat")

    # If action still in_progress, check steps for generic drop/allow markers
    for trace in traces_dict.values():
        if trace["action"] == "in_progress":
            all_msgs = " ".join(s["message"] for s in trace["steps"]).lower()
            if "drop" in all_msgs or "failed" in all_msgs or "deny" in all_msgs:
                trace["action"] = "dropped"
            elif "forward" in all_msgs or "reverse route" in all_msgs or trace["out_interface"]:
                trace["action"] = "allowed"
                
    traces_list = list(traces_dict.values())
    return {
        "metadata": {
            "generator": "diag_fgt_debug_flow_v3",
            "exported_at": datetime.now().isoformat(),
            "total_traces": len(traces_list),
            "host": host,
        },
        "traces": traces_list,
    }


def export_traces_to_json(raw_text: str, output_path: str | None = None, host: str | None = None, base_epoch: float = 0.0) -> str:
    """Parse trace output and serialize to JSON, optionally saving to a file."""
    data = parse_debug_flow_text(raw_text, host=host, base_epoch=base_epoch)
    for t in data.get("traces", []):
        t.pop("_sort_timestamp", None)
    json_str = json.dumps(data, indent=2)
    if output_path is not None:
        _write_text(output_path, json_str)
    return json_str


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
        if os.path.exists(KNOWN_HOSTS_PATH):
            try:
                merged.load(KNOWN_HOSTS_PATH)
            except Exception:
                pass
        merged.add(hostname, key.get_name(), key)
        parent_dir = os.path.dirname(KNOWN_HOSTS_PATH)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        merged.save(KNOWN_HOSTS_PATH)


def compute_key_fingerprints(key: paramiko.PKey) -> tuple[str, str]:
    """Compute SHA256 (OpenSSH standard) and MD5 fingerprints for an SSH public key."""
    raw_bytes = key.asbytes()
    sha256_fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw_bytes).digest()).decode("ascii").rstrip("=")
    md5_fp = ":".join(f"{b:02x}" for b in key.get_fingerprint())
    return sha256_fp, md5_fp


@dataclass
class HostKeyVerificationRequest:
    """Thread-safe request passed from background SSH worker threads to the main Tkinter UI thread."""
    hostname: str
    port: int
    key_type: str
    key_bits: int | None
    fingerprint_sha256: str
    fingerprint_md5: str
    key: paramiko.PKey
    response_event: threading.Event = field(default_factory=threading.Event)
    decision: str | None = None  # "trust_and_save", "trust_once", "reject"


class TrustOnFirstUsePolicy:
    """Paramiko missing-host-key policy: silently trust and persist a host
    key the first time it is seen for a given host, so repeat runs need no
    prompt and no manual known_hosts setup.
    """

    def __init__(self, logger: Callable[[str, str], None]) -> None:
        self.logger = logger

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        sha256_fp, _ = compute_key_fingerprints(key)
        client.get_host_keys().add(hostname, key.get_name(), key)
        persist_host_key(hostname, key)
        self.logger(
            LOG_WARN,
            f"New SSH host key for {hostname} trusted on first connection and "
            f"saved to {os.path.basename(KNOWN_HOSTS_PATH)}: {key.get_name()} {sha256_fp}",
        )


class InteractiveStrictHostKeyPolicy:
    """Paramiko missing-host-key policy: presents an interactive wizard dialog
    when strict host-key checking encounters an unknown host key, allowing the user
    to review key details, trust and save, trust once, or reject.
    """

    def __init__(
        self,
        port: int,
        prompt_callback: Callable[[HostKeyVerificationRequest], None] | None,
        logger: Callable[[str, str], None],
    ) -> None:
        self.port = port
        self.prompt_callback = prompt_callback
        self.logger = logger

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        sha256_fp, md5_fp = compute_key_fingerprints(key)
        key_name = key.get_name()
        key_bits = key.get_bits() if hasattr(key, "get_bits") else None

        if not self.prompt_callback:
            raise DebugFlowError(
                f"SSH host key for {hostname} is not in the known_hosts file ({key_name} {sha256_fp})."
            )

        req = HostKeyVerificationRequest(
            hostname=hostname,
            port=self.port,
            key_type=key_name,
            key_bits=key_bits,
            fingerprint_sha256=sha256_fp,
            fingerprint_md5=md5_fp,
            key=key,
        )

        self.prompt_callback(req)

        # Wait up to 120 seconds for user decision in the GUI wizard
        if not req.response_event.wait(timeout=120):
            raise DebugFlowError(f"Host key verification for {hostname} timed out waiting for user response.")

        if req.decision == "trust_and_save":
            client.get_host_keys().add(hostname, key.get_name(), key)
            persist_host_key(hostname, key)
            self.logger(
                LOG_INFO,
                f"SSH host key for {hostname} ({key_name} {sha256_fp}) trusted and saved to {os.path.basename(KNOWN_HOSTS_PATH)}.",
            )
        elif req.decision == "trust_once":
            client.get_host_keys().add(hostname, key.get_name(), key)
            self.logger(
                LOG_INFO,
                f"SSH host key for {hostname} ({key_name} {sha256_fp}) trusted for this session only.",
            )
        else:
            raise DebugFlowError(
                f"SSH host key for {hostname} was rejected by user ({key_name} {sha256_fp})."
            )


def load_all_known_hosts() -> dict[str, list[tuple]]:
    """Load known hosts from both the script's local known_hosts and user's
    ~/.ssh/known_hosts. Returns a dict mapping hostname to list of (key_type, key).
    """
    hosts_data = {}
    
    # Load from script's local known_hosts
    if os.path.exists(KNOWN_HOSTS_PATH):
        try:
            for line in _read_text(KNOWN_HOSTS_PATH).splitlines():
                if line.strip() and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        hostname = parts[0]
                        key_type = parts[1] if len(parts) >= 3 else "unknown"
                        if hostname not in hosts_data:
                            hosts_data[hostname] = []
                        hosts_data[hostname].append((key_type, line))
        except Exception:
            pass
    
    # Load from user's ~/.ssh/known_hosts
    user_known_hosts = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
    if os.path.exists(user_known_hosts):
        try:
            for line in _read_text(user_known_hosts).splitlines():
                if line.strip() and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        hostname = parts[0]
                        key_type = parts[1] if len(parts) >= 3 else "unknown"
                        if hostname not in hosts_data:
                            hosts_data[hostname] = []
                        hosts_data[hostname].append((key_type, line))
        except Exception:
            pass
    
    return hosts_data


def delete_known_host(hostname: str) -> None:
    """Remove a host entry from the script's known_hosts file."""
    if not os.path.exists(KNOWN_HOSTS_PATH):
        return
    
    try:
        lines = _read_text(KNOWN_HOSTS_PATH).splitlines()
        filtered = [line for line in lines if line.strip() and not line.startswith(hostname)]
        _write_text(KNOWN_HOSTS_PATH, "\n".join(filtered) + "\n" if filtered else "")
    except Exception as exc:
        raise DebugFlowError(f"Failed to delete host from known_hosts: {exc}") from exc


def show_known_hosts_manager(parent: tk.Tk | tk.Toplevel) -> None:
    """Show a dialog to view and manage known hosts."""
    hosts_data = load_all_known_hosts()
    
    if not hosts_data:
        messagebox.showinfo("Known Hosts Manager", "No known hosts found.")
        return
    
    manager_window = tk.Toplevel(parent)
    manager_window.title("Known Hosts Manager")
    manager_window.geometry("800x600")
    
    # Create a frame with scrollbar for the list
    frame = ttk.Frame(manager_window)
    frame.pack(fill="both", expand=True, padx=4, pady=4)
    
    scrollbar = ttk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")
    
    listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, font=("Courier", 9))
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.configure(command=listbox.yview)
    
    # Populate the listbox
    for hostname in sorted(hosts_data.keys()):
        listbox.insert("end", hostname)
    
    # Button frame
    button_frame = ttk.Frame(manager_window)
    button_frame.pack(fill="x", padx=4, pady=4)
    
    def delete_selected():
        selection = listbox.curselection()
        if not selection:
            messagebox.showwarning("Delete Host", "Please select a host to delete.")
            return
        
        hostname = listbox.get(selection[0])
        if messagebox.askyesno("Delete Host", f"Delete known host entry for {hostname}?"):
            try:
                delete_known_host(hostname)
                listbox.delete(selection[0])
                messagebox.showinfo("Deleted", f"Host entry for {hostname} has been removed.")
            except Exception as exc:
                messagebox.showerror("Delete Failed", f"Error deleting host: {exc}")
    
    delete_button = ttk.Button(button_frame, text="Delete Selected", command=delete_selected)
    delete_button.pack(side="left", padx=4)
    
    close_button = ttk.Button(button_frame, text="Close", command=manager_window.destroy)
    close_button.pack(side="left", padx=4)
    
    info_label = ttk.Label(
        manager_window,
        text=f"Known hosts from script ({os.path.basename(KNOWN_HOSTS_PATH)}) and user (~/.ssh/known_hosts):",
        font=("", 9)
    )
    info_label.pack(fill="x", padx=4, pady=4)


def encrypt_full_profile(profile_dict: dict, passphrase: str) -> dict:
    """Encrypt the entire profile dictionary using AES-256-GCM and PBKDF2-HMAC-SHA256."""
    if AESGCM is None:
        load_optional_modules()
        if AESGCM is None:
            raise DebugFlowError(
                "The 'cryptography' package is required to encrypt profiles. "
                "Please click 'Check / Install Requirements' first."
            )

    salt = os.urandom(16)
    nonce = os.urandom(12)
    iterations = 100_000

    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(profile_dict).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, PROFILE_AAD)

    return {
        "format": "fgt_debug_flow_encrypted_profile",
        "version": 3,
        "kdf": {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
        },
        "cipher": {
            "algorithm": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        },
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_full_profile(envelope: dict, passphrase: str) -> dict:
    """Decrypt a full profile dictionary using AES-256-GCM and PBKDF2-HMAC-SHA256."""
    if AESGCM is None:
        load_optional_modules()
        if AESGCM is None:
            raise DebugFlowError(
                "The 'cryptography' package is required to decrypt profiles. "
                "Please click 'Check / Install Requirements' first."
            )

    try:
        salt = base64.b64decode(envelope["kdf"]["salt_b64"])
        iterations = int(envelope["kdf"]["iterations"])
        nonce = base64.b64decode(envelope["cipher"]["nonce_b64"])
        ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    except Exception as exc:
        raise ValidationError(f"Corrupted profile encryption envelope: {exc}") from exc
    
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, PROFILE_AAD)
    except Exception as exc:
        raise ValidationError("Incorrect master passphrase or corrupted profile data.") from exc
    
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValidationError(f"Failed to parse decrypted profile JSON: {exc}") from exc


def save_session_profile(
    args: DebugFlowSshArgs,
    filepath: str,
    passphrase: str,
) -> None:
    """Save a session profile to an encrypted JSON file.
    
    The entire profile (network IPs, hostnames, ports, filters, options, and credentials)
    is 100% encrypted with AES-256-GCM. Zero plaintext network data exists on disk.
    """
    if not passphrase:
        raise ValidationError("Master passphrase is required to encrypt the session profile.")

    raw_profile_data = {
        "hosts": args.hosts,
        "username": args.username,
        "auth_method": args.auth_method,
        "password": args.password or "",
        "key_path": args.key_path or "",
        "key_passphrase": args.key_passphrase or "",
        "ssh_port": args.ssh_port,
        "output_dir": args.output_dir,
        "num_packets": args.num_packets,
        "timer_seconds": args.timer_seconds,
        "file_label": args.file_label,
        "addr_from": args.addr_from or "",
        "addr_to": args.addr_to or "",
        "addr_negate": args.addr_negate,
        "daddr_from": args.daddr_from or "",
        "daddr_to": args.daddr_to or "",
        "daddr_negate": args.daddr_negate,
        "saddr_from": args.saddr_from or "",
        "saddr_to": args.saddr_to or "",
        "saddr_negate": args.saddr_negate,
        "port_from": args.port_from,
        "port_to": args.port_to,
        "port_negate": args.port_negate,
        "dport_from": args.dport_from,
        "dport_to": args.dport_to,
        "dport_negate": args.dport_negate,
        "sport_from": args.sport_from,
        "sport_to": args.sport_to,
        "sport_negate": args.sport_negate,
        "proto": args.proto,
        "proto_negate": args.proto_negate,
        "show_function_name": args.show_function_name,
        "show_iprope": args.show_iprope,
        "console_timestamp": args.console_timestamp,
        "strict_host_key_checking": args.strict_host_key_checking,
        "save_text_output": args.save_text_output,
        "save_combined_text": args.save_combined_text,
        "save_json_output": args.save_json_output,
        "save_json_separate": args.save_json_separate,
        "save_json_combined": args.save_json_combined,
    }
    
    envelope = encrypt_full_profile(raw_profile_data, passphrase)
    
    try:
        _write_text(filepath, json.dumps(envelope, indent=2))
    except Exception as exc:
        raise DebugFlowError(f"Failed to save profile: {exc}") from exc


def load_session_profile(filepath: str, passphrase: str = "") -> dict:
    """Load and decrypt a session profile from an encrypted file."""
    if not os.path.exists(filepath):
        raise DebugFlowError(f"Profile file not found: {filepath}")
    
    try:
        data = json.loads(_read_text(filepath))
    except json.JSONDecodeError as exc:
        raise DebugFlowError(f"Invalid profile file format: {exc}") from exc
    except Exception as exc:
        raise DebugFlowError(f"Failed to read profile: {exc}") from exc
    
    if isinstance(data, dict) and ("ciphertext" in data or data.get("format") == "fgt_debug_flow_encrypted_profile"):
        if not passphrase:
            raise ValidationError("Master passphrase is required to decrypt this profile.")
        return decrypt_full_profile(data, passphrase)
    elif isinstance(data, dict) and "hosts" in data:
        # Legacy unencrypted format fallback
        return data
    else:
        raise DebugFlowError("Unrecognized profile file format.")


class SaveProfilePassphraseDialog:
    """Modal dialog prompting user for a master passphrase to fully encrypt the session profile."""

    def __init__(self, parent: tk.Tk | tk.Toplevel) -> None:
        self.result: str | None = None  # None = cancel, str = passphrase
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Encrypt Session Profile")
        self.dialog.geometry("460x290")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center dialog relative to parent
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width()
        parent_h = parent.winfo_height()
        dlg_w = 460
        dlg_h = 290
        pos_x = max(parent_x + (parent_w - dlg_w) // 2, 0)
        pos_y = max(parent_y + (parent_h - dlg_h) // 2, 0)
        self.dialog.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")

        main_frame = ttk.Frame(self.dialog, padding=16)
        main_frame.pack(fill="both", expand=True)

        header = ttk.Label(
            main_frame,
            text="🔐 Encrypt Session Profile",
            font=("", 11, "bold"),
        )
        header.pack(anchor="w", pady=(0, 4))

        desc = ttk.Label(
            main_frame,
            text="This profile contains sensitive network configuration (hosts, IPs, ports,\n"
                 "filters, and credentials). All contents will be fully encrypted with\n"
                 "AES-256-GCM using your master passphrase.",
            wraplength=420,
            justify="left",
        )
        desc.pack(anchor="w", pady=(0, 12))

        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill="x", pady=4)
        form_frame.columnconfigure(1, weight=1)

        ttk.Label(form_frame, text="Master Passphrase:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(form_frame, textvariable=self.pw_var, show="*", width=28)
        self.pw_entry.grid(row=0, column=1, sticky="ew", pady=4)

        ttk.Label(form_frame, text="Confirm Passphrase:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(form_frame, textvariable=self.confirm_var, show="*", width=28)
        self.confirm_entry.grid(row=1, column=1, sticky="ew", pady=4)

        self.show_pw_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(
            form_frame,
            text="Show Passphrase",
            variable=self.show_pw_var,
            command=self._toggle_show_pw,
        )
        show_cb.grid(row=2, column=1, sticky="w", pady=2)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(16, 0))

        encrypt_btn = ttk.Button(btn_frame, text="Encrypt & Save", command=self._on_encrypt_and_save)
        encrypt_btn.pack(side="left", padx=(0, 6))

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self._on_cancel)
        cancel_btn.pack(side="right")

        self.pw_entry.bind("<Return>", lambda _e: self._on_encrypt_and_save())
        self.confirm_entry.bind("<Return>", lambda _e: self._on_encrypt_and_save())
        self.dialog.bind("<Escape>", lambda _e: self._on_cancel())

        self.pw_entry.focus_set()
        self.dialog.wait_window()

    def _toggle_show_pw(self) -> None:
        char = "" if self.show_pw_var.get() else "*"
        self.pw_entry.configure(show=char)
        self.confirm_entry.configure(show=char)

    def _on_encrypt_and_save(self) -> None:
        pw = self.pw_var.get()
        confirm = self.confirm_var.get()
        if not pw:
            messagebox.showwarning(
                "Passphrase Required",
                "Please enter a master passphrase to encrypt the session profile.",
                parent=self.dialog,
            )
            self.pw_entry.focus_set()
            return
        if pw != confirm:
            messagebox.showerror(
                "Passphrase Mismatch",
                "The confirmation passphrase does not match. Please re-type.",
                parent=self.dialog,
            )
            self.confirm_entry.focus_set()
            return
        self.result = pw
        self.dialog.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.dialog.destroy()


class UnlockProfilePassphraseDialog:
    """Modal dialog prompting user for master passphrase to unlock a fully encrypted profile."""

    def __init__(self, parent: tk.Tk | tk.Toplevel, profile_path: str) -> None:
        self.result: str | None = None  # None = cancel, str = passphrase
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Unlock Session Profile")
        self.dialog.geometry("450x240")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width()
        parent_h = parent.winfo_height()
        dlg_w = 450
        dlg_h = 240
        pos_x = max(parent_x + (parent_w - dlg_w) // 2, 0)
        pos_y = max(parent_y + (parent_h - dlg_h) // 2, 0)
        self.dialog.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")

        main_frame = ttk.Frame(self.dialog, padding=16)
        main_frame.pack(fill="both", expand=True)

        header = ttk.Label(
            main_frame,
            text="🔓 Unlock Session Profile",
            font=("", 11, "bold"),
        )
        header.pack(anchor="w", pady=(0, 4))

        filename = os.path.basename(profile_path)
        desc = ttk.Label(
            main_frame,
            text=f"Profile '{filename}' is fully encrypted with AES-256-GCM.\n"
                 "Enter the master passphrase to decrypt and load settings:",
            wraplength=410,
            justify="left",
        )
        desc.pack(anchor="w", pady=(0, 12))

        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill="x", pady=4)
        form_frame.columnconfigure(1, weight=1)

        ttk.Label(form_frame, text="Master Passphrase:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(form_frame, textvariable=self.pw_var, show="*", width=28)
        self.pw_entry.grid(row=0, column=1, sticky="ew", pady=4)

        self.show_pw_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(
            form_frame,
            text="Show Passphrase",
            variable=self.show_pw_var,
            command=self._toggle_show_pw,
        )
        show_cb.grid(row=1, column=1, sticky="w", pady=2)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(16, 0))

        unlock_btn = ttk.Button(btn_frame, text="Unlock", command=self._on_unlock)
        unlock_btn.pack(side="left", padx=(0, 6))

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self._on_cancel)
        cancel_btn.pack(side="right")

        self.pw_entry.bind("<Return>", lambda _e: self._on_unlock())
        self.dialog.bind("<Escape>", lambda _e: self._on_cancel())

        self.pw_entry.focus_set()
        self.dialog.wait_window()

    def _toggle_show_pw(self) -> None:
        self.pw_entry.configure(show="" if self.show_pw_var.get() else "*")

    def _on_unlock(self) -> None:
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning(
                "Passphrase Required",
                "Please enter the master passphrase.",
                parent=self.dialog,
            )
            self.pw_entry.focus_set()
            return
        self.result = pw
        self.dialog.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.dialog.destroy()


class HostKeyWizardDialog:
    """Modal wizard dialog presented when an unknown SSH host key is encountered in strict mode."""

    def __init__(self, parent: tk.Tk | tk.Toplevel, req: HostKeyVerificationRequest) -> None:
        self.req = req
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"SSH Host Key Verification - {req.hostname}")
        self.dialog.geometry("560x450")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center relative to parent
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width()
        parent_h = parent.winfo_height()
        dlg_w = 560
        dlg_h = 450
        pos_x = max(parent_x + (parent_w - dlg_w) // 2, 0)
        pos_y = max(parent_y + (parent_h - dlg_h) // 2, 0)
        self.dialog.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")

        main_frame = ttk.Frame(self.dialog, padding=16)
        main_frame.pack(fill="both", expand=True)

        header = ttk.Label(
            main_frame,
            text="⚠️  Unknown SSH Host Key Detected",
            font=("", 12, "bold"),
            foreground="#c62828",
        )
        header.pack(anchor="w", pady=(0, 4))

        intro = ttk.Label(
            main_frame,
            text=f"The authenticity of target host '{req.hostname}' (port {req.port}) "
                 "cannot be established with your known_hosts files. "
                 "Please review the key details before connecting:",
            wraplength=520,
            justify="left",
        )
        intro.pack(anchor="w", pady=(0, 10))

        # Details box
        details_frame = ttk.LabelFrame(main_frame, text="Host Key Details", padding=10)
        details_frame.pack(fill="x", pady=(0, 10))
        details_frame.columnconfigure(1, weight=1)

        ttk.Label(details_frame, text="Target Host:", font=("", 9, "bold")).grid(row=0, column=0, sticky="w", pady=3)
        ttk.Label(details_frame, text=f"{req.hostname} (port {req.port})").grid(row=0, column=1, sticky="w", padx=8, pady=3)

        ttk.Label(details_frame, text="Key Type:", font=("", 9, "bold")).grid(row=1, column=0, sticky="w", pady=3)
        bits_str = f" ({req.key_bits} bits)" if req.key_bits else ""
        ttk.Label(details_frame, text=f"{req.key_type}{bits_str}").grid(row=1, column=1, sticky="w", padx=8, pady=3)

        ttk.Label(details_frame, text="SHA-256 Fingerprint:", font=("", 9, "bold")).grid(row=2, column=0, sticky="w", pady=3)
        sha_entry = ttk.Entry(details_frame, font=("Consolas", 9), width=44)
        sha_entry.insert(0, req.fingerprint_sha256)
        sha_entry.configure(state="readonly")
        sha_entry.grid(row=2, column=1, sticky="ew", padx=8, pady=3)

        ttk.Label(details_frame, text="MD5 Fingerprint:", font=("", 9, "bold")).grid(row=3, column=0, sticky="w", pady=3)
        md5_entry = ttk.Entry(details_frame, font=("Consolas", 9), width=44)
        md5_entry.insert(0, req.fingerprint_md5)
        md5_entry.configure(state="readonly")
        md5_entry.grid(row=3, column=1, sticky="ew", padx=8, pady=3)

        warning_text = ttk.Label(
            main_frame,
            text="• Trust & Save: Permanently adds key to known_hosts and connects.\n"
                 "• Trust Once: Accepts key for this session without saving to disk.\n"
                 "• Do Not Trust: Aborts SSH connection to this host immediately.",
            wraplength=520,
            justify="left",
            font=("", 9),
        )
        warning_text.pack(anchor="w", pady=(0, 14))

        # Button row
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(4, 0))

        trust_save_btn = ttk.Button(
            btn_frame,
            text="✓ Trust & Save Key",
            command=self._on_trust_and_save,
        )
        trust_save_btn.pack(side="left", padx=(0, 6))

        trust_once_btn = ttk.Button(
            btn_frame,
            text="Trust Once",
            command=self._on_trust_once,
        )
        trust_once_btn.pack(side="left", padx=6)

        reject_btn = ttk.Button(
            btn_frame,
            text="✗ Do Not Trust (Reject)",
            command=self._on_reject,
        )
        reject_btn.pack(side="right")

        self.dialog.protocol("WM_DELETE_WINDOW", self._on_reject)
        self.dialog.bind("<Escape>", lambda _e: self._on_reject())
        trust_save_btn.focus_set()

        self.dialog.wait_window()

    def _on_trust_and_save(self) -> None:
        self.req.decision = "trust_and_save"
        self.req.response_event.set()
        self.dialog.destroy()

    def _on_trust_once(self) -> None:
        self.req.decision = "trust_once"
        self.req.response_event.set()
        self.dialog.destroy()

    def _on_reject(self) -> None:
        self.req.decision = "reject"
        self.req.response_event.set()
        self.dialog.destroy()


class RunCoordinator:
    """Shared state across every SshDebugSession started from one Start click.

    Used so that as soon as any single target host reaches its own requested
    trace count, every other host that is still running gets told to stop too
    instead of continuing to collect on its own.
    """

    def __init__(self) -> None:
        self.trace_stop_event = threading.Event()
        self.trace_stop_host: str | None = None
        self.trace_stop_reason: str = ""
        self._lock = threading.Lock()

    def claim_trace_stop(self, host: str, reason: str = "") -> bool:
        """Record which host first reached its trace count. Returns True only
        for the first caller, so only that host is recorded as the cause."""
        with self._lock:
            if self.trace_stop_event.is_set():
                return False
            self.trace_stop_host = host
            if reason:
                self.trace_stop_reason = reason
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
        host_key_callback: Callable[[HostKeyVerificationRequest], None] | None = None,
    ) -> None:
        if paramiko is None:
            raise DebugFlowError("Missing dependency: paramiko. Use the Check/Install Requirements button.")
        self.host = host
        self.args = args
        self.logger = logger
        self.coordinator = coordinator
        self.host_key_callback = host_key_callback
        self.client = None
        self.channel = None
        self.stop_requested = threading.Event()
        self.completed = threading.Event()
        self.output_chunks = []
        self.error_text = ""
        self.result_file: str | None = None
        self.started_at = 0.0
        self.started_wall_time = 0.0
        self.ended_at = 0.0
        self.start_trace_id: int | None = None
        self.target_trace_id: int | None = None
        self.trace_count_reached = False
        self.seen_trace_ids: set[int] = set()
        self.target_trace_seen = False
        self.target_trace_last_line_at = 0.0
        self.stop_reason = "n/a"
        self._line_buffer = ""

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
            if os.path.exists(KNOWN_HOSTS_PATH):
                try:
                    client.load_host_keys(KNOWN_HOSTS_PATH)
                except Exception as exc:
                    self.log(LOG_WARNING, f"Could not read local known_hosts: {exc}")
            user_known = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
            if os.path.exists(user_known):
                try:
                    client.load_host_keys(user_known)
                except Exception:
                    pass

        if self.args.strict_host_key_checking:
            client.set_missing_host_key_policy(
                InteractiveStrictHostKeyPolicy(
                    port=self.args.ssh_port,
                    prompt_callback=self.host_key_callback,
                    logger=lambda lvl, msg: self.log(lvl, msg),
                )
            )
        else:
            client.set_missing_host_key_policy(
                TrustOnFirstUsePolicy(lambda lvl, msg: self.log(lvl, msg))
            )

        kwargs: dict[str, Any] = dict(
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
            kwargs["key_filename"] = self.args.key_path
            if self.args.key_passphrase:
                kwargs["passphrase"] = self.args.key_passphrase
            self.log(LOG_INFO, f"Authenticating with private key: {self.args.key_path}")
        else:
            kwargs["password"] = self.args.password

        client.connect(**kwargs)
        self.client = client
        self.channel = client.invoke_shell(term="vt100", width=200, height=1000)
        self.channel.settimeout(0.0)
        time.sleep(0.5)
        self.drain_channel()
        self.log(LOG_INFO, "SSH connection established.")

    def note_trace_line(self, line: str) -> None:
        if self.trace_count_reached or self.stop_requested.is_set() or self.args.num_packets <= 0:
            return
        trace_id = extract_trace_id(line)
        if trace_id is None:
            return

        self.seen_trace_ids.add(trace_id)

        if self.start_trace_id is None:
            self.start_trace_id = trace_id
            self.target_trace_id = trace_id + self.args.num_packets - 1
            self.log(
                LOG_INFO,
                f"First trace_id observed: {trace_id}. Session will stop once "
                f"trace_id {self.target_trace_id} finishes ({self.args.num_packets} trace(s) requested).",
            )

        # If a trace beyond target is seen, or distinct count exceeded, target trace is definitely complete
        if (self.target_trace_id is not None and trace_id > self.target_trace_id) or len(self.seen_trace_ids) > self.args.num_packets:
            self.trace_count_reached = True
            captured = len(self.seen_trace_ids)
            reason = (
                f"Requested trace count reached ({captured}/{self.args.num_packets} trace(s) captured, "
                f"trace_id {trace_id} observed after target {self.target_trace_id})."
            )
            self.log(LOG_INFO, reason)
            self.coordinator.claim_trace_stop(self.host, reason)
            self.send_ctrl_c(reason)
            return

        # If target trace is reached (by target_trace_id or count), mark it seen and update timestamp
        if (self.target_trace_id is not None and trace_id >= self.target_trace_id) or len(self.seen_trace_ids) >= self.args.num_packets:
            self.target_trace_seen = True
            self.target_trace_last_line_at = time.monotonic()

    def _handle_complete_line(self, line: str) -> None:
        stripped = line.rstrip("\r")
        if stripped.strip():
            self.logger(LOG_INFO, f"[{self.host}] {stripped}", LOG_KIND_TRACE)
            self.note_trace_line(stripped)

    def _consume_for_lines(self, data: str) -> None:
        self._line_buffer += data
        parts = self._line_buffer.split("\n")
        self._line_buffer = parts.pop()
        for line in parts:
            self._handle_complete_line(line)

    def flush_line_buffer(self) -> None:
        line, self._line_buffer = self._line_buffer, ""
        if line:
            self._handle_complete_line(line)

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
                self._consume_for_lines(data)
            except Exception:
                break

    def write_file(self) -> str:
        filename = f"{sanitize_component(self.host, 'fortigate')}_ssh_debug_flow_{sanitize_component(self.args.file_label, 'run')}_{timestamp_token()}.txt"
        path = os.path.join(self.args.output_dir, filename)
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
        session_output = "".join(self.output_chunks)
        if self.args.save_text_output:
            _write_text(path, "\n".join(lines))
            self.result_file = path
            self.log(LOG_INFO, f"Result file created: {path}")

        # Automatically export structured JSON alongside text output if enabled
        if self.args.save_json_separate:
            try:
                json_path = f"{os.path.splitext(path)[0]}.json"
                structured_data = parse_debug_flow_text(session_output, host=self.host, base_epoch=self.started_wall_time)
                for t in structured_data.get("traces", []):
                    t.pop("_sort_timestamp", None)
                structured_data["metadata"]["elapsed_seconds"] = round(elapsed, 2)
                structured_data["metadata"]["trace_count_requested"] = self.args.num_packets
                structured_data["metadata"]["trace_count_reached"] = self.trace_count_reached
                structured_data["metadata"]["stop_reason"] = self.stop_reason
                structured_data["metadata"]["active_filters"] = active_filters(self.args)
                _write_text(json_path, json.dumps(structured_data, indent=2))
                self.log(LOG_INFO, f"Structured JSON trace file created: {json_path}")
            except Exception as json_exc:
                self.log(LOG_WARNING, f"Could not generate JSON trace export: {json_exc}")

        return path

    def run(self) -> None:
        self.started_at = time.monotonic()
        self.started_wall_time = time.time()
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
                    captured_count = len(self.seen_trace_ids) if self.seen_trace_ids else self.args.num_packets
                    reason = (
                        f"Stopped by trace count (trace_id {self.start_trace_id}-{self.target_trace_id}, "
                        f"{captured_count} trace(s) captured)."
                    )
                    self.log(LOG_INFO, reason)
                    self.send_ctrl_c(reason)
                    break
                if self.target_trace_seen and not self.trace_count_reached:
                    # Give trailing lines of the target trace 350ms of quiet channel to finish arriving
                    if time.monotonic() - self.target_trace_last_line_at >= 0.35:
                        self.trace_count_reached = True
                        captured_count = len(self.seen_trace_ids) if self.seen_trace_ids else self.args.num_packets
                        reason = (
                            f"Requested trace count reached ({captured_count}/{self.args.num_packets} trace(s) captured, "
                            f"target trace_id {self.target_trace_id} finished)."
                        )
                        self.log(LOG_INFO, reason)
                        self.coordinator.claim_trace_stop(self.host, reason)
                        self.send_ctrl_c(reason)
                        break
                if self.coordinator.trace_stop_event.is_set():
                    reason = (
                        f"Stopped by {self.coordinator.trace_stop_host} "
                        f"({self.coordinator.trace_stop_reason or 'that host reached its trace count first'})."
                    )
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
                time.sleep(0.1)
            self.drain_channel()
            self.cleanup_remote_debug()
            time.sleep(0.5)
            self.drain_channel()
            self.flush_line_buffer()
            self.drain_channel()
            self.flush_line_buffer()
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
        "Folder where result files are saved: one '<host>_ssh_debug_flow_<label>_<timestamp>.txt' per "
        "host with its full trace output, plus one 'run_report_<label>_<timestamp>.txt' per run "
        "summarizing connections, stop reasons, errors, and warnings across all hosts (no raw trace "
        "output). The folder is created automatically if it does not already exist."
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
    "strict_host_key_checking": (
        "When enabled, requires host keys to be verified. If a host key is not already in your known_hosts "
        "files, an interactive Host Key Verification Wizard prompts you to review the key details and fingerprint, "
        "giving you the choice to Trust & Save, Trust Once, or Reject (preventing man-in-the-middle attacks)."
    ),
    "known_hosts_manager_button": (
        "Opens a dialog to view and manage all known hosts from both the script's known_hosts file and "
        "your user's ~/.ssh/known_hosts, allowing you to delete entries as needed."
    ),
    "save_profile_button": (
        "Saves the entire session configuration to a fully encrypted profile file using AES-256-GCM authenticated "
        "encryption with PBKDF2-HMAC-SHA256 key derivation. All sensitive network info (hostnames, IPs, ports, "
        "filters, and credentials) is 100% encrypted using a master passphrase of your choice."
    ),
    "load_profile_button": (
        "Loads a fully encrypted configuration profile from a file. Prompts for the master passphrase to decrypt "
        "and restore all network settings, filters, and credentials into the GUI."
    ),
    "regex_filter": (
        "Enter regex patterns with advanced boolean chaining (AND, OR, NOT, parentheses, and quoted strings). "
        "Filter live output in real time. Examples:\n"
        "• '(10.0.0.1 OR 10.0.0.2) AND NOT drop'\n"
        "• '\"vd-root:0\" && (SYN || ACK)'\n"
        "• 'NOT \"msg=deny\"'\n"
        "• 'trace_id=\\d+'"
    ),
    "show_matching_button": (
        "Display only log lines matching the boolean regex filter expression. Lines not matching will be hidden."
    ),
    "hide_matching_button": (
        "Hide all log lines matching the boolean regex filter expression. Lines not matching will remain visible."
    ),
    "clear_filter_button": (
        "Remove the active filter and restore all live log lines."
    ),
    "export_json_button": (
        "Exports console window to JSON, including Live Output Filters"
    ),
    "save_text_output": (
        "Saves standard FortiOS debug-flow console output to an individual plain text file (.txt) per target firewall."
    ),
    "save_combined_text": (
        "Saves a consolidated chronological text capture (.txt) interleaving debug-flow trace lines across all firewalls with [hostname] provenance."
    ),
    "save_json_separate": (
        "Generates an individual structured JSON file (.json) for each target firewall containing 5-tuples, VDOM, routing, policy rules, and verdicts."
    ),
    "save_json_combined": (
        "Generates a single aggregated JSON trace file (.json) combining all target firewalls sorted chronologically by trace arrival time."
    ),
}


# The GUI layer is intentionally thin. It collects user input, validates it,
# converts it into a DebugFlowSshArgs structure, and then launches one worker
# thread per host so the Tk event loop remains responsive while SSH work runs.
class DebugFlowSshGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Debug Flow SSH Standalone (v3)")
        self.vars = {}
        self.sessions = []
        self.threads = []
        self.manager_thread = None
        self.install_thread = None
        self.log_queue = queue.Queue()
        self.host_key_queue = queue.Queue()
        self.start_button = None
        self.stop_button = None
        self.req_button = None
        self.text_out_cb = None
        self.comb_text_cb = None
        self.json_out_cb = None
        self.json_separate_cb = None
        self.json_combined_cb = None
        self.report_lines: list[str] = []
        
        # Filter state
        self.current_regex_filter: BooleanRegexFilter | None = None
        self.filter_mode = None  # None, "show", or "hide"
        self.all_log_lines: list[tuple[str, str, str]] = []  # (level, message, stamp)
        
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

    def add_labeled_entry(self, parent, row, label, name, value="", show=None, col=0, width=30, tooltip=None):
        label_widget = ttk.Label(parent, text=label)
        label_widget.grid(row=row, column=col, sticky="w", padx=(4, 6), pady=2)
        entry = ttk.Entry(parent, textvariable=self.str_var(name, value), show=show, width=width)
        entry.grid(row=row, column=col + 1, sticky="w", padx=(0, 4), pady=2)
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
        self.content_frame.rowconfigure(6, weight=1)

        def _on_canvas_configure(event):
            self.canvas.itemconfig(self.content_window, width=event.width)
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.bind("<Configure>", _on_canvas_configure)
        self.content_frame.bind("<Configure>", lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        req = ttk.LabelFrame(self.content_frame, text="Python Requirements")
        req.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        req.columnconfigure(1, weight=1)
        self.req_button = ttk.Button(req, text="Check / Install Requirements", command=self.install_requirements_clicked)
        self.req_button.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ToolTip(self.req_button, FIELD_HELP["req_button"])
        self.req_status = ttk.Label(req, text="Checking requirements...")
        self.req_status.grid(row=0, column=1, sticky="w", padx=8, pady=2)

        conn = ttk.LabelFrame(self.content_frame, text="SSH Connection")
        conn.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        conn.columnconfigure(1, weight=1)
        self.add_labeled_entry(conn, 0, "Hostnames or IPs (Separated by commas)", "hosts", width=42, tooltip=FIELD_HELP["hosts"])
        self.add_labeled_entry(conn, 1, "SSH Username", "username", width=42, tooltip=FIELD_HELP["username"])

        ttk.Label(conn, text="Authentication Method").grid(row=2, column=0, sticky="w", padx=4, pady=2)
        auth_method_var = self.str_var("auth_method", "password")
        auth_frame = ttk.Frame(conn)
        auth_frame.grid(row=2, column=1, sticky="w", padx=4, pady=2)
        password_radio = ttk.Radiobutton(
            auth_frame, text="Password", variable=auth_method_var, value="password", command=self.update_auth_method_state
        )
        password_radio.pack(side="left", padx=(0, 20))
        key_radio = ttk.Radiobutton(
            auth_frame, text="Private Key", variable=auth_method_var, value="key", command=self.update_auth_method_state
        )
        key_radio.pack(side="left", padx=0)
        ToolTip(password_radio, FIELD_HELP["auth_method"])
        ToolTip(key_radio, FIELD_HELP["auth_method"])

        self.password_entry = self.add_labeled_entry(conn, 3, "SSH Password", "password", show="*", width=42, tooltip=FIELD_HELP["password"])
        
        # Private Key File + Browse button side-by-side
        ttk.Label(conn, text="Private Key File").grid(row=4, column=0, sticky="w", padx=4, pady=2)
        key_frame = ttk.Frame(conn)
        key_frame.grid(row=4, column=1, sticky="w", padx=4, pady=2)
        self.key_path_entry = ttk.Entry(key_frame, textvariable=self.str_var("key_path"), width=42)
        self.key_path_entry.pack(side="left", padx=(0, 6))
        self.key_browse_button = ttk.Button(key_frame, text="Browse", command=self.browse_key_file)
        self.key_browse_button.pack(side="left")
        ToolTip(self.key_path_entry, FIELD_HELP["key_path"])
        ToolTip(self.key_browse_button, FIELD_HELP["key_browse_button"])

        self.key_passphrase_entry = self.add_labeled_entry(
            conn, 5, "Key Passphrase (if encrypted)", "key_passphrase", show="*", width=42, tooltip=FIELD_HELP["key_passphrase"]
        )

        self.add_labeled_entry(conn, 6, "SSH Port", "ssh_port", str(DEFAULT_SSH_PORT), width=10, tooltip=FIELD_HELP["ssh_port"])
        
        # Output Directory + Browse button side-by-side
        ttk.Label(conn, text="Output Directory").grid(row=7, column=0, sticky="w", padx=4, pady=2)
        out_frame = ttk.Frame(conn)
        out_frame.grid(row=7, column=1, sticky="w", padx=4, pady=2)
        out_entry = ttk.Entry(out_frame, textvariable=self.str_var("output_dir", DEFAULT_OUTPUT_DIR), width=42)
        out_entry.pack(side="left", padx=(0, 6))
        browse_button = ttk.Button(out_frame, text="Browse", command=self.browse_output_dir)
        browse_button.pack(side="left")
        ToolTip(out_entry, FIELD_HELP["output_dir"])
        ToolTip(browse_button, FIELD_HELP["browse_button"])
        
        # Add strict host-key checking option and Known Hosts Manager button
        strict_check_cb = ttk.Checkbutton(conn, text="Strict Host-Key Checking", variable=self.bool_var("strict_host_key_checking", True))
        strict_check_cb.grid(row=8, column=0, sticky="w", padx=4, pady=2)
        ToolTip(strict_check_cb, FIELD_HELP["strict_host_key_checking"])
        
        known_hosts_button = ttk.Button(conn, text="Known Hosts Manager", command=self.open_known_hosts_manager)
        known_hosts_button.grid(row=8, column=1, sticky="w", padx=4, pady=2)
        ToolTip(known_hosts_button, FIELD_HELP["known_hosts_manager_button"])
        
        self.update_auth_method_state()

        opts = ttk.LabelFrame(self.content_frame, text="Debug Flow Options")
        opts.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        
        # Row 0: Trace Count
        row0 = ttk.Frame(opts)
        row0.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        tc_lbl = ttk.Label(row0, text="Trace Count", width=14, anchor="w")
        tc_lbl.pack(side="left", padx=(0, 4))
        tc_entry = ttk.Entry(row0, textvariable=self.str_var("num_packets", "100"), width=20)
        tc_entry.pack(side="left")
        ToolTip(tc_lbl, FIELD_HELP["num_packets"])
        ToolTip(tc_entry, FIELD_HELP["num_packets"])
        
        # Row 1: Timer Seconds
        row1 = ttk.Frame(opts)
        row1.grid(row=1, column=0, sticky="w", padx=4, pady=2)
        ts_lbl = ttk.Label(row1, text="Timer Seconds", width=14, anchor="w")
        ts_lbl.pack(side="left", padx=(0, 4))
        ts_entry = ttk.Entry(row1, textvariable=self.str_var("timer_seconds", "0"), width=20)
        ts_entry.pack(side="left")
        ToolTip(ts_lbl, FIELD_HELP["timer_seconds"])
        ToolTip(ts_entry, FIELD_HELP["timer_seconds"])
        
        # Row 2: Filename Label
        row2 = ttk.Frame(opts)
        row2.grid(row=2, column=0, sticky="w", padx=4, pady=2)
        fl_lbl = ttk.Label(row2, text="Filename Label", width=14, anchor="w")
        fl_lbl.pack(side="left", padx=(0, 4))
        fl_entry = ttk.Entry(row2, textvariable=self.str_var("file_label", "run"), width=20)
        fl_entry.pack(side="left")
        ToolTip(fl_lbl, FIELD_HELP["file_label"])
        ToolTip(fl_entry, FIELD_HELP["file_label"])
        
        # Row 3: Display Checkboxes (below input fields and above file output checkboxes)
        display_frame = ttk.Frame(opts)
        display_frame.grid(row=3, column=0, sticky="w", padx=4, pady=2)
        show_fn_cb = ttk.Checkbutton(display_frame, text="Show function-name", variable=self.bool_var("show_function_name", True))
        show_fn_cb.pack(side="left", padx=(0, 16))
        ToolTip(show_fn_cb, FIELD_HELP["show_function_name"])
        show_iprope_cb = ttk.Checkbutton(display_frame, text="Show iprope", variable=self.bool_var("show_iprope", True))
        show_iprope_cb.pack(side="left", padx=(0, 16))
        ToolTip(show_iprope_cb, FIELD_HELP["show_iprope"])
        console_ts_cb = ttk.Checkbutton(display_frame, text="Console timestamp", variable=self.bool_var("console_timestamp", True))
        console_ts_cb.pack(side="left", padx=0)
        ToolTip(console_ts_cb, FIELD_HELP["console_timestamp"])

        # Row 4: Output File Format Options (Symmetrical 2x2 Layout)
        out_opts_frame = ttk.Frame(opts)
        out_opts_frame.grid(row=4, column=0, sticky="w", padx=4, pady=(4, 2))

        # Row 4a: Per-Host Options
        r4a = ttk.Frame(out_opts_frame)
        r4a.pack(anchor="w", pady=1)
        ttk.Label(r4a, text="Per-Host:", width=10, font=("TkDefaultFont", 9, "bold")).pack(side="left", padx=(0, 6))
        self.text_out_cb = ttk.Checkbutton(
            r4a, text="Save Text Output (.txt)", variable=self.bool_var("save_text_output", True)
        )
        self.text_out_cb.pack(side="left", padx=(0, 16))
        ToolTip(self.text_out_cb, FIELD_HELP["save_text_output"])

        self.json_separate_cb = ttk.Checkbutton(
            r4a, text="Save JSON (.json)", variable=self.bool_var("save_json_separate", True)
        )
        self.json_separate_cb.pack(side="left", padx=0)
        ToolTip(self.json_separate_cb, FIELD_HELP["save_json_separate"])

        # Row 4b: Combined Options
        r4b = ttk.Frame(out_opts_frame)
        r4b.pack(anchor="w", pady=1)
        ttk.Label(r4b, text="Combined:", width=10, font=("TkDefaultFont", 9, "bold")).pack(side="left", padx=(0, 6))
        self.comb_text_cb = ttk.Checkbutton(
            r4b, text="Save Combined Text (.txt)", variable=self.bool_var("save_combined_text", True)
        )
        self.comb_text_cb.pack(side="left", padx=(0, 16))
        ToolTip(self.comb_text_cb, FIELD_HELP["save_combined_text"])

        self.json_combined_cb = ttk.Checkbutton(
            r4b, text="Combined JSON (.json)", variable=self.bool_var("save_json_combined", True)
        )
        self.json_combined_cb.pack(side="left", padx=0)
        ToolTip(self.json_combined_cb, FIELD_HELP["save_json_combined"])

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
            filter_label.grid(row=row, column=0, sticky="w", padx=(4, 6), pady=2)
            entry_from = ttk.Entry(filter_fields, textvariable=self.str_var(start_name), width=15)
            entry_from.grid(row=row, column=1, sticky="w", padx=(0, 4), pady=2)
            to_label = ttk.Label(filter_fields, text="to")
            to_label.grid(row=row, column=2, sticky="w", padx=(2, 4), pady=2)
            entry_to = ttk.Entry(filter_fields, textvariable=self.str_var(end_name), width=15)
            entry_to.grid(row=row, column=3, sticky="w", padx=(0, 4), pady=2)
            negate_cb = ttk.Checkbutton(filter_fields, text="Not", variable=self.bool_var(f"{help_key}_negate", False))
            negate_cb.grid(row=row, column=4, sticky="w", padx=(6, 4), pady=2)
            help_text = FIELD_HELP[help_key]
            ToolTip(filter_label, help_text)
            ToolTip(entry_from, help_text)
            ToolTip(entry_to, help_text)
            ToolTip(negate_cb, FIELD_HELP["negate"])
        proto_row = 6
        proto_label = ttk.Label(filter_fields, text="Proto #")
        proto_label.grid(row=proto_row, column=0, sticky="w", padx=(4, 6), pady=2)
        proto_entry = ttk.Entry(filter_fields, textvariable=self.str_var("proto"), width=10)
        proto_entry.grid(row=proto_row, column=1, sticky="w", padx=(0, 4), pady=2)
        proto_negate_cb = ttk.Checkbutton(filter_fields, text="Not", variable=self.bool_var("proto_negate", False))
        proto_negate_cb.grid(row=proto_row, column=4, sticky="w", padx=(6, 4), pady=2)
        ToolTip(proto_label, FIELD_HELP["proto"])
        ToolTip(proto_entry, FIELD_HELP["proto"])
        ToolTip(proto_negate_cb, FIELD_HELP["negate"])

        actions = ttk.Frame(self.content_frame)
        actions.grid(row=4, column=0, sticky="ew", padx=4, pady=4)
        actions.columnconfigure(0, weight=1)
        
        # First row: Start, Stop, Clear Log
        button_row1 = ttk.Frame(actions)
        button_row1.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self.start_button = ttk.Button(button_row1, text="Start", command=self.start)
        self.start_button.grid(row=0, column=0, padx=4, pady=4)
        ToolTip(self.start_button, FIELD_HELP["start_button"])
        self.stop_button = ttk.Button(button_row1, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=4, pady=4)
        ToolTip(self.stop_button, FIELD_HELP["stop_button"])
        clear_log_button = ttk.Button(button_row1, text="Clear Log", command=self.clear_log)
        clear_log_button.grid(row=0, column=2, padx=4, pady=4)
        ToolTip(clear_log_button, FIELD_HELP["clear_log_button"])
        
        # Second row: Save Profile, Load Profile, Export JSON
        button_row2 = ttk.Frame(actions)
        button_row2.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
        save_profile_button = ttk.Button(button_row2, text="Save Profile", command=self.save_profile_clicked)
        save_profile_button.grid(row=0, column=0, padx=4, pady=4)
        ToolTip(save_profile_button, FIELD_HELP["save_profile_button"])
        load_profile_button = ttk.Button(button_row2, text="Load Profile", command=self.load_profile_clicked)
        load_profile_button.grid(row=0, column=1, padx=4, pady=4)
        ToolTip(load_profile_button, FIELD_HELP["load_profile_button"])
        export_json_button = ttk.Button(button_row2, text="Export JSON", command=self.export_json_clicked)
        export_json_button.grid(row=0, column=2, padx=4, pady=4)
        ToolTip(export_json_button, FIELD_HELP["export_json_button"])

        # Advanced Boolean & Regex filter panel
        filter_frame = ttk.LabelFrame(self.content_frame, text="Live Output Advanced Filter — Boolean & Regex (Optional)")
        filter_frame.grid(row=5, column=0, sticky="ew", padx=4, pady=4)
        filter_frame.columnconfigure(1, weight=1)
        
        regex_label = ttk.Label(filter_frame, text="Filter Expression:")
        regex_label.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        regex_entry = ttk.Entry(filter_frame, textvariable=self.str_var("regex_filter_pattern", ""), width=60)
        regex_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=2)
        regex_entry.bind("<Return>", lambda _event: self.show_regex_matching())
        ToolTip(regex_label, FIELD_HELP["regex_filter"])
        ToolTip(regex_entry, FIELD_HELP["regex_filter"])
        
        show_matching_button = ttk.Button(filter_frame, text="Show Matching", command=self.show_regex_matching)
        show_matching_button.grid(row=0, column=2, padx=4, pady=2)
        ToolTip(show_matching_button, FIELD_HELP["show_matching_button"])
        
        hide_matching_button = ttk.Button(filter_frame, text="Hide Matching", command=self.hide_regex_matching)
        hide_matching_button.grid(row=0, column=3, padx=4, pady=2)
        ToolTip(hide_matching_button, FIELD_HELP["hide_matching_button"])
        
        clear_filter_button = ttk.Button(filter_frame, text="Clear Filter", command=self.clear_regex_filter)
        clear_filter_button.grid(row=0, column=4, padx=4, pady=2)
        ToolTip(clear_filter_button, FIELD_HELP["clear_filter_button"])

        log_frame = ttk.LabelFrame(self.content_frame, text="Live SSH Output / Log")
        log_frame.grid(row=6, column=0, sticky="nsew", padx=4, pady=4)
        self.content_frame.rowconfigure(6, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=20,
            wrap="word",
            bg="black",
            fg="#e0e0e0",
            insertbackground="white",
            selectbackground="#333333",
            selectforeground="white",
            font=("Consolas", 10),
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        # Configure color tags for different log levels on black background
        self.log_text.tag_configure("info", foreground="#e0e0e0")
        self.log_text.tag_configure("warning", foreground="#ffd740")
        self.log_text.tag_configure("error", foreground="#ff5252")
        
        # Define vibrant, high-contrast terminal colors for hosts on black background
        host_colors = [
            "#00e5ff",  # Bright Cyan
            "#69f0ae",  # Mint / Bright Green
            "#ffd740",  # Bright Amber / Gold
            "#ff80ab",  # Pink / Magenta
            "#b388ff",  # Light Violet / Purple
            "#ffab40",  # Bright Orange
            "#80d8ff",  # Sky Blue
            "#eeff41",  # Lime Yellow
            "#ea80fc",  # Light Fuchsia
            "#1de9b6",  # Teal Accent
        ]
        self.host_colors = {}
        self.host_color_index = 0
        self.host_colors_list = host_colors

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
        selected = filedialog.askdirectory(initialdir=self.vars["output_dir"].get() or DEFAULT_OUTPUT_DIR)
        if selected:
            self.vars["output_dir"].set(selected)

    def browse_key_file(self):
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        initial_dir = ssh_dir if os.path.isdir(ssh_dir) else SCRIPT_DIR
        selected = filedialog.askopenfilename(initialdir=initial_dir, title="Select Private Key File")
        if selected:
            self.vars["key_path"].set(selected)

    def open_known_hosts_manager(self):
        """Open the Known Hosts Manager dialog."""
        show_known_hosts_manager(self.root)

    def save_profile_clicked(self):
        """Save the current configuration to a fully encrypted profile file."""
        try:
            args = self.collect_args()
        except Exception as exc:
            messagebox.showerror("Save Profile Error", f"Cannot save profile: {exc}")
            return
        
        dialog = SaveProfilePassphraseDialog(self.root)
        if not dialog.result:
            # User cancelled dialog
            return
        passphrase = dialog.result
        
        selected = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Encrypted Profile (*.json)", "*.json"), ("All Files", "*.*")],
            initialfile=f"debug_flow_profile_{args.file_label}.json"
        )
        if not selected:
            return
        
        try:
            save_session_profile(args, selected, passphrase=passphrase)
            messagebox.showinfo(
                "Profile Saved",
                f"Profile successfully encrypted and saved to:\n{selected}\n\n"
                "All network settings, hostnames, IPs, and credentials are 100% encrypted with AES-256-GCM."
            )
            self.logger(LOG_INFO, f"Encrypted session profile saved: {selected}")
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Error saving profile: {exc}")

    def load_profile_clicked(self):
        """Load a fully encrypted profile file with passphrase decryption."""
        selected = filedialog.askopenfilename(
            filetypes=[("Encrypted Profile (*.json)", "*.json"), ("All Files", "*.*")],
            initialdir=SCRIPT_DIR
        )
        if not selected:
            return
        
        profile_path = selected
        try:
            raw_data = json.loads(_read_text(profile_path))
        except Exception as exc:
            messagebox.showerror("Load Failed", f"Error reading profile file: {exc}")
            return

        is_encrypted = isinstance(raw_data, dict) and ("ciphertext" in raw_data or raw_data.get("format") == "fgt_debug_flow_encrypted_profile")

        if is_encrypted:
            while True:
                unlock_dlg = UnlockProfilePassphraseDialog(self.root, selected)
                if not unlock_dlg.result:
                    # User clicked Cancel
                    return
                
                passphrase = unlock_dlg.result
                try:
                    profile_data = load_session_profile(profile_path, passphrase=passphrase)
                    self._apply_profile(profile_data)
                    messagebox.showinfo(
                        "Profile Loaded",
                        f"Profile loaded successfully from:\n{selected}\n\nAll settings and credentials unlocked."
                    )
                    self.logger(LOG_INFO, f"Encrypted session profile loaded and decrypted: {selected}")
                    return
                except Exception as exc:
                    messagebox.showerror(
                        "Decryption Failed",
                        f"Could not decrypt profile:\n{exc}\n\nPlease check your master passphrase.",
                    )
                    continue
        else:
            # Legacy unencrypted file fallback
            try:
                profile_data = load_session_profile(profile_path, passphrase="")
                self._apply_profile(profile_data)
                messagebox.showinfo("Profile Loaded", f"Legacy profile loaded from:\n{selected}")
                self.logger(LOG_INFO, f"Legacy session profile loaded: {selected}")
            except Exception as exc:
                messagebox.showerror("Load Failed", f"Error loading profile: {exc}")

    def export_json_clicked(self) -> None:
        """Export the current live log output to structured JSON format."""
        if not self.all_log_lines:
            messagebox.showwarning("No Data", "No log output available to export.")
            return
        
        default_name = f"debug_flow_export_{timestamp_token()}.json"
        initial_dir = self.vars.get("output_dir", tk.StringVar()).get() or DEFAULT_OUTPUT_DIR
        
        file_path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export Debug Flow to JSON",
            initialdir=initial_dir,
            initialfile=default_name,
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not file_path:
            return
            
        # Collect lines reflecting active live output filters
        lines_to_export = []
        for level, msg, stamp in self.all_log_lines:
            should_include = True
            if self.current_regex_filter:
                matches = self.current_regex_filter.matches(msg)
                if self.filter_mode == "show":
                    should_include = matches
                elif self.filter_mode == "hide":
                    should_include = not matches
            if should_include:
                lines_to_export.append(f"{stamp} ({level}) {msg}")
                
        full_text = "\n".join(lines_to_export)
        try:
            structured_data = parse_debug_flow_text(full_text)
            for t in structured_data.get("traces", []):
                t.pop("_sort_timestamp", None)
            if self.current_regex_filter and self.filter_mode:
                structured_data["metadata"]["live_filter_applied"] = self.vars.get("regex_filter_pattern", tk.StringVar()).get().strip()
                structured_data["metadata"]["live_filter_mode"] = self.filter_mode
            _write_text(file_path, json.dumps(structured_data, indent=2))
            count = structured_data["metadata"]["total_traces"]
            self.logger(LOG_INFO, f"Exported {count} trace(s) to JSON: {file_path}")
            messagebox.showinfo(
                "Export Successful",
                f"Successfully exported {count} structured trace(s) to:\n{file_path}"
            )
        except Exception as exc:
            messagebox.showerror("Export Error", f"Failed to export JSON:\n{exc}")

    def _apply_profile(self, profile_data: dict) -> None:
        """Apply loaded profile data to the GUI fields."""
        # Connection settings
        self.vars["hosts"].set(",".join(profile_data.get("hosts", [])))
        self.vars["username"].set(profile_data.get("username", ""))
        self.vars["auth_method"].set(profile_data.get("auth_method", "password"))
        self.vars["password"].set(profile_data.get("password", "") or "")
        self.vars["key_path"].set(profile_data.get("key_path", "") or "")
        self.vars["key_passphrase"].set(profile_data.get("key_passphrase", "") or "")
        self.vars["ssh_port"].set(str(profile_data.get("ssh_port", DEFAULT_SSH_PORT)))
        self.vars["output_dir"].set(profile_data.get("output_dir", DEFAULT_OUTPUT_DIR))
        self.vars["strict_host_key_checking"].set(profile_data.get("strict_host_key_checking", True))
        
        # Debug flow options
        self.vars["num_packets"].set(str(profile_data.get("num_packets", 100)))
        self.vars["timer_seconds"].set(str(profile_data.get("timer_seconds", 0)))
        self.vars["file_label"].set(profile_data.get("file_label", "run"))
        self.vars["show_function_name"].set(profile_data.get("show_function_name", True))
        self.vars["show_iprope"].set(profile_data.get("show_iprope", True))
        self.vars["console_timestamp"].set(profile_data.get("console_timestamp", True))
        
        # Address filters
        self.vars["addr_from"].set(profile_data.get("addr_from", "") or "")
        self.vars["addr_to"].set(profile_data.get("addr_to", "") or "")
        self.vars["addr_negate"].set(profile_data.get("addr_negate", False))
        self.vars["daddr_from"].set(profile_data.get("daddr_from", "") or "")
        self.vars["daddr_to"].set(profile_data.get("daddr_to", "") or "")
        self.vars["daddr_negate"].set(profile_data.get("daddr_negate", False))
        self.vars["saddr_from"].set(profile_data.get("saddr_from", "") or "")
        self.vars["saddr_to"].set(profile_data.get("saddr_to", "") or "")
        self.vars["saddr_negate"].set(profile_data.get("saddr_negate", False))
        
        # Port filters
        self.vars["port_from"].set(str(profile_data.get("port_from", "")) if profile_data.get("port_from") else "")
        self.vars["port_to"].set(str(profile_data.get("port_to", "")) if profile_data.get("port_to") else "")
        self.vars["port_negate"].set(profile_data.get("port_negate", False))
        self.vars["dport_from"].set(str(profile_data.get("dport_from", "")) if profile_data.get("dport_from") else "")
        self.vars["dport_to"].set(str(profile_data.get("dport_to", "")) if profile_data.get("dport_to") else "")
        self.vars["dport_negate"].set(profile_data.get("dport_negate", False))
        self.vars["sport_from"].set(str(profile_data.get("sport_from", "")) if profile_data.get("sport_from") else "")
        self.vars["sport_to"].set(str(profile_data.get("sport_to", "")) if profile_data.get("sport_to") else "")
        self.vars["sport_negate"].set(profile_data.get("sport_negate", False))
        
        # Protocol filter
        self.vars["proto"].set(str(profile_data.get("proto", "")) if profile_data.get("proto") else "")
        self.vars["proto_negate"].set(profile_data.get("proto_negate", False))
        
        # Output options
        self.vars["save_text_output"].set(profile_data.get("save_text_output", True))
        self.vars["save_combined_text"].set(profile_data.get("save_combined_text", True))
        legacy_json = profile_data.get("save_json_output", True)
        self.vars["save_json_separate"].set(profile_data.get("save_json_separate", legacy_json))
        self.vars["save_json_combined"].set(profile_data.get("save_json_combined", legacy_json))

        # Update UI states
        self.update_auth_method_state()

    def _apply_filter_mode(self, mode: str) -> None:
        pattern = self.vars.get("regex_filter_pattern", tk.StringVar()).get().strip()
        if not pattern:
            messagebox.showwarning("No Filter", "Please enter a filter expression first.")
            return
        try:
            self.current_regex_filter = BooleanRegexFilter(pattern)
        except ValidationError as exc:
            messagebox.showerror("Filter Syntax Error", f"Invalid filter expression:\n{exc}")
            return
        except Exception as exc:
            messagebox.showerror("Filter Error", f"Error parsing filter: {exc}")
            return
        self.filter_mode = mode
        self.logger(LOG_INFO, f"Advanced filter applied ({mode} matching): {pattern}")
        self.redraw_filtered_log()

    def hide_regex_matching(self) -> None:
        """Hide lines matching the boolean regex filter expression."""
        self._apply_filter_mode("hide")

    def show_regex_matching(self) -> None:
        """Show only lines matching the boolean regex filter expression."""
        self._apply_filter_mode("show")

    def clear_regex_filter(self) -> None:
        """Clear the filter and show all lines."""
        self.current_regex_filter = None
        self.filter_mode = None
        self.vars.get("regex_filter_pattern", tk.StringVar()).set("")
        self.redraw_filtered_log()
        self.logger(LOG_INFO, "Filter cleared - all lines visible.")

    def redraw_filtered_log(self):
        """Redraw the log text based on the current filter."""
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        
        for level, message, stamp in self.all_log_lines:
            # Check if line should be displayed based on filter
            should_display = True
            if self.current_regex_filter:
                matches = self.current_regex_filter.matches(message)
                if self.filter_mode == "show":
                    should_display = matches
                elif self.filter_mode == "hide":
                    should_display = not matches
            
            if should_display:
                # Re-insert the line with proper formatting
                self._insert_log_line(level, message, stamp)
        
        self.log_text.see("end")
        self.log_text.config(state="normal")

    def _insert_log_line(self, level: str, message: str, stamp: str) -> None:
        """Insert a single log line with whole-line color formatting."""
        # Extract host name if present (format: [hostname] message)
        host_color_tag = None
        if message.startswith("[") and "]" in message:
            host_part = message.split("]")[0].strip("[")
            if host_part not in self.host_colors:
                # Assign a new color to this host
                if self.host_color_index < len(self.host_colors_list):
                    color = self.host_colors_list[self.host_color_index]
                    self.host_colors[host_part] = color
                    self.log_text.tag_configure(f"host_{host_part}", foreground=color)
                    self.host_color_index += 1
                else:
                    # Cycle through colors if we have more hosts
                    color = self.host_colors_list[len(self.host_colors) % len(self.host_colors_list)]
                    self.host_colors[host_part] = color
                    self.log_text.tag_configure(f"host_{host_part}", foreground=color)
            host_color_tag = f"host_{host_part}"
        
        # Apply level-based tag (error/warning/info)
        level_tag = level.lower() if level.lower() in ["error", "warning", "info"] else "info"
        
        # Insert text with appropriate tags
        self.log_text.insert("end", f"{stamp} ({level}) {message}\n")
        
        # Apply tags to the newly inserted line (excluding newline)
        line_start = self.log_text.index("end-2c linestart")
        line_end = self.log_text.index("end-1c")
        
        # If line belongs to a host, color the WHOLE line with the host's assigned color;
        # otherwise use the level-based color (info/warning/error).
        if host_color_tag:
            self.log_text.tag_add(host_color_tag, line_start, line_end)
        else:
            self.log_text.tag_add(level_tag, line_start, line_end)

    def update_auth_method_state(self):
        is_key = self.vars["auth_method"].get() == "key"
        self.password_entry.configure(state="disabled" if is_key else "normal")
        self.key_path_entry.configure(state="normal" if is_key else "disabled")
        self.key_browse_button.configure(state="normal" if is_key else "disabled")
        self.key_passphrase_entry.configure(state="normal" if is_key else "disabled")

    def update_json_output_state(self):
        """Kept for backward-compatibility; output toggles operate independently."""
        pass

    def clear_log(self):
        self.log_text.delete("1.0", "end")
        self.all_log_lines = []

    def logger(self, level, message, kind=LOG_KIND_PROGRAM):
        stamp = datetime.now().strftime("%H:%M:%S")
        if kind != LOG_KIND_TRACE:
            self.report_lines.append(f"{stamp} ({level}) {message}")
        self.log_queue.put((level, message, stamp))

    def check_host_key_queue(self) -> None:
        """Drain any pending host key verification requests from worker threads and show wizard dialog."""
        try:
            while True:
                req = self.host_key_queue.get_nowait()
                HostKeyWizardDialog(self.root, req)
        except queue.Empty:
            pass

    def drain_log_queue(self):
        self.check_host_key_queue()
        try:
            while True:
                level, message, stamp = self.log_queue.get_nowait()
                
                # Store line for filtering
                self.all_log_lines.append((level, message, stamp))
                
                # Check if line should be displayed based on active filter
                should_display = True
                if self.current_regex_filter:
                    matches = self.current_regex_filter.matches(message)
                    if self.filter_mode == "show":
                        should_display = matches
                    elif self.filter_mode == "hide":
                        should_display = not matches
                
                if should_display:
                    self._insert_log_line(level, message, stamp)
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
            if not os.path.isfile(key_path):
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
            output_dir=self.vars["output_dir"].get() or DEFAULT_OUTPUT_DIR,
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
            proto_negate=bool(self.vars["proto_negate"].get()),
            show_function_name=bool(self.vars["show_function_name"].get()),
            show_iprope=bool(self.vars["show_iprope"].get()),
            console_timestamp=bool(self.vars["console_timestamp"].get()),
            strict_host_key_checking=bool(self.vars["strict_host_key_checking"].get()),
            save_text_output=bool(self.vars.get("save_text_output", tk.BooleanVar(value=True)).get()),
            save_combined_text=bool(self.vars.get("save_combined_text", tk.BooleanVar(value=True)).get()),
            save_json_separate=bool(self.vars.get("save_json_separate", tk.BooleanVar(value=True)).get()),
            save_json_combined=bool(self.vars.get("save_json_combined", tk.BooleanVar(value=True)).get()),
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
        
        def prompt_host_key_callback(req: HostKeyVerificationRequest) -> None:
            self.host_key_queue.put(req)

        coordinator = RunCoordinator()
        self.sessions = [
            SshDebugSession(
                host,
                args,
                self.logger,
                coordinator,
                host_key_callback=prompt_host_key_callback,
            )
            for host in args.hosts
        ]
        self.threads = []
        self.report_lines = []
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
                if args.save_text_output:
                    try:
                        report_path = self.write_run_report(args)
                        self.logger(LOG_INFO, f"Run report written: {report_path}")
                    except Exception as exc:
                        self.logger(LOG_ERROR, f"Failed to write run report: {exc}")
                
                # Combined chronological text trace output
                if args.save_combined_text:
                    try:
                        comb_text_path, total_lines = self.write_combined_text(args)
                        self.logger(LOG_INFO, f"Combined chronological text trace written ({total_lines} lines): {comb_text_path}")
                    except Exception as exc:
                        self.logger(LOG_ERROR, f"Failed to write combined text trace file: {exc}")

                # If multiple hosts were targeted, automatically generate a combined JSON trace export if enabled
                if len(self.sessions) > 1 and args.save_json_combined:
                    try:
                        combined_json_path = self.write_combined_json(args)
                        self.logger(LOG_INFO, f"Combined multi-host JSON trace file written: {combined_json_path}")
                    except Exception as exc:
                        self.logger(LOG_ERROR, f"Failed to write combined JSON trace file: {exc}")

                self.root.after(0, lambda: self.set_running_state(False))
        self.manager_thread = threading.Thread(target=manager, daemon=True)
        self.manager_thread.start()

    def write_run_report(self, args: DebugFlowSshArgs) -> str:
        path = os.path.join(
            args.output_dir,
            f"run_report_{sanitize_component(args.file_label, 'run')}_{timestamp_token()}.txt",
        )
        lines = [
            "=== FortiGate SSH Debug Flow Run Report ===",
            f"Hosts: {', '.join(args.hosts)}",
            f"Trace Count Requested: {args.num_packets}",
            f"Timer Seconds: {args.timer_seconds}",
            "",
            "=== Program Log (connections, stop reasons, errors, warnings - no raw trace output) ===",
            *self.report_lines,
        ]
        _write_text(path, "\n".join(lines))
        return path

    def write_combined_text(self, args: DebugFlowSshArgs) -> tuple[str | None, int]:
        """Write consolidated chronological debug flow output across all targeted firewalls."""
        safe_label = sanitize_component(args.file_label, "run")
        ts = timestamp_token()
        path = os.path.join(args.output_dir, f"combined_ssh_debug_flow_{safe_label}_{ts}.txt")
        session_outputs = [
            (s.host, "".join(s.output_chunks), getattr(s, "started_wall_time", 0.0))
            for s in self.sessions
        ]
        merged_content, total_lines = merge_debug_flow_texts_chronologically(session_outputs)
        elapsed_list = [s.ended_at - s.started_at for s in self.sessions if s.ended_at and s.started_at]
        elapsed = max(elapsed_list) if elapsed_list else 0.0
        banner = [
            "=== FortiGate SSH Debug Flow Combined Capture (Chronological) ===",
            f"Hosts: {', '.join(args.hosts)}",
            f"SSH Port: {args.ssh_port}",
            f"Trace Count Requested: {args.num_packets}",
            f"Timer Seconds: {args.timer_seconds}",
            f"Active Filters: {'; '.join(active_filters(args)) if active_filters(args) else 'none'}",
            f"Elapsed Seconds: {elapsed:.2f}",
            f"Total Interleaved Lines: {total_lines}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=== Chronological Debug Flow Output ===",
            merged_content,
        ]
        _write_text(path, "\n".join(banner))
        return path, total_lines

    def write_combined_json(self, args: DebugFlowSshArgs) -> str:
        """Generate a single combined JSON trace export aggregating all targeted hosts chronologically."""
        path = os.path.join(
            args.output_dir,
            f"combined_ssh_debug_flow_{sanitize_component(args.file_label, 'run')}_{timestamp_token()}.json",
        )
        
        all_traces: list[dict[str, Any]] = []
        hosts_summary: dict[str, Any] = {}
        
        for session in self.sessions:
            session_output = "".join(session.output_chunks)
            parsed = parse_debug_flow_text(session_output, host=session.host, base_epoch=getattr(session, "started_wall_time", 0.0))
            traces = parsed.get("traces", [])
            all_traces.extend(traces)
            
            elapsed = session.ended_at - session.started_at if session.ended_at and session.started_at else 0.0
            hosts_summary[session.host] = {
                "elapsed_seconds": round(elapsed, 2),
                "trace_count_captured": len(traces),
                "trace_count_reached": session.trace_count_reached,
                "stop_reason": session.stop_reason,
                "error": session.error_text or None,
            }
            
        all_traces.sort(key=lambda t: (t.get("_sort_timestamp", 0.0), t.get("host", ""), t.get("trace_id", 0)))
        for t in all_traces:
            t.pop("_sort_timestamp", None)

        combined_payload = {
            "metadata": {
                "generator": "diag_fgt_debug_flow_v3",
                "exported_at": datetime.now().isoformat(),
                "mode": "multi_host_combined",
                "hosts": args.hosts,
                "total_hosts": len(args.hosts),
                "total_traces": len(all_traces),
                "trace_count_requested": args.num_packets,
                "timer_seconds": args.timer_seconds,
                "active_filters": active_filters(args),
                "hosts_summary": hosts_summary,
            },
            "traces": all_traces,
        }
        
        _write_text(path, json.dumps(combined_payload, indent=2))
        return path

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
