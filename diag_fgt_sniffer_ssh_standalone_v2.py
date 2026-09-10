"""
diag_fgt_sniffer_ssh_standalone_v2.py

Standalone FortiGate Packet Sniffer utility over direct SSH using Paramiko.
Supersedes diag_fgt_sniffer_ssh_standalone_v1.py (archived).

Key Features ported & enhanced from diag_fgt_debug_flow_v3.py:
- Standardized on Paramiko worker threads (dedicated thread per firewall, no async event-loop collisions).
- Python requirements check & auto-installer for paramiko and cryptography.
- Wireshark / text2pcap integration:
  * Automatic detection of Wireshark text2pcap on standard Windows, macOS, and Linux locations.
  * Configurable Wireshark installation folder / text2pcap path with Browse picker & Auto-Detect.
  * Real-time path verification indicator.
  * Direct PCAP creation during live capture runs.
  * Standalone "Convert Log to PCAP" button to convert any past text capture to .pcap at any time.
  * Automatic timestamp format alignment (%Y-%m-%d %H:%M:%S.) eliminating text2pcap parsing errors.
- Dark console live view:
  * High-contrast dark console terminal (Consolas font on black background).
  * Whole-line per-host color coding using a vibrant 10-color terminal palette.
  * Color-tagged program log events (info, warning, error).
  * Complete line buffering across SSH receive chunks so headers and hex dumps are never split.
- Live output Boolean & Regex filter chaining (AND, OR, NOT, &&, ||, !, parentheses, quoted strings).
- Structured JSON Sniffer Trace Export:
  * Pure parser extracting 5-tuples (src/dst IP & port), interface, direction (in/out), protocol,
    summary flags, and reassembled hex/ascii payloads.
  * Per-Host JSON and Combined Multi-Host JSON exports.
  * GUI "Export JSON" button exporting console view reflecting active live filters.
- 100% Full-File Session Profile Encryption:
  * All targets, credentials, filter configurations, Wireshark path, and output preferences are
    fully encrypted with AES-256-GCM and PBKDF2-HMAC-SHA256. Zero plaintext network data on disk.
- SSH Security & Host Key Verification:
  * Password and Private Key authentication (.pem, id_rsa, id_ed25519 + passphrase).
  * Strict host-key checking enabled by default.
  * Interactive Host Key Verification Wizard (Trust & Save, Trust Once, Do Not Trust).
  * Known Hosts Manager dialog for viewing and removing known host entries.
  * Dual loading from script's local known_hosts and user's ~/.ssh/known_hosts.
- Standardized cross-platform os.path and resilient file I/O helpers.
- One run report per Start click (run_report_<label>_<timestamp>.txt) summarizing connections,
  stop reasons, packet counts, errors, and warnings across all hosts.

License:
    Copyright (c) 2026 RancerStank. All rights reserved.
    Licensed under the Fair Source / Commercial Tiered License.
    - Free for individual, educational, and single-consultant use.
    - Multi-user business/enterprise use requires an annual commercial subscription tier.
    - See LICENSE.md for complete terms and commercial inquiry details.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
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
MAX_DURATION_SECONDS = 24 * 60 * 60

PROFILE_AAD = b"diag_fgt_sniffer_profile_v2"

LOG_INFO = "info"
LOG_WARN = "warning"
LOG_ERROR = "error"

LOG_KIND_PROGRAM = "program"
LOG_KIND_SNIFFER = "sniffer"


def _read_text(filepath: str, encoding: str = "utf-8") -> str:
    """Read full text content of a file."""
    with open(filepath, "r", encoding=encoding, errors="replace") as f:
        return f.read()


def _write_text(filepath: str, content: str, encoding: str = "utf-8") -> None:
    """Write text content to a file, automatically creating parent directories if needed."""
    parent_dir = os.path.dirname(filepath)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(filepath, "w", encoding=encoding, errors="replace") as f:
        f.write(content)


class SnifferError(Exception):
    pass


class ValidationError(SnifferError):
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


def find_text2pcap(custom_dir_or_exe: str | None = None) -> str | None:
    """Find the text2pcap binary from custom path, system PATH, or standard installation directories."""
    if custom_dir_or_exe and custom_dir_or_exe.strip():
        cleaned = custom_dir_or_exe.strip().strip('"').strip("'")
        if os.path.isfile(cleaned):
            return os.path.abspath(cleaned)
        if os.path.isdir(cleaned):
            for candidate in ("text2pcap.exe", "text2pcap"):
                p = os.path.join(cleaned, candidate)
                if os.path.isfile(p):
                    return os.path.abspath(p)

    which_path = shutil.which("text2pcap") or shutil.which("text2pcap.exe")
    if which_path and os.path.isfile(which_path):
        return os.path.abspath(which_path)

    system_drive = os.environ.get("SystemDrive", "C:")
    program_files = os.environ.get("ProgramFiles", f"{system_drive}\\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", f"{system_drive}\\Program Files (x86)")

    candidates = [
        os.path.join(program_files, "Wireshark", "text2pcap.exe"),
        os.path.join(program_files_x86, "Wireshark", "text2pcap.exe"),
        os.path.join(program_files, "Ethereal", "text2pcap.exe"),
        os.path.join(program_files_x86, "Ethereal", "text2pcap.exe"),
        "/usr/bin/text2pcap",
        "/usr/local/bin/text2pcap",
        "/opt/homebrew/bin/text2pcap",
        "/Applications/Wireshark.app/Contents/MacOS/text2pcap",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return None


def normalize_for_text2pcap(raw_text: str) -> str:
    """Normalize FortiOS sniffer text output for Wireshark text2pcap conversion.
    
    Extracts timestamps and parses 0x0000 hex rows into standard text2pcap input format:
    YYYY-MM-DD HH:MM:SS.ffffff
    000000 45 00 00 28 ...
    000010 ...
    """
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
        if not line:
            continue
        # Strip optional host prefix [hostname]
        if line.startswith("[") and "]" in line:
            line = line.split("]", 1)[1].strip()

        # Match absolute timestamp (e.g. 2026-09-09 10:00:00.123456 or 09/09/2026 10:00:00)
        absolute = re.match(r"^(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b", line)
        if absolute:
            flush()
            timestamp = f"{absolute.group(1)} {absolute.group(2)}"
            continue

        # Match hex row: 0x0000 4500 004e ...
        hex_row = re.match(r"^0x([0-9a-fA-F]{4})\s+(.+)$", line)
        if not hex_row:
            continue

        hex_body = hex_row.group(2).split("\t", 1)[0]
        # Ignore ascii column if space separated after hex words
        groups = re.findall(r"[0-9a-fA-F]+", hex_body)
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


def create_pcap_file(text_path: str, text2pcap_exe: str | None = None) -> tuple[str | None, str]:
    """Convert a sniffer text output file to a .pcap file using text2pcap."""
    executable = text2pcap_exe or find_text2pcap()
    if not executable or not os.path.isfile(executable):
        return None, "text2pcap executable not found. Install Wireshark or specify its directory."

    if not os.path.isfile(text_path):
        return None, f"Source text file does not exist: {text_path}"

    raw_text = _read_text(text_path)
    normalized = normalize_for_text2pcap(raw_text)
    if not normalized.strip():
        return None, "No timestamp and hex packet rows (0x0000) were detected in output."

    base, _ = os.path.splitext(text_path)
    temp_path = f"{base}.text2pcap.txt"
    pcap_path = f"{base}.pcap"

    try:
        _write_text(temp_path, normalized)
        # Use strptime format "%Y-%m-%d %H:%M:%S." to parse FortiOS timestamp cleanly
        cmd = [executable, "-q", "-t", "%Y-%m-%d %H:%M:%S.", temp_path, pcap_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            err_msg = (proc.stderr or proc.stdout or f"text2pcap exited with code {proc.returncode}").strip()
            return None, err_msg
        if not os.path.isfile(pcap_path) or os.path.getsize(pcap_path) == 0:
            return None, "text2pcap generated an empty PCAP file."
        return pcap_path, ""
    except Exception as exc:
        return None, f"Execution failed: {exc}"
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@dataclass
class SnifferSshArgs:
    hosts: list[str]
    username: str
    auth_method: str = "password"
    password: str | None = None
    key_path: str | None = None
    key_passphrase: str | None = None
    ssh_port: int = DEFAULT_SSH_PORT
    interface: str = "any"
    verbose: int = 6
    count: int = 300
    duration_seconds: int = 1800
    file_label: str = "run"
    output_dir: str = DEFAULT_OUTPUT_DIR
    wireshark_path: str = ""
    protocol: str = ""
    host: str = ""
    src_host: str = ""
    dst_host: str = ""
    port: str = ""
    src_port: str = ""
    dst_port: str = ""
    net: str = ""
    src_net: str = ""
    dst_net: str = ""
    custom_filter: str = ""
    strict_host_key_checking: bool = True
    save_text_output: bool = True
    create_pcap: bool = True
    save_json_output: bool = True
    save_json_separate: bool = True
    save_json_combined: bool = True
    timeout: int = DEFAULT_TIMEOUT_SECONDS


def timestamp_token() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def sanitize_component(value: str | None, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip())
    cleaned = cleaned.strip("-_.")
    return cleaned or fallback


def parse_target_list(raw_targets: str) -> list[str]:
    targets = []
    seen = set()
    for item in str(raw_targets or "").split(","):
        value = item.strip()
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        targets.append(value)
    return targets


def split_values(raw: str) -> list[str]:
    return [x.strip() for x in re.split(r"\s+and\s+|,|;", raw or "", flags=re.I) if x.strip()]


def validate_target(value: str) -> None:
    if not value or any(c.isspace() for c in value):
        raise ValidationError(f"Invalid IP address or hostname: {value!r}")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(
        r"(?i)(?=.{1,253}\.?$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?",
        value,
    ):
        raise ValidationError(f"Invalid IP address or hostname: {value}")


def validate_ip(name: str, value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError as exc:
        raise ValidationError(f"Invalid IP address for {name}: {value}") from exc


def validate_net(name: str, value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError as exc:
        raise ValidationError(f"Invalid CIDR network for {name}: {value}") from exc


def validate_port(name: str, value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise ValidationError(f"Invalid port for {name}: {value}") from exc
    if not 1 <= number <= 65535:
        raise ValidationError(f"Port out of range (1-65535) for {name}: {value}")
    return number


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


def build_sniffer_filter(args: SnifferSshArgs) -> str:
    clauses = []
    if args.protocol.strip():
        for value in split_values(args.protocol):
            v_low = value.lower()
            if v_low not in {"tcp", "udp", "icmp", "ip", "arp", "esp", "gre"}:
                raise ValidationError(f"Invalid protocol in filter: {value}")
            clauses.append(v_low)

    for field_val, prefix, validator, name in (
        (args.host, "host", validate_ip, "Host"),
        (args.src_host, "src host", validate_ip, "Source Host"),
        (args.dst_host, "dst host", validate_ip, "Destination Host"),
        (args.port, "port", validate_port, "Port"),
        (args.src_port, "src port", validate_port, "Source Port"),
        (args.dst_port, "dst port", validate_port, "Destination Port"),
        (args.net, "net", validate_net, "Net"),
        (args.src_net, "src net", validate_net, "Source Net"),
        (args.dst_net, "dst net", validate_net, "Destination Net"),
    ):
        for value in split_values(field_val):
            validator(name, value)
            clauses.append(f"{prefix} {value}")

    if args.custom_filter.strip():
        custom = args.custom_filter.strip()
        clauses.append(f"({custom})" if clauses else custom)

    return " and ".join(clauses)


def quote_filter(value: str) -> str:
    if not value.strip():
        return "none"
    return "'" + value.replace("'", "\\'") + "'"


def build_sniffer_command(args: SnifferSshArgs) -> str:
    filter_expr = build_sniffer_filter(args)
    quoted = quote_filter(filter_expr)
    # FortiOS syntax: diagnose sniffer packet <interface> <filter> <verbose> <count> <tsformat>
    # tsformat: l (local timestamp)
    count_val = args.count if args.count > 0 else 0
    return f"diagnose sniffer packet {args.interface} {quoted} {args.verbose} {count_val} l"


def split_ip_port(endpoint: str) -> tuple[str, int | None]:
    """Parse an endpoint string like '10.0.0.1.443' or '[2001:db8::1]:443' into (ip, port)."""
    endpoint = endpoint.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        ip, port_str = endpoint[1:].split("]:", 1)
        try:
            return ip, int(port_str)
        except ValueError:
            return endpoint, None
    parts = endpoint.split(".")
    if len(parts) == 5 and all(p.isdigit() for p in parts):
        return ".".join(parts[:4]), int(parts[4])
    if ":" in endpoint and "." in endpoint:
        rparts = endpoint.rsplit(".", 1)
        if rparts[1].isdigit():
            return rparts[0], int(rparts[1])
    return endpoint, None


TIMESTAMP_HEADER_RE = re.compile(
    r"^(?:\[(?P<host>[^\]]+)\]\s+)?"
    r"(?P<timestamp>(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d+\.\d+)\s+"
    r"(?P<rest>.*)$"
)

IFACE_DIR_RE = re.compile(
    r"^(?P<interface>[a-zA-Z0-9._-]+)\s+(?P<direction>in|out)\s+(?P<body>.*)$"
)

IP_TRAFFIC_RE = re.compile(
    r"^(?P<src>[0-9a-fA-F\.:]+)\s*(?:->|-->>)\s*(?P<dst>[0-9a-fA-F\.:]+):\s*(?P<summary>.*)$"
)

HEX_ROW_RE = re.compile(
    r"^0x(?P<offset>[0-9a-fA-F]{4})\s+(?P<hex_data>.+)$"
)


def parse_sniffer_text(
    raw_text: str,
    host: str | None = None,
    interface: str | None = None,
    filter_expr: str | None = None,
    verbose: int | None = None,
) -> dict[str, Any]:
    """Parse raw FortiOS sniffer output into structured JSON containing individual packet metadata and hex payloads."""
    packets: list[dict[str, Any]] = []
    current_pkt: dict[str, Any] | None = None

    def flush_packet():
        nonlocal current_pkt
        if current_pkt:
            if current_pkt.get("hex_octets"):
                current_pkt["payload_hex"] = "".join(current_pkt.pop("hex_octets"))
            else:
                current_pkt.pop("hex_octets", None)
                current_pkt["payload_hex"] = None
            packets.append(current_pkt)
            current_pkt = None

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        line_host = host
        cleaned_line = line
        if line.startswith("[") and "]" in line:
            p_host, body = line[1:].split("]", 1)
            if not line_host:
                line_host = p_host.strip()
            cleaned_line = body.strip()

        m_ts = TIMESTAMP_HEADER_RE.match(line)
        if m_ts:
            flush_packet()
            gd = m_ts.groupdict()
            if gd.get("host") and not line_host:
                line_host = gd["host"].strip()

            rest = gd.get("rest") or ""
            pkt_iface = None
            pkt_direction = None
            pkt_body = rest

            m_dir = IFACE_DIR_RE.match(rest)
            if m_dir:
                pkt_iface = m_dir.group("interface")
                pkt_direction = m_dir.group("direction")
                pkt_body = m_dir.group("body")

            src_ip, src_port = None, None
            dst_ip, dst_port = None, None
            proto_name = None
            summary = pkt_body

            m_ip = IP_TRAFFIC_RE.match(pkt_body)
            if m_ip:
                src_ip, src_port = split_ip_port(m_ip.group("src"))
                dst_ip, dst_port = split_ip_port(m_ip.group("dst"))
                summary = m_ip.group("summary").strip()
                first_word = summary.split()[0].lower() if summary.split() else ""
                if first_word in ("tcp", "udp", "icmp", "arp", "ip", "esp", "gre"):
                    proto_name = first_word.upper()
                elif "syn" in summary.lower() or "ack" in summary.lower():
                    proto_name = "TCP"
                else:
                    proto_name = "IP"
            elif "arp" in pkt_body.lower():
                proto_name = "ARP"

            current_pkt = {
                "packet_number": len(packets) + 1,
                "host": line_host,
                "timestamp": gd.get("timestamp"),
                "interface": pkt_iface,
                "direction": pkt_direction,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto_name,
                "summary": summary,
                "payload_hex": None,
                "payload_ascii": None,
                "hex_octets": [],
                "raw_header": cleaned_line,
                "raw_lines": [cleaned_line],
            }
            continue

        m_hex = HEX_ROW_RE.match(cleaned_line)
        if m_hex and current_pkt:
            current_pkt["raw_lines"].append(cleaned_line)
            hex_data = m_hex.group("hex_data").split("\t", 1)[0]
            groups = re.findall(r"[0-9a-fA-F]+", hex_data)
            for group in groups:
                if len(group) >= 2 and len(group) % 2 == 0:
                    current_pkt["hex_octets"].extend(group[i:i+2] for i in range(0, len(group), 2))

    flush_packet()

    return {
        "metadata": {
            "generator": "diag_fgt_sniffer_ssh_standalone_v2",
            "exported_at": datetime.now().isoformat(),
            "total_packets": len(packets),
            "host": host,
            "interface": interface,
            "verbose_level": verbose,
            "active_filter": filter_expr,
        },
        "packets": packets,
    }


def export_sniffer_to_json(
    raw_text: str,
    output_path: str | None = None,
    host: str | None = None,
    interface: str | None = None,
    filter_expr: str | None = None,
    verbose: int | None = None,
) -> str:
    """Parse sniffer text and serialize to structured JSON string, optionally writing to disk."""
    data = parse_sniffer_text(raw_text, host=host, interface=interface, filter_expr=filter_expr, verbose=verbose)
    json_str = json.dumps(data, indent=2)
    if output_path is not None:
        _write_text(output_path, json_str)
    return json_str


class BooleanRegexFilter:
    """Evaluates boolean logic expressions over regex patterns for live output filtering."""

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


_known_hosts_lock = threading.Lock()


def persist_host_key(hostname: str, key: paramiko.PKey) -> None:
    """Merge newly-trusted host key into the shared known_hosts file."""
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
    """Compute SHA256 and MD5 fingerprints for an SSH key."""
    raw_bytes = key.asbytes()
    sha256_fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw_bytes).digest()).decode("ascii").rstrip("=")
    md5_fp = ":".join(f"{b:02x}" for b in key.get_fingerprint())
    return sha256_fp, md5_fp


@dataclass
class HostKeyVerificationRequest:
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
            raise SnifferError(
                f"SSH host key for {hostname} is not in known_hosts ({key_name} {sha256_fp})."
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

        if not req.response_event.wait(timeout=120):
            raise SnifferError(f"Host key verification for {hostname} timed out waiting for user response.")

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
            raise SnifferError(
                f"SSH host key for {hostname} was rejected by user ({key_name} {sha256_fp})."
            )


def load_all_known_hosts() -> dict[str, list[tuple]]:
    hosts_data = {}
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
    if not os.path.exists(KNOWN_HOSTS_PATH):
        return
    try:
        lines = _read_text(KNOWN_HOSTS_PATH).splitlines()
        filtered = [line for line in lines if line.strip() and not line.startswith(hostname)]
        _write_text(KNOWN_HOSTS_PATH, "\n".join(filtered) + "\n" if filtered else "")
    except Exception as exc:
        raise SnifferError(f"Failed to delete host from known_hosts: {exc}") from exc


def show_known_hosts_manager(parent: tk.Tk | tk.Toplevel) -> None:
    hosts_data = load_all_known_hosts()
    if not hosts_data:
        messagebox.showinfo("Known Hosts Manager", "No known hosts found.")
        return

    manager_window = tk.Toplevel(parent)
    manager_window.title("Known Hosts Manager")
    manager_window.geometry("800x600")

    frame = ttk.Frame(manager_window)
    frame.pack(fill="both", expand=True, padx=4, pady=4)

    scrollbar = ttk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")

    listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, font=("Consolas", 9))
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.configure(command=listbox.yview)

    for hostname in sorted(hosts_data.keys()):
        listbox.insert("end", hostname)

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

    ttk.Button(button_frame, text="Delete Selected", command=delete_selected).pack(side="left", padx=4)
    ttk.Button(button_frame, text="Close", command=manager_window.destroy).pack(side="left", padx=4)
    ttk.Label(
        manager_window,
        text=f"Known hosts loaded from script ({os.path.basename(KNOWN_HOSTS_PATH)}) and user (~/.ssh/known_hosts):",
        font=("", 9),
    ).pack(fill="x", padx=4, pady=4)


def encrypt_full_profile(profile_dict: dict, passphrase: str) -> dict:
    if AESGCM is None:
        load_optional_modules()
        if AESGCM is None:
            raise SnifferError(
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
        "format": "fgt_sniffer_encrypted_profile",
        "version": 2,
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
    if AESGCM is None:
        load_optional_modules()
        if AESGCM is None:
            raise SnifferError(
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


def save_session_profile(args: SnifferSshArgs, filepath: str, passphrase: str) -> None:
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
        "interface": args.interface,
        "verbose": args.verbose,
        "count": args.count,
        "duration_seconds": args.duration_seconds,
        "file_label": args.file_label,
        "output_dir": args.output_dir,
        "wireshark_path": args.wireshark_path,
        "protocol": args.protocol,
        "host": args.host,
        "src_host": args.src_host,
        "dst_host": args.dst_host,
        "port": args.port,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "net": args.net,
        "src_net": args.src_net,
        "dst_net": args.dst_net,
        "custom_filter": args.custom_filter,
        "strict_host_key_checking": args.strict_host_key_checking,
        "save_text_output": args.save_text_output,
        "create_pcap": args.create_pcap,
        "save_json_output": args.save_json_output,
        "save_json_separate": args.save_json_separate,
        "save_json_combined": args.save_json_combined,
    }

    envelope = encrypt_full_profile(raw_profile_data, passphrase)
    _write_text(filepath, json.dumps(envelope, indent=2))


def load_session_profile(filepath: str, passphrase: str = "") -> dict:
    if not os.path.exists(filepath):
        raise SnifferError(f"Profile file not found: {filepath}")

    try:
        data = json.loads(_read_text(filepath))
    except Exception as exc:
        raise SnifferError(f"Failed to read profile: {exc}") from exc

    if isinstance(data, dict) and (
        "ciphertext" in data or data.get("format") == "fgt_sniffer_encrypted_profile"
    ):
        if not passphrase:
            raise ValidationError("Master passphrase is required to decrypt this profile.")
        return decrypt_full_profile(data, passphrase)
    elif isinstance(data, dict) and "hosts" in data:
        return data
    else:
        raise SnifferError("Unrecognized profile file format.")


class SaveProfilePassphraseDialog:
    def __init__(self, parent: tk.Tk | tk.Toplevel) -> None:
        self.result: str | None = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Encrypt Session Profile")
        self.dialog.geometry("460x290")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        parent_x, parent_y = parent.winfo_rootx(), parent.winfo_rooty()
        parent_w, parent_h = parent.winfo_width(), parent.winfo_height()
        dlg_w, dlg_h = 460, 290
        pos_x = max(parent_x + (parent_w - dlg_w) // 2, 0)
        pos_y = max(parent_y + (parent_h - dlg_h) // 2, 0)
        self.dialog.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")

        main_frame = ttk.Frame(self.dialog, padding=16)
        main_frame.pack(fill="both", expand=True)

        header = ttk.Label(main_frame, text="🔐 Encrypt Sniffer Session Profile", font=("", 11, "bold"))
        header.pack(anchor="w", pady=(0, 4))

        desc = ttk.Label(
            main_frame,
            text="This profile contains sensitive network configuration (hosts, credentials, "
                 "and capture filters). All contents will be 100% encrypted with AES-256-GCM "
                 "using your master passphrase.",
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
        ttk.Checkbutton(
            form_frame,
            text="Show Passphrase",
            variable=self.show_pw_var,
            command=self._toggle_show_pw,
        ).grid(row=2, column=1, sticky="w", pady=2)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(16, 0))
        ttk.Button(btn_frame, text="Encrypt & Save", command=self._on_encrypt_and_save).pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side="right")

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
            messagebox.showwarning("Passphrase Required", "Please enter a master passphrase.", parent=self.dialog)
            self.pw_entry.focus_set()
            return
        if pw != confirm:
            messagebox.showerror("Passphrase Mismatch", "The confirmation passphrase does not match.", parent=self.dialog)
            self.confirm_entry.focus_set()
            return
        self.result = pw
        self.dialog.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.dialog.destroy()


class UnlockProfilePassphraseDialog:
    def __init__(self, parent: tk.Tk | tk.Toplevel, profile_path: str) -> None:
        self.result: str | None = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Unlock Session Profile")
        self.dialog.geometry("450x240")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        parent_x, parent_y = parent.winfo_rootx(), parent.winfo_rooty()
        parent_w, parent_h = parent.winfo_width(), parent.winfo_height()
        dlg_w, dlg_h = 450, 240
        pos_x = max(parent_x + (parent_w - dlg_w) // 2, 0)
        pos_y = max(parent_y + (parent_h - dlg_h) // 2, 0)
        self.dialog.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")

        main_frame = ttk.Frame(self.dialog, padding=16)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(main_frame, text="🔓 Unlock Sniffer Profile", font=("", 11, "bold")).pack(anchor="w", pady=(0, 4))
        filename = os.path.basename(profile_path)
        ttk.Label(
            main_frame,
            text=f"Profile '{filename}' is fully encrypted with AES-256-GCM.\n"
                 "Enter your master passphrase to decrypt and load settings:",
            wraplength=410,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill="x", pady=4)
        form_frame.columnconfigure(1, weight=1)

        ttk.Label(form_frame, text="Master Passphrase:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(form_frame, textvariable=self.pw_var, show="*", width=28)
        self.pw_entry.grid(row=0, column=1, sticky="ew", pady=4)

        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form_frame,
            text="Show Passphrase",
            variable=self.show_pw_var,
            command=self._toggle_show_pw,
        ).grid(row=1, column=1, sticky="w", pady=2)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(16, 0))
        ttk.Button(btn_frame, text="Unlock", command=self._on_unlock).pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side="right")

        self.pw_entry.bind("<Return>", lambda _e: self._on_unlock())
        self.dialog.bind("<Escape>", lambda _e: self._on_cancel())
        self.pw_entry.focus_set()
        self.dialog.wait_window()

    def _toggle_show_pw(self) -> None:
        self.pw_entry.configure(show="" if self.show_pw_var.get() else "*")

    def _on_unlock(self) -> None:
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("Passphrase Required", "Please enter the master passphrase.", parent=self.dialog)
            self.pw_entry.focus_set()
            return
        self.result = pw
        self.dialog.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.dialog.destroy()


class HostKeyWizardDialog:
    def __init__(self, parent: tk.Tk | tk.Toplevel, req: HostKeyVerificationRequest) -> None:
        self.req = req
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"SSH Host Key Verification - {req.hostname}")
        self.dialog.geometry("560x450")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        parent_x, parent_y = parent.winfo_rootx(), parent.winfo_rooty()
        parent_w, parent_h = parent.winfo_width(), parent.winfo_height()
        dlg_w, dlg_h = 560, 450
        pos_x = max(parent_x + (parent_w - dlg_w) // 2, 0)
        pos_y = max(parent_y + (parent_h - dlg_h) // 2, 0)
        self.dialog.geometry(f"{dlg_w}x{dlg_h}+{pos_x}+{pos_y}")

        main_frame = ttk.Frame(self.dialog, padding=16)
        main_frame.pack(fill="both", expand=True)

        header = ttk.Label(main_frame, text="⚠️ Unknown SSH Host Key Detected", font=("", 12, "bold"), foreground="#c62828")
        header.pack(anchor="w", pady=(0, 4))

        ttk.Label(
            main_frame,
            text=f"The authenticity of target host '{req.hostname}' (port {req.port}) "
                 "cannot be established with your known_hosts files. "
                 "Please review key details before connecting:",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

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

        ttk.Label(
            main_frame,
            text="• Trust & Save: Permanently adds key to known_hosts and connects.\n"
                 "• Trust Once: Accepts key for this session without saving to disk.\n"
                 "• Do Not Trust: Aborts SSH connection immediately.",
            wraplength=520,
            justify="left",
            font=("", 9),
        ).pack(anchor="w", pady=(0, 14))

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(4, 0))
        trust_save_btn = ttk.Button(btn_frame, text="✓ Trust & Save Key", command=self._on_trust_and_save)
        trust_save_btn.pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="Trust Once", command=self._on_trust_once).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="✗ Do Not Trust (Reject)", command=self._on_reject).pack(side="right")

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
    """Shared state across every SshSnifferSession in a single run."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.stop_host: str | None = None
        self.stop_reason: str | None = None
        self._lock = threading.Lock()

    def claim_stop(self, host: str, reason: str) -> bool:
        with self._lock:
            if self.stop_event.is_set():
                return False
            self.stop_host = host
            self.stop_reason = reason
            self.stop_event.set()
            return True


class SshSnifferSession:
    """Manages one SSH sniffer session to a single FortiGate."""

    def __init__(
        self,
        host: str,
        args: SnifferSshArgs,
        logger: Callable[[str, str, str], None],
        coordinator: RunCoordinator,
        host_key_callback: Callable[[HostKeyVerificationRequest], None] | None = None,
    ) -> None:
        if paramiko is None:
            raise SnifferError("Missing dependency: paramiko. Click 'Check / Install Requirements'.")
        self.host = host
        self.args = args
        self.logger = logger
        self.coordinator = coordinator
        self.host_key_callback = host_key_callback
        self.client = None
        self.channel = None
        self.stop_requested = threading.Event()
        self.completed = threading.Event()
        self.output_chunks: list[str] = []
        self.error_text = ""
        self.result_text_file: str | None = None
        self.result_pcap_file: str | None = None
        self.result_json_file: str | None = None
        self.started_at = 0.0
        self.ended_at = 0.0
        self.packet_count = 0
        self.stop_reason = "n/a"
        self._line_buffer = ""
        self._packet_pattern = re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\b")

    def log(self, level: str, message: str, kind: str = LOG_KIND_PROGRAM) -> None:
        self.logger(level, f"[{self.host}] {message}", kind)

    def send_ctrl_c(self, reason: str = "Manual stop") -> None:
        if self.stop_reason == "n/a":
            self.stop_reason = reason
        if self.channel:
            self.log(LOG_INFO, "Sending Ctrl+C to stop sniffer stream.")
            try:
                self.channel.send("\x03")
            except Exception as exc:
                self.log(LOG_WARN, f"Failed to send Ctrl+C: {exc}")
        self.stop_requested.set()

    def cleanup_remote(self) -> None:
        if not self.channel:
            return
        for cmd in ("\x03", "diagnose sniffer packet stop", "exit"):
            try:
                self.channel.send(cmd + "\n")
                time.sleep(0.15)
            except Exception:
                pass

    def connect(self) -> None:
        self.log(LOG_INFO, f"Connecting to {self.host}:{self.args.ssh_port}.")
        client = paramiko.SSHClient()
        with _known_hosts_lock:
            if os.path.exists(KNOWN_HOSTS_PATH):
                try:
                    client.load_host_keys(KNOWN_HOSTS_PATH)
                except Exception as exc:
                    self.log(LOG_WARN, f"Could not read local known_hosts: {exc}")
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
        self.channel = client.invoke_shell(term="vt100", width=240, height=1000)
        self.channel.settimeout(0.0)
        time.sleep(0.4)
        self.drain_channel()
        self.log(LOG_INFO, "SSH connection established.")

    def _handle_complete_line(self, line: str) -> None:
        stripped = line.rstrip("\r")
        if stripped.strip():
            self.log(LOG_INFO, stripped, LOG_KIND_SNIFFER)
            if self._packet_pattern.search(stripped):
                self.packet_count += 1
                if self.args.count > 0 and self.packet_count >= self.args.count and not self.stop_requested.is_set():
                    reason = f"Packet count reached ({self.packet_count}/{self.args.count})."
                    self.log(LOG_INFO, reason)
                    self.coordinator.claim_stop(self.host, reason)
                    self.send_ctrl_c(reason)

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

    def write_output_files(self) -> None:
        safe_host = sanitize_component(self.host, "fortigate")
        safe_label = sanitize_component(self.args.file_label, "run")
        stem = f"{safe_host}_ssh_sniffer_{safe_label}_{timestamp_token()}"
        base_path = os.path.join(self.args.output_dir, stem)
        elapsed = self.ended_at - self.started_at if self.ended_at and self.started_at else 0.0

        full_raw_output = "".join(self.output_chunks)

        if self.args.save_text_output:
            txt_path = f"{base_path}.txt"
            cmd_sent = build_sniffer_command(self.args)
            content = [
                "=== FortiGate SSH Packet Sniffer Capture ===",
                f"Host: {self.host}",
                f"SSH Port: {self.args.ssh_port}",
                f"Interface: {self.args.interface}",
                f"Verbose Level: {self.args.verbose}",
                f"Filter: {build_sniffer_filter(self.args) or 'none'}",
                f"Command: {cmd_sent}",
                f"Elapsed Seconds: {elapsed:.2f}",
                f"Packets Captured: {self.packet_count}",
                f"Stop Reason: {self.stop_reason}",
                "",
                "=== Sniffer Output ===",
                full_raw_output,
            ]
            if self.error_text:
                content.extend(["", "=== Error ===", self.error_text])
            _write_text(txt_path, "\n".join(content))
            self.result_text_file = txt_path
            self.log(LOG_INFO, f"Text capture saved: {txt_path}")

        if self.args.create_pcap:
            text_source = self.result_text_file or f"{base_path}.txt"
            if not os.path.exists(text_source):
                _write_text(text_source, full_raw_output)
            pcap_path, pcap_err = create_pcap_file(text_source, self.args.wireshark_path)
            if pcap_path:
                self.result_pcap_file = pcap_path
                self.log(LOG_INFO, f"Wireshark PCAP generated: {pcap_path}")
            else:
                self.log(LOG_WARN, f"PCAP conversion skipped/failed: {pcap_err}")

        if self.args.save_json_output and self.args.save_json_separate:
            try:
                json_path = f"{base_path}.json"
                parsed = parse_sniffer_text(
                    full_raw_output,
                    host=self.host,
                    interface=self.args.interface,
                    filter_expr=build_sniffer_filter(self.args),
                    verbose=self.args.verbose,
                )
                parsed["metadata"]["elapsed_seconds"] = round(elapsed, 2)
                parsed["metadata"]["stop_reason"] = self.stop_reason
                parsed["metadata"]["packet_count_requested"] = self.args.count
                _write_text(json_path, json.dumps(parsed, indent=2))
                self.result_json_file = json_path
                self.log(LOG_INFO, f"Structured JSON packets saved: {json_path}")
            except Exception as j_exc:
                self.log(LOG_WARN, f"Could not export JSON: {j_exc}")

    def run(self) -> None:
        self.started_at = time.monotonic()
        try:
            self.connect()
            cmd = build_sniffer_command(self.args)
            self.log(LOG_INFO, f"Executing sniffer command: {cmd}")
            self.channel.send(cmd + "\n")
            time.sleep(0.3)
            self.drain_channel()

            timer_deadline = None
            if self.args.duration_seconds > 0:
                timer_deadline = time.monotonic() + self.args.duration_seconds
                self.log(LOG_INFO, f"Duration timer set for {self.args.duration_seconds}s.")

            last_keepalive = time.monotonic()

            while not self.stop_requested.is_set():
                self.drain_channel()

                if self.coordinator.stop_event.is_set():
                    reason = f"Stopped by {self.coordinator.stop_host} ({self.coordinator.stop_reason})."
                    self.log(LOG_INFO, reason)
                    self.send_ctrl_c(reason)
                    break

                if timer_deadline is not None and time.monotonic() >= timer_deadline:
                    reason = "Stopped by duration timer expiration."
                    self.log(LOG_INFO, reason)
                    self.coordinator.claim_stop(self.host, reason)
                    self.send_ctrl_c(reason)
                    break

                if self.channel and self.channel.exit_status_ready():
                    self.stop_reason = "SSH channel closed remotely."
                    self.log(LOG_INFO, "SSH channel exit status ready.")
                    break

                # Send lightweight newline keepalive every 25 seconds if idle
                if time.monotonic() - last_keepalive >= 25.0:
                    try:
                        self.channel.send("\n")
                    except Exception:
                        pass
                    last_keepalive = time.monotonic()

                time.sleep(0.2)

            self.drain_channel()
            self.cleanup_remote()
            time.sleep(0.4)
            self.drain_channel()
            self.flush_line_buffer()

        except Exception as exc:
            self.error_text = str(exc)
            self.log(LOG_ERROR, f"Session error: {exc}")
        finally:
            self.ended_at = time.monotonic()
            try:
                self.write_output_files()
            except Exception as exc:
                self.log(LOG_ERROR, f"Failed to save output files: {exc}")
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
            self.log(LOG_INFO, f"Session finished. (Packets captured: {self.packet_count})")


class ToolTip:
    def __init__(self, widget: Any, text: str, delay_ms: int = 500, wraplength: int = 360) -> None:
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


FIELD_HELP = {
    "req_button": "Verifies that paramiko and cryptography Python packages are installed, and runs pip install if missing.",
    "wireshark_path": "Path to Wireshark installation folder or text2pcap executable used for generating Wireshark .pcap files.",
    "wireshark_browse": "Browse for Wireshark directory or text2pcap.exe executable.",
    "wireshark_autodetect": "Automatically scan standard system and Program Files locations for Wireshark text2pcap.",
    "convert_pcap_btn": "Select an existing sniffer capture text file (.txt) and convert it to Wireshark .pcap format immediately.",
    "hosts": "Comma-separated list of FortiGate hostnames or IP addresses. Each target firewall runs an independent concurrent capture session.",
    "username": "SSH administrative login username for the FortiGate firewall(s).",
    "auth_method": "Authentication mechanism: Password uses the SSH password field, Private Key uses a .pem or OpenSSH key file.",
    "password": "SSH login password for target firewalls. Kept only in memory and never stored in plaintext.",
    "key_path": "Local path to SSH private key file (e.g. id_rsa, id_ed25519, .pem).",
    "key_browse_button": "Open file dialog to pick an SSH private key file.",
    "key_passphrase": "Passphrase for encrypted private keys. Leave blank if key has no passphrase.",
    "ssh_port": "TCP port for SSH connections (default 22; standard FortiGate direct port).",
    "output_dir": "Directory where text logs, PCAP captures, JSON traces, and run reports are saved.",
    "browse_button": "Browse for output directory.",
    "strict_host_key_checking": "When enabled, prompts with an interactive Host Key Verification Wizard displaying SHA-256 and MD5 fingerprints before connecting to unknown host keys.",
    "known_hosts_manager_button": "View and manage trusted host keys from local known_hosts and ~/.ssh/known_hosts.",
    "interface": "FortiGate interface to sniff (e.g. 'any', 'port1', 'wan1', 'internal'). Default is 'any'.",
    "verbose": (
        "FortiOS Sniffer Verbosity level:\n"
        "1: Packet header\n"
        "2: Packet header + IP data\n"
        "3: Packet header + Ethernet data (hex)\n"
        "4: Packet header + Interface name\n"
        "5: Packet header + IP data + Interface name\n"
        "6: Packet header + Ethernet data + Interface name (Recommended for Wireshark PCAPs)"
    ),
    "count": "Total packet count limit before stopping capture (0 = unlimited). When any host reaches this count, all sibling hosts stop cleanly.",
    "duration_seconds": "Duration safety-net timeout in seconds (0 = unlimited). Stops capture after elapsed time.",
    "file_label": "Label token included in output filenames (e.g. ticket number or short description).",
    "save_text_output": "Save full raw sniffer text output to a timestamped .txt file.",
    "create_pcap": "Automatically convert hex packet dumps into a Wireshark .pcap file using text2pcap.",
    "save_json_output": "Automatically parse packet headers and hex dumps into structured JSON files.",
    "save_json_separate": "Save individual per-host JSON packet files.",
    "save_json_combined": "Save an aggregated combined multi-host JSON file when running multiple target firewalls.",
    "protocol": "Protocol filter (e.g. 'tcp', 'udp', 'icmp', 'arp'). Leave blank for all protocols.",
    "host": "Filter on host IP address (matches either source or destination).",
    "src_host": "Filter only on source host IP address.",
    "dst_host": "Filter only on destination host IP address.",
    "port": "Filter on TCP/UDP port (matches either source or destination).",
    "src_port": "Filter only on source port.",
    "dst_port": "Filter only on destination port.",
    "net": "Filter on IP subnet / CIDR (e.g. 192.168.1.0/24).",
    "src_net": "Filter only on source subnet / CIDR.",
    "dst_net": "Filter only on destination subnet / CIDR.",
    "custom_filter": "Raw BPF filter expression passed directly to FortiOS (e.g. 'port 80 or port 443').",
    "start_button": "Start SSH packet sniffer sessions across all target firewalls.",
    "stop_button": "Interrupt running sniffer sessions (sends Ctrl+C, executes remote stop cleanup, and writes output files).",
    "clear_log_button": "Clear current console log view.",
    "save_profile_button": "Save all session settings, targets, filters, credentials, and Wireshark paths into a 100% AES-256-GCM encrypted profile.",
    "load_profile_button": "Load and decrypt an encrypted profile using your master passphrase.",
    "export_json_button": "Export currently visible console log and packet traces into structured JSON, respecting active live output filters.",
    "regex_filter": "Advanced real-time boolean regex search filter (AND, OR, NOT, parentheses, quotes). E.g. 'wan1 AND (10.0.0.1 OR 10.0.0.2) AND NOT syn'.",
    "show_matching_button": "Filter console output to display only lines matching the boolean regex filter.",
    "hide_matching_button": "Filter console output to hide lines matching the boolean regex filter.",
    "clear_filter_button": "Clear live output filter and restore all lines.",
}


VERBOSE_CHOICES = [
    ("1", "1 — Packet header"),
    ("2", "2 — Header + IP payload"),
    ("3", "3 — Header + Ethernet payload (Hex)"),
    ("4", "4 — Header + Interface name"),
    ("5", "5 — Header + IP payload + Interface name"),
    ("6", "6 — Header + Ethernet payload + Interface name (Best for PCAP)"),
]


class SnifferSshGui:
    """Tkinter-based GUI for FortiGate SSH Standalone Packet Sniffer v2."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Packet Sniffer SSH Standalone (v2)")
        self.vars: dict[str, Any] = {}
        self.sessions: list[SshSnifferSession] = []
        self.threads: list[threading.Thread] = []
        self.manager_thread: threading.Thread | None = None
        self.install_thread: threading.Thread | None = None
        self.log_queue: queue.Queue = queue.Queue()
        self.host_key_queue: queue.Queue = queue.Queue()
        self.report_lines: list[str] = []

        self.current_regex_filter: BooleanRegexFilter | None = None
        self.filter_mode: str | None = None
        self.all_log_lines: list[tuple[str, str, str]] = []

        self.start_button = None
        self.stop_button = None
        self.req_button = None
        self.wireshark_status_label = None

        self.build_ui()
        self.drain_log_queue()
        self.root.after(200, self.check_startup_status)

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

        def _on_canvas_configure(event):
            self.canvas.itemconfig(self.content_window, width=event.width)
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        self.canvas.bind("<Configure>", _on_canvas_configure)
        self.content_frame.bind("<Configure>", lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # --- Frame 0: Requirements & Wireshark Integration ---
        req_frame = ttk.LabelFrame(self.content_frame, text="Requirements & Wireshark PCAP Integration")
        req_frame.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        req_frame.columnconfigure(1, weight=1)

        row0_f = ttk.Frame(req_frame)
        row0_f.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=2)
        self.req_button = ttk.Button(row0_f, text="Check / Install Requirements", command=self.install_requirements_clicked)
        self.req_button.pack(side="left", padx=(0, 8))
        ToolTip(self.req_button, FIELD_HELP["req_button"])

        self.req_status = ttk.Label(row0_f, text="Checking Python packages...")
        self.req_status.pack(side="left", padx=(0, 12))

        ttk.Label(req_frame, text="Wireshark / text2pcap Path:").grid(row=1, column=0, sticky="w", padx=4, pady=2)
        ws_row = ttk.Frame(req_frame)
        ws_row.grid(row=1, column=1, sticky="ew", padx=4, pady=2)
        ws_row.columnconfigure(0, weight=1)

        init_ws = find_text2pcap() or ""
        self.ws_entry = ttk.Entry(ws_row, textvariable=self.str_var("wireshark_path", init_ws), width=42)
        self.ws_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ToolTip(self.ws_entry, FIELD_HELP["wireshark_path"])

        browse_ws_btn = ttk.Button(ws_row, text="Browse", command=self.browse_wireshark_path)
        browse_ws_btn.pack(side="left", padx=(0, 6))
        ToolTip(browse_ws_btn, FIELD_HELP["wireshark_browse"])

        detect_ws_btn = ttk.Button(ws_row, text="Auto-Detect", command=self.autodetect_wireshark)
        detect_ws_btn.pack(side="left", padx=(0, 6))
        ToolTip(detect_ws_btn, FIELD_HELP["wireshark_autodetect"])

        convert_log_btn = ttk.Button(ws_row, text="Convert Log to PCAP...", command=self.convert_log_to_pcap_dialog)
        convert_log_btn.pack(side="left", padx=(0, 4))
        ToolTip(convert_log_btn, FIELD_HELP["convert_pcap_btn"])

        self.wireshark_status_label = ttk.Label(req_frame, text="", font=("", 9))
        self.wireshark_status_label.grid(row=2, column=1, sticky="w", padx=4, pady=1)

        # --- Frame 1: SSH Connection ---
        conn = ttk.LabelFrame(self.content_frame, text="SSH Connection")
        conn.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        conn.columnconfigure(1, weight=1)

        self.add_labeled_entry(conn, 0, "Hostnames or IPs (comma-separated)", "hosts", width=42, tooltip=FIELD_HELP["hosts"])
        self.add_labeled_entry(conn, 1, "SSH Username", "username", width=42, tooltip=FIELD_HELP["username"])

        ttk.Label(conn, text="Authentication Method").grid(row=2, column=0, sticky="w", padx=4, pady=2)
        auth_frame = ttk.Frame(conn)
        auth_frame.grid(row=2, column=1, sticky="w", padx=4, pady=2)
        auth_method_var = self.str_var("auth_method", "password")
        pwd_radio = ttk.Radiobutton(auth_frame, text="Password", variable=auth_method_var, value="password", command=self.update_auth_method_state)
        pwd_radio.pack(side="left", padx=(0, 20))
        key_radio = ttk.Radiobutton(auth_frame, text="Private Key", variable=auth_method_var, value="key", command=self.update_auth_method_state)
        key_radio.pack(side="left")
        ToolTip(pwd_radio, FIELD_HELP["auth_method"])
        ToolTip(key_radio, FIELD_HELP["auth_method"])

        self.password_entry = self.add_labeled_entry(conn, 3, "SSH Password", "password", show="*", width=42, tooltip=FIELD_HELP["password"])

        ttk.Label(conn, text="Private Key File").grid(row=4, column=0, sticky="w", padx=4, pady=2)
        key_frame = ttk.Frame(conn)
        key_frame.grid(row=4, column=1, sticky="w", padx=4, pady=2)
        self.key_path_entry = ttk.Entry(key_frame, textvariable=self.str_var("key_path"), width=42)
        self.key_path_entry.pack(side="left", padx=(0, 6))
        self.key_browse_button = ttk.Button(key_frame, text="Browse", command=self.browse_key_file)
        self.key_browse_button.pack(side="left")
        ToolTip(self.key_path_entry, FIELD_HELP["key_path"])
        ToolTip(self.key_browse_button, FIELD_HELP["key_browse_button"])

        self.key_passphrase_entry = self.add_labeled_entry(conn, 5, "Key Passphrase (if encrypted)", "key_passphrase", show="*", width=42, tooltip=FIELD_HELP["key_passphrase"])
        self.add_labeled_entry(conn, 6, "SSH Port", "ssh_port", str(DEFAULT_SSH_PORT), width=10, tooltip=FIELD_HELP["ssh_port"])

        ttk.Label(conn, text="Output Directory").grid(row=7, column=0, sticky="w", padx=4, pady=2)
        out_frame = ttk.Frame(conn)
        out_frame.grid(row=7, column=1, sticky="w", padx=4, pady=2)
        out_entry = ttk.Entry(out_frame, textvariable=self.str_var("output_dir", DEFAULT_OUTPUT_DIR), width=42)
        out_entry.pack(side="left", padx=(0, 6))
        browse_dir_btn = ttk.Button(out_frame, text="Browse", command=self.browse_output_dir)
        browse_dir_btn.pack(side="left")
        ToolTip(out_entry, FIELD_HELP["output_dir"])
        ToolTip(browse_dir_btn, FIELD_HELP["browse_button"])

        strict_cb = ttk.Checkbutton(conn, text="Strict Host-Key Checking", variable=self.bool_var("strict_host_key_checking", True))
        strict_cb.grid(row=8, column=0, sticky="w", padx=4, pady=2)
        ToolTip(strict_cb, FIELD_HELP["strict_host_key_checking"])

        known_hosts_btn = ttk.Button(conn, text="Known Hosts Manager", command=self.open_known_hosts_manager)
        known_hosts_btn.grid(row=8, column=1, sticky="w", padx=4, pady=2)
        ToolTip(known_hosts_btn, FIELD_HELP["known_hosts_manager_button"])

        self.update_auth_method_state()

        # --- Frame 2: Sniffer & Output Options ---
        opts = ttk.LabelFrame(self.content_frame, text="Sniffer & Output Options")
        opts.grid(row=2, column=0, sticky="ew", padx=4, pady=4)

        # Row 0: Interface
        r0 = ttk.Frame(opts)
        r0.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        iface_lbl = ttk.Label(r0, text="Interface", width=14, anchor="w")
        iface_lbl.pack(side="left", padx=(0, 4))
        iface_entry = ttk.Entry(r0, textvariable=self.str_var("interface", "any"), width=20)
        iface_entry.pack(side="left")
        ToolTip(iface_lbl, FIELD_HELP["interface"])
        ToolTip(iface_entry, FIELD_HELP["interface"])

        # Row 1: Verbose Level
        r1 = ttk.Frame(opts)
        r1.grid(row=1, column=0, sticky="w", padx=4, pady=2)
        v_lbl = ttk.Label(r1, text="Verbose Level", width=14, anchor="w")
        v_lbl.pack(side="left", padx=(0, 4))
        self.verbose_var = tk.StringVar(value="6 — Header + Ethernet payload + Interface name (Best for PCAP)")
        self.vars["verbose"] = self.verbose_var
        v_combo = ttk.Combobox(r1, textvariable=self.verbose_var, values=[desc for _, desc in VERBOSE_CHOICES], width=64, state="readonly")
        v_combo.pack(side="left")
        ToolTip(v_lbl, FIELD_HELP["verbose"])
        ToolTip(v_combo, FIELD_HELP["verbose"])

        # Row 2: Packet Count & Duration
        r2 = ttk.Frame(opts)
        r2.grid(row=2, column=0, sticky="w", padx=4, pady=2)
        cnt_lbl = ttk.Label(r2, text="Packet Count", width=14, anchor="w")
        cnt_lbl.pack(side="left", padx=(0, 4))
        cnt_entry = ttk.Entry(r2, textvariable=self.str_var("count", "300"), width=12)
        cnt_entry.pack(side="left", padx=(0, 20))
        ToolTip(cnt_lbl, FIELD_HELP["count"])
        ToolTip(cnt_entry, FIELD_HELP["count"])

        dur_lbl = ttk.Label(r2, text="Duration (s)", width=12, anchor="w")
        dur_lbl.pack(side="left", padx=(0, 4))
        dur_entry = ttk.Entry(r2, textvariable=self.str_var("duration_seconds", "1800"), width=12)
        dur_entry.pack(side="left")
        ToolTip(dur_lbl, FIELD_HELP["duration_seconds"])
        ToolTip(dur_entry, FIELD_HELP["duration_seconds"])

        # Row 3: Filename Label
        r3 = ttk.Frame(opts)
        r3.grid(row=3, column=0, sticky="w", padx=4, pady=2)
        lbl_lbl = ttk.Label(r3, text="Filename Label", width=14, anchor="w")
        lbl_lbl.pack(side="left", padx=(0, 4))
        lbl_entry = ttk.Entry(r3, textvariable=self.str_var("file_label", "run"), width=20)
        lbl_entry.pack(side="left")
        ToolTip(lbl_lbl, FIELD_HELP["file_label"])
        ToolTip(lbl_entry, FIELD_HELP["file_label"])

        # Row 4: Output Formats Checkboxes
        r4 = ttk.Frame(opts)
        r4.grid(row=4, column=0, sticky="w", padx=4, pady=(4, 2))

        txt_cb = ttk.Checkbutton(r4, text="Save Text Output (.txt)", variable=self.bool_var("save_text_output", True))
        txt_cb.pack(side="left", padx=(0, 16))
        ToolTip(txt_cb, FIELD_HELP["save_text_output"])

        pcap_cb = ttk.Checkbutton(r4, text="Create PCAP (.pcap)", variable=self.bool_var("create_pcap", True))
        pcap_cb.pack(side="left", padx=(0, 16))
        ToolTip(pcap_cb, FIELD_HELP["create_pcap"])

        self.json_out_cb = ttk.Checkbutton(
            r4, text="Save JSON (.json)", variable=self.bool_var("save_json_output", True), command=self.update_json_output_state
        )
        self.json_out_cb.pack(side="left", padx=(0, 16))
        ToolTip(self.json_out_cb, FIELD_HELP["save_json_output"])

        self.json_sep_cb = ttk.Checkbutton(r4, text="Separate JSON", variable=self.bool_var("save_json_separate", True))
        self.json_sep_cb.pack(side="left", padx=(0, 16))
        ToolTip(self.json_sep_cb, FIELD_HELP["save_json_separate"])

        self.json_comb_cb = ttk.Checkbutton(r4, text="Combined JSON", variable=self.bool_var("save_json_combined", True))
        self.json_comb_cb.pack(side="left")
        ToolTip(self.json_comb_cb, FIELD_HELP["save_json_combined"])

        self.update_json_output_state()

        # --- Frame 3: Traffic Filter Builder ---
        filters = ttk.LabelFrame(self.content_frame, text="Traffic Filter Builder (BPF syntax)")
        filters.grid(row=3, column=0, sticky="ew", padx=4, pady=4)
        filters.columnconfigure(1, weight=1)
        filters.columnconfigure(3, weight=1)
        filters.columnconfigure(5, weight=1)

        ttk.Label(filters, text="Protocol:").grid(row=0, column=0, sticky="w", padx=(4, 6), pady=2)
        proto_entry = ttk.Entry(filters, textvariable=self.str_var("protocol"), width=16)
        proto_entry.grid(row=0, column=1, sticky="w", padx=(0, 4), pady=2)
        ToolTip(proto_entry, FIELD_HELP["protocol"])

        # Host / Src Host / Dst Host
        ttk.Label(filters, text="Host:").grid(row=1, column=0, sticky="w", padx=(4, 6), pady=2)
        h_entry = ttk.Entry(filters, textvariable=self.str_var("host"), width=18)
        h_entry.grid(row=1, column=1, sticky="w", padx=(0, 4), pady=2)
        ToolTip(h_entry, FIELD_HELP["host"])

        ttk.Label(filters, text="Src Host:").grid(row=1, column=2, sticky="w", padx=(4, 6), pady=2)
        sh_entry = ttk.Entry(filters, textvariable=self.str_var("src_host"), width=18)
        sh_entry.grid(row=1, column=3, sticky="w", padx=(0, 4), pady=2)
        ToolTip(sh_entry, FIELD_HELP["src_host"])

        ttk.Label(filters, text="Dst Host:").grid(row=1, column=4, sticky="w", padx=(4, 6), pady=2)
        dh_entry = ttk.Entry(filters, textvariable=self.str_var("dst_host"), width=18)
        dh_entry.grid(row=1, column=5, sticky="w", padx=(0, 4), pady=2)
        ToolTip(dh_entry, FIELD_HELP["dst_host"])

        # Port / Src Port / Dst Port
        ttk.Label(filters, text="Port:").grid(row=2, column=0, sticky="w", padx=(4, 6), pady=2)
        p_entry = ttk.Entry(filters, textvariable=self.str_var("port"), width=18)
        p_entry.grid(row=2, column=1, sticky="w", padx=(0, 4), pady=2)
        ToolTip(p_entry, FIELD_HELP["port"])

        ttk.Label(filters, text="Src Port:").grid(row=2, column=2, sticky="w", padx=(4, 6), pady=2)
        sp_entry = ttk.Entry(filters, textvariable=self.str_var("src_port"), width=18)
        sp_entry.grid(row=2, column=3, sticky="w", padx=(0, 4), pady=2)
        ToolTip(sp_entry, FIELD_HELP["src_port"])

        ttk.Label(filters, text="Dst Port:").grid(row=2, column=4, sticky="w", padx=(4, 6), pady=2)
        dp_entry = ttk.Entry(filters, textvariable=self.str_var("dst_port"), width=18)
        dp_entry.grid(row=2, column=5, sticky="w", padx=(0, 4), pady=2)
        ToolTip(dp_entry, FIELD_HELP["dst_port"])

        # Net / Src Net / Dst Net
        ttk.Label(filters, text="Net/CIDR:").grid(row=3, column=0, sticky="w", padx=(4, 6), pady=2)
        n_entry = ttk.Entry(filters, textvariable=self.str_var("net"), width=18)
        n_entry.grid(row=3, column=1, sticky="w", padx=(0, 4), pady=2)
        ToolTip(n_entry, FIELD_HELP["net"])

        ttk.Label(filters, text="Src Net:").grid(row=3, column=2, sticky="w", padx=(4, 6), pady=2)
        sn_entry = ttk.Entry(filters, textvariable=self.str_var("src_net"), width=18)
        sn_entry.grid(row=3, column=3, sticky="w", padx=(0, 4), pady=2)
        ToolTip(sn_entry, FIELD_HELP["src_net"])

        ttk.Label(filters, text="Dst Net:").grid(row=3, column=4, sticky="w", padx=(4, 6), pady=2)
        dn_entry = ttk.Entry(filters, textvariable=self.str_var("dst_net"), width=18)
        dn_entry.grid(row=3, column=5, sticky="w", padx=(0, 4), pady=2)
        ToolTip(dn_entry, FIELD_HELP["dst_net"])

        # Custom Raw Filter
        ttk.Label(filters, text="Custom Filter:").grid(row=4, column=0, sticky="w", padx=(4, 6), pady=2)
        cf_entry = ttk.Entry(filters, textvariable=self.str_var("custom_filter"), width=60)
        cf_entry.grid(row=4, column=1, columnspan=5, sticky="ew", padx=(0, 4), pady=2)
        ToolTip(cf_entry, FIELD_HELP["custom_filter"])

        # --- Frame 4: Actions & Buttons ---
        actions = ttk.Frame(self.content_frame)
        actions.grid(row=4, column=0, sticky="ew", padx=4, pady=4)
        actions.columnconfigure(0, weight=1)

        b_row1 = ttk.Frame(actions)
        b_row1.grid(row=0, column=0, sticky="ew")
        self.start_button = ttk.Button(b_row1, text="Start Sniffer", command=self.start)
        self.start_button.grid(row=0, column=0, padx=4, pady=4)
        ToolTip(self.start_button, FIELD_HELP["start_button"])

        self.stop_button = ttk.Button(b_row1, text="Stop Active Capture", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=4, pady=4)
        ToolTip(self.stop_button, FIELD_HELP["stop_button"])

        clear_btn = ttk.Button(b_row1, text="Clear Log", command=self.clear_log)
        clear_btn.grid(row=0, column=2, padx=4, pady=4)
        ToolTip(clear_btn, FIELD_HELP["clear_log_button"])

        b_row2 = ttk.Frame(actions)
        b_row2.grid(row=1, column=0, sticky="ew")
        save_prof_btn = ttk.Button(b_row2, text="Save Profile", command=self.save_profile_clicked)
        save_prof_btn.grid(row=0, column=0, padx=4, pady=4)
        ToolTip(save_prof_btn, FIELD_HELP["save_profile_button"])

        load_prof_btn = ttk.Button(b_row2, text="Load Profile", command=self.load_profile_clicked)
        load_prof_btn.grid(row=0, column=1, padx=4, pady=4)
        ToolTip(load_prof_btn, FIELD_HELP["load_profile_button"])

        export_json_btn = ttk.Button(b_row2, text="Export JSON", command=self.export_json_clicked)
        export_json_btn.grid(row=0, column=2, padx=4, pady=4)
        ToolTip(export_json_btn, FIELD_HELP["export_json_button"])

        # --- Frame 5: Live Output Advanced Filter (Boolean & Regex) ---
        filter_frame = ttk.LabelFrame(self.content_frame, text="Live Output Advanced Filter — Boolean & Regex (Optional)")
        filter_frame.grid(row=5, column=0, sticky="ew", padx=4, pady=4)
        filter_frame.columnconfigure(1, weight=1)

        f_lbl = ttk.Label(filter_frame, text="Filter Expression:")
        f_lbl.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        f_entry = ttk.Entry(filter_frame, textvariable=self.str_var("regex_filter_pattern", ""), width=60)
        f_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=2)
        f_entry.bind("<Return>", lambda _e: self.show_regex_matching())
        ToolTip(f_lbl, FIELD_HELP["regex_filter"])
        ToolTip(f_entry, FIELD_HELP["regex_filter"])

        show_m_btn = ttk.Button(filter_frame, text="Show Matching", command=self.show_regex_matching)
        show_m_btn.grid(row=0, column=2, padx=4, pady=2)
        ToolTip(show_m_btn, FIELD_HELP["show_matching_button"])

        hide_m_btn = ttk.Button(filter_frame, text="Hide Matching", command=self.hide_regex_matching)
        hide_m_btn.grid(row=0, column=3, padx=4, pady=2)
        ToolTip(hide_m_btn, FIELD_HELP["hide_matching_button"])

        clear_f_btn = ttk.Button(filter_frame, text="Clear Filter", command=self.clear_regex_filter)
        clear_f_btn.grid(row=0, column=4, padx=4, pady=2)
        ToolTip(clear_f_btn, FIELD_HELP["clear_filter_button"])

        # --- Frame 6: Live Dark Console Log Output ---
        log_frame = ttk.LabelFrame(self.content_frame, text="Live SSH Output / Sniffer Log")
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

        self.log_text.tag_configure("info", foreground="#e0e0e0")
        self.log_text.tag_configure("warning", foreground="#ffd740")
        self.log_text.tag_configure("error", foreground="#ff5252")

        host_colors = [
            "#00e5ff",  # Bright Cyan
            "#69f0ae",  # Mint Green
            "#ffd740",  # Bright Amber
            "#ff80ab",  # Pink / Magenta
            "#b388ff",  # Light Violet
            "#ffab40",  # Bright Orange
            "#80d8ff",  # Sky Blue
            "#eeff41",  # Lime Yellow
            "#ea80fc",  # Light Fuchsia
            "#1de9b6",  # Teal Accent
        ]
        self.host_colors: dict[str, str] = {}
        self.host_color_index = 0
        self.host_colors_list = host_colors

    def check_startup_status(self) -> None:
        missing = missing_requirements()
        if missing:
            self.req_status.configure(text="Missing required package(s): " + ", ".join(missing), foreground="#c62828")
            self.logger(LOG_WARN, "Missing required Python package(s): " + ", ".join(missing))
        else:
            load_optional_modules()
            self.req_status.configure(text="Python requirements: OK (paramiko & cryptography)", foreground="#2e7d32")

        self.verify_wireshark_path(update_status_only=True)

    def verify_wireshark_path(self, update_status_only: bool = False) -> bool:
        current_path = self.vars.get("wireshark_path", tk.StringVar()).get()
        found = find_text2pcap(current_path)
        if found:
            self.vars["wireshark_path"].set(found)
            if self.wireshark_status_label:
                self.wireshark_status_label.configure(
                    text=f"✓ Wireshark text2pcap detected: {found}",
                    foreground="#2e7d32",
                )
            return True
        else:
            if self.wireshark_status_label:
                self.wireshark_status_label.configure(
                    text="⚠ Wireshark text2pcap not found. Specify folder above or install Wireshark to enable PCAP creation.",
                    foreground="#d32f2f",
                )
            return False

    def autodetect_wireshark(self) -> None:
        found = find_text2pcap()
        if found:
            self.vars["wireshark_path"].set(found)
            self.verify_wireshark_path()
            messagebox.showinfo("Wireshark Detected", f"Wireshark text2pcap detected:\n{found}")
            self.logger(LOG_INFO, f"Wireshark text2pcap detected: {found}")
        else:
            messagebox.showwarning(
                "Wireshark Not Found",
                "text2pcap was not found in standard system directories.\n"
                "Please use Browse to select your Wireshark installation folder.",
            )

    def browse_wireshark_path(self) -> None:
        init_dir = os.environ.get("ProgramFiles", "C:\\Program Files")
        selected = filedialog.askdirectory(parent=self.root, title="Select Wireshark Installation Folder", initialdir=init_dir)
        if selected:
            found = find_text2pcap(selected)
            if found:
                self.vars["wireshark_path"].set(found)
                self.verify_wireshark_path()
                self.logger(LOG_INFO, f"Configured Wireshark text2pcap: {found}")
            else:
                self.vars["wireshark_path"].set(selected)
                self.verify_wireshark_path()
                messagebox.showwarning("File Not Found", f"text2pcap.exe was not found in:\n{selected}")

    def convert_log_to_pcap_dialog(self) -> None:
        initial_dir = self.vars.get("output_dir", tk.StringVar()).get() or DEFAULT_OUTPUT_DIR
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="Select FortiOS Sniffer Text Output to Convert to PCAP",
            initialdir=initial_dir,
            filetypes=[("Text Log (*.txt)", "*.txt"), ("All Files", "*.*")],
        )
        if not selected:
            return

        ws_exe = find_text2pcap(self.vars.get("wireshark_path", tk.StringVar()).get())
        if not ws_exe:
            messagebox.showerror(
                "text2pcap Required",
                "Wireshark text2pcap is not detected. Please configure Wireshark path first.",
            )
            return

        pcap_path, err = create_pcap_file(selected, ws_exe)
        if pcap_path:
            messagebox.showinfo("PCAP Created", f"PCAP conversion successful!\nSaved to:\n{pcap_path}")
            self.logger(LOG_INFO, f"Manually converted text log to PCAP: {pcap_path}")
        else:
            messagebox.showerror("PCAP Conversion Error", f"Failed to create PCAP:\n{err}")
            self.logger(LOG_ERROR, f"PCAP conversion error on {selected}: {err}")

    def install_requirements_clicked(self) -> None:
        if self.install_thread and self.install_thread.is_alive():
            return
        if self.req_button:
            self.req_button.configure(state="disabled")
        self.req_status.configure(text="Checking/installing Python packages...", foreground="#1976d2")

        def worker():
            success = install_requirements(lambda lvl, msg: self.logger(lvl, msg))
            def done():
                if success:
                    self.req_status.configure(text="Python requirements: OK (paramiko & cryptography)", foreground="#2e7d32")
                else:
                    self.req_status.configure(text="Requirement installation failed. See log.", foreground="#c62828")
                if self.req_button:
                    self.req_button.configure(state="normal")
            self.root.after(0, done)

        self.install_thread = threading.Thread(target=worker, daemon=True)
        self.install_thread.start()

    def browse_output_dir(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.vars["output_dir"].get() or DEFAULT_OUTPUT_DIR)
        if selected:
            self.vars["output_dir"].set(selected)

    def browse_key_file(self) -> None:
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        initial_dir = ssh_dir if os.path.isdir(ssh_dir) else SCRIPT_DIR
        selected = filedialog.askopenfilename(initialdir=initial_dir, title="Select Private Key File")
        if selected:
            self.vars["key_path"].set(selected)

    def open_known_hosts_manager(self) -> None:
        show_known_hosts_manager(self.root)

    def update_auth_method_state(self) -> None:
        is_key = self.vars["auth_method"].get() == "key"
        self.password_entry.configure(state="disabled" if is_key else "normal")
        self.key_path_entry.configure(state="normal" if is_key else "disabled")
        self.key_browse_button.configure(state="normal" if is_key else "disabled")
        self.key_passphrase_entry.configure(state="normal" if is_key else "disabled")

    def update_json_output_state(self) -> None:
        is_json = bool(self.vars.get("save_json_output", tk.BooleanVar(value=True)).get())
        state = "normal" if is_json else "disabled"
        if hasattr(self, "json_sep_cb") and self.json_sep_cb:
            self.json_sep_cb.configure(state=state)
        if hasattr(self, "json_comb_cb") and self.json_comb_cb:
            self.json_comb_cb.configure(state=state)

    def clear_log(self) -> None:
        self.log_text.delete("1.0", "end")
        self.all_log_lines = []

    def logger(self, level: str, message: str, kind: str = LOG_KIND_PROGRAM) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        if kind != LOG_KIND_SNIFFER:
            self.report_lines.append(f"{stamp} ({level}) {message}")
        self.log_queue.put((level, message, stamp))

    def check_host_key_queue(self) -> None:
        try:
            while True:
                req = self.host_key_queue.get_nowait()
                HostKeyWizardDialog(self.root, req)
        except queue.Empty:
            pass

    def drain_log_queue(self) -> None:
        self.check_host_key_queue()
        try:
            while True:
                level, message, stamp = self.log_queue.get_nowait()
                self.all_log_lines.append((level, message, stamp))

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

    def _insert_log_line(self, level: str, message: str, stamp: str) -> None:
        host_color_tag = None
        if message.startswith("[") and "]" in message:
            host_part = message.split("]")[0].strip("[")
            if host_part not in self.host_colors:
                if self.host_color_index < len(self.host_colors_list):
                    color = self.host_colors_list[self.host_color_index]
                    self.host_colors[host_part] = color
                    self.log_text.tag_configure(f"host_{host_part}", foreground=color)
                    self.host_color_index += 1
                else:
                    color = self.host_colors_list[len(self.host_colors) % len(self.host_colors_list)]
                    self.host_colors[host_part] = color
                    self.log_text.tag_configure(f"host_{host_part}", foreground=color)
            host_color_tag = f"host_{host_part}"

        level_tag = level.lower() if level.lower() in ["error", "warning", "info"] else "info"
        self.log_text.insert("end", f"{stamp} ({level}) {message}\n")

        line_start = self.log_text.index("end-2c linestart")
        line_end = self.log_text.index("end-1c")

        if host_color_tag:
            self.log_text.tag_add(host_color_tag, line_start, line_end)
        else:
            self.log_text.tag_add(level_tag, line_start, line_end)

    def redraw_filtered_log(self) -> None:
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        for level, message, stamp in self.all_log_lines:
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
        self.logger(LOG_INFO, f"Live output filter applied ({mode} matching): {pattern}")
        self.redraw_filtered_log()

    def show_regex_matching(self) -> None:
        self._apply_filter_mode("show")

    def hide_regex_matching(self) -> None:
        self._apply_filter_mode("hide")

    def clear_regex_filter(self) -> None:
        self.current_regex_filter = None
        self.filter_mode = None
        self.vars.get("regex_filter_pattern", tk.StringVar()).set("")
        self.redraw_filtered_log()
        self.logger(LOG_INFO, "Filter cleared — all lines visible.")

    def export_json_clicked(self) -> None:
        if not self.all_log_lines:
            messagebox.showwarning("No Data", "No log output available to export.")
            return

        default_name = f"sniffer_export_{timestamp_token()}.json"
        initial_dir = self.vars.get("output_dir", tk.StringVar()).get() or DEFAULT_OUTPUT_DIR

        file_path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export Sniffer Logs to JSON",
            initialdir=initial_dir,
            initialfile=default_name,
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not file_path:
            return

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
            structured_data = parse_sniffer_text(full_text)
            if self.current_regex_filter and self.filter_mode:
                structured_data["metadata"]["live_filter_applied"] = self.vars.get("regex_filter_pattern", tk.StringVar()).get().strip()
                structured_data["metadata"]["live_filter_mode"] = self.filter_mode
            _write_text(file_path, json.dumps(structured_data, indent=2))
            count = structured_data["metadata"]["total_packets"]
            self.logger(LOG_INFO, f"Exported {count} structured packet(s) to JSON: {file_path}")
            messagebox.showinfo("Export Successful", f"Successfully exported {count} packet(s) to:\n{file_path}")
        except Exception as exc:
            messagebox.showerror("Export Error", f"Failed to export JSON:\n{exc}")

    def save_profile_clicked(self) -> None:
        try:
            args = self.collect_args()
        except Exception as exc:
            messagebox.showerror("Save Profile Error", f"Cannot save profile: {exc}")
            return

        dialog = SaveProfilePassphraseDialog(self.root)
        if not dialog.result:
            return
        passphrase = dialog.result

        selected = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Encrypted Profile (*.json)", "*.json"), ("All Files", "*.*")],
            initialfile=f"sniffer_profile_{args.file_label}.json",
        )
        if not selected:
            return

        try:
            save_session_profile(args, selected, passphrase=passphrase)
            messagebox.showinfo("Profile Saved", f"Profile successfully encrypted and saved to:\n{selected}")
            self.logger(LOG_INFO, f"Encrypted sniffer profile saved: {selected}")
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Error saving profile: {exc}")

    def load_profile_clicked(self) -> None:
        selected = filedialog.askopenfilename(
            filetypes=[("Encrypted Profile (*.json)", "*.json"), ("All Files", "*.*")],
            initialdir=SCRIPT_DIR,
        )
        if not selected:
            return

        try:
            raw_data = json.loads(_read_text(selected))
        except Exception as exc:
            messagebox.showerror("Load Failed", f"Error reading profile file: {exc}")
            return

        is_encrypted = isinstance(raw_data, dict) and (
            "ciphertext" in raw_data or raw_data.get("format") == "fgt_sniffer_encrypted_profile"
        )

        if is_encrypted:
            while True:
                unlock_dlg = UnlockProfilePassphraseDialog(self.root, selected)
                if not unlock_dlg.result:
                    return
                passphrase = unlock_dlg.result
                try:
                    profile_data = load_session_profile(selected, passphrase=passphrase)
                    self._apply_profile(profile_data)
                    messagebox.showinfo("Profile Loaded", f"Profile loaded successfully from:\n{selected}")
                    self.logger(LOG_INFO, f"Encrypted profile loaded: {selected}")
                    return
                except Exception as exc:
                    messagebox.showerror("Decryption Failed", f"Could not decrypt profile:\n{exc}\nPlease check passphrase.")
        else:
            try:
                profile_data = load_session_profile(selected, passphrase="")
                self._apply_profile(profile_data)
                messagebox.showinfo("Profile Loaded", f"Profile loaded from:\n{selected}")
                self.logger(LOG_INFO, f"Session profile loaded: {selected}")
            except Exception as exc:
                messagebox.showerror("Load Failed", f"Error loading profile: {exc}")

    def _apply_profile(self, profile_data: dict) -> None:
        self.vars["hosts"].set(",".join(profile_data.get("hosts", [])))
        self.vars["username"].set(profile_data.get("username", ""))
        self.vars["auth_method"].set(profile_data.get("auth_method", "password"))
        self.vars["password"].set(profile_data.get("password", "") or "")
        self.vars["key_path"].set(profile_data.get("key_path", "") or "")
        self.vars["key_passphrase"].set(profile_data.get("key_passphrase", "") or "")
        self.vars["ssh_port"].set(str(profile_data.get("ssh_port", DEFAULT_SSH_PORT)))
        self.vars["output_dir"].set(profile_data.get("output_dir", DEFAULT_OUTPUT_DIR))
        self.vars["wireshark_path"].set(profile_data.get("wireshark_path", ""))
        self.vars["strict_host_key_checking"].set(profile_data.get("strict_host_key_checking", True))

        self.vars["interface"].set(profile_data.get("interface", "any"))
        v_num = str(profile_data.get("verbose", 6))
        for num, desc in VERBOSE_CHOICES:
            if num == v_num:
                self.verbose_var.set(desc)
                break

        self.vars["count"].set(str(profile_data.get("count", 300)))
        self.vars["duration_seconds"].set(str(profile_data.get("duration_seconds", 1800)))
        self.vars["file_label"].set(profile_data.get("file_label", "run"))

        self.vars["protocol"].set(profile_data.get("protocol", ""))
        self.vars["host"].set(profile_data.get("host", ""))
        self.vars["src_host"].set(profile_data.get("src_host", ""))
        self.vars["dst_host"].set(profile_data.get("dst_host", ""))
        self.vars["port"].set(profile_data.get("port", ""))
        self.vars["src_port"].set(profile_data.get("src_port", ""))
        self.vars["dst_port"].set(profile_data.get("dst_port", ""))
        self.vars["net"].set(profile_data.get("net", ""))
        self.vars["src_net"].set(profile_data.get("src_net", ""))
        self.vars["dst_net"].set(profile_data.get("dst_net", ""))
        self.vars["custom_filter"].set(profile_data.get("custom_filter", ""))

        self.vars["save_text_output"].set(profile_data.get("save_text_output", True))
        self.vars["create_pcap"].set(profile_data.get("create_pcap", True))
        self.vars["save_json_output"].set(profile_data.get("save_json_output", True))
        self.vars["save_json_separate"].set(profile_data.get("save_json_separate", True))
        self.vars["save_json_combined"].set(profile_data.get("save_json_combined", True))

        self.update_auth_method_state()
        self.update_json_output_state()
        self.verify_wireshark_path(update_status_only=True)

    def collect_args(self) -> SnifferSshArgs:
        hosts = parse_target_list(self.vars["hosts"].get())
        username = self.vars["username"].get().strip()
        auth_method = self.vars["auth_method"].get()
        password = self.vars["password"].get()
        key_path = self.vars["key_path"].get().strip()
        key_passphrase = self.vars["key_passphrase"].get()

        if not hosts:
            raise ValidationError("At least one target IP or hostname is required.")
        for h in hosts:
            validate_target(h)
        if not username:
            raise ValidationError("SSH Username is required.")
        if auth_method == "key":
            if not key_path:
                raise ValidationError("Private Key File is required when Authentication Method is 'Private Key'.")
            if not os.path.isfile(key_path):
                raise ValidationError(f"Private Key File not found: {key_path}")
        elif not password:
            raise ValidationError("SSH Password is required.")

        verbose_str = self.verbose_var.get()
        verbose_val = 6
        for num, desc in VERBOSE_CHOICES:
            if desc == verbose_str or num == verbose_str:
                verbose_val = int(num)
                break

        ws_path = self.vars.get("wireshark_path", tk.StringVar()).get().strip()

        args = SnifferSshArgs(
            hosts=hosts,
            username=username,
            auth_method=auth_method,
            password=password or None,
            key_path=key_path or None,
            key_passphrase=key_passphrase or None,
            ssh_port=validate_int_range("SSH Port", self.vars["ssh_port"].get(), DEFAULT_SSH_PORT, 1, 65535),
            interface=(self.vars["interface"].get().strip() or "any"),
            verbose=verbose_val,
            count=validate_int_range("Packet Count", self.vars["count"].get(), 300, 0, 10000000),
            duration_seconds=validate_int_range("Duration Seconds", self.vars["duration_seconds"].get(), 1800, 0, MAX_DURATION_SECONDS),
            file_label=self.vars["file_label"].get() or "run",
            output_dir=self.vars["output_dir"].get() or DEFAULT_OUTPUT_DIR,
            wireshark_path=ws_path,
            protocol=self.vars["protocol"].get().strip(),
            host=self.vars["host"].get().strip(),
            src_host=self.vars["src_host"].get().strip(),
            dst_host=self.vars["dst_host"].get().strip(),
            port=self.vars["port"].get().strip(),
            src_port=self.vars["src_port"].get().strip(),
            dst_port=self.vars["dst_port"].get().strip(),
            net=self.vars["net"].get().strip(),
            src_net=self.vars["src_net"].get().strip(),
            dst_net=self.vars["dst_net"].get().strip(),
            custom_filter=self.vars["custom_filter"].get().strip(),
            strict_host_key_checking=bool(self.vars["strict_host_key_checking"].get()),
            save_text_output=bool(self.vars.get("save_text_output", tk.BooleanVar(value=True)).get()),
            create_pcap=bool(self.vars.get("create_pcap", tk.BooleanVar(value=True)).get()),
            save_json_output=bool(self.vars.get("save_json_output", tk.BooleanVar(value=True)).get()),
            save_json_separate=bool(self.vars.get("save_json_separate", tk.BooleanVar(value=True)).get()),
            save_json_combined=bool(self.vars.get("save_json_combined", tk.BooleanVar(value=True)).get()),
        )

        build_sniffer_filter(args)
        return args

    def set_running_state(self, running: bool) -> None:
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

    def start(self) -> None:
        if missing_requirements():
            messagebox.showerror("Missing Requirements", "Missing required Python packages. Click 'Check / Install Requirements'.")
            return
        load_optional_modules()

        if self.manager_thread and self.manager_thread.is_alive():
            messagebox.showwarning("Busy", "Sniffer sessions are already running.")
            return

        try:
            args = self.collect_args()
        except Exception as exc:
            messagebox.showerror("Input Validation Error", str(exc))
            return

        if args.create_pcap and not find_text2pcap(args.wireshark_path):
            resp = messagebox.askyesno(
                "Wireshark text2pcap Not Found",
                "text2pcap was not found. PCAP files will not be created automatically.\n\n"
                "Would you like to proceed with text and JSON captures anyway?",
            )
            if not resp:
                return

        def prompt_host_key_callback(req: HostKeyVerificationRequest) -> None:
            self.host_key_queue.put(req)

        coordinator = RunCoordinator()
        self.sessions = [
            SshSnifferSession(
                host,
                args,
                lambda lvl, msg, kind=LOG_KIND_PROGRAM: self.logger(lvl, msg, kind),
                coordinator,
                host_key_callback=prompt_host_key_callback,
            )
            for host in args.hosts
        ]
        self.threads = []
        self.report_lines = []
        self.set_running_state(True)
        self.logger(LOG_INFO, f"Starting sniffer capture across {len(self.sessions)} firewall(s).")

        def manager():
            try:
                for session in self.sessions:
                    thread = threading.Thread(target=session.run, daemon=True)
                    self.threads.append(thread)
                    thread.start()
                for thread in self.threads:
                    thread.join()
            finally:
                self.logger(LOG_INFO, "All sniffer sessions are complete.")
                if args.save_text_output:
                    try:
                        report_path = self.write_run_report(args)
                        self.logger(LOG_INFO, f"Run summary report written: {report_path}")
                    except Exception as exc:
                        self.logger(LOG_ERROR, f"Failed to write run report: {exc}")

                if len(self.sessions) > 1 and args.save_json_output and args.save_json_combined:
                    try:
                        comb_path = self.write_combined_json(args)
                        self.logger(LOG_INFO, f"Combined multi-host JSON written: {comb_path}")
                    except Exception as exc:
                        self.logger(LOG_ERROR, f"Failed to write combined JSON: {exc}")

                self.root.after(0, lambda: self.set_running_state(False))

        self.manager_thread = threading.Thread(target=manager, daemon=True)
        self.manager_thread.start()

    def write_run_report(self, args: SnifferSshArgs) -> str:
        path = os.path.join(
            args.output_dir,
            f"run_report_sniffer_{sanitize_component(args.file_label, 'run')}_{timestamp_token()}.txt",
        )
        lines = [
            "=== FortiGate SSH Sniffer Run Report ===",
            f"Hosts: {', '.join(args.hosts)}",
            f"Interface: {args.interface}",
            f"Verbose Level: {args.verbose}",
            f"Packet Count Requested: {args.count}",
            f"Duration Seconds Limit: {args.duration_seconds}",
            f"Active Filter: {build_sniffer_filter(args) or 'none'}",
            "",
            "=== Host Summary ===",
        ]
        for s in self.sessions:
            elapsed = s.ended_at - s.started_at if s.ended_at and s.started_at else 0.0
            lines.append(
                f"[{s.host}] Packets={s.packet_count}; Elapsed={elapsed:.2f}s; StopReason={s.stop_reason}; "
                f"TextFile={os.path.basename(s.result_text_file) if s.result_text_file else 'none'}; "
                f"PCAP={os.path.basename(s.result_pcap_file) if s.result_pcap_file else 'none'}"
            )
        lines.extend([
            "",
            "=== Program Events Log ===",
            *self.report_lines,
        ])
        _write_text(path, "\n".join(lines))
        return path

    def write_combined_json(self, args: SnifferSshArgs) -> str:
        path = os.path.join(
            args.output_dir,
            f"combined_ssh_sniffer_{sanitize_component(args.file_label, 'run')}_{timestamp_token()}.json",
        )
        all_packets: list[dict[str, Any]] = []
        hosts_summary: dict[str, Any] = {}

        for session in self.sessions:
            full_text = "".join(session.output_chunks)
            parsed = parse_sniffer_text(
                full_text,
                host=session.host,
                interface=args.interface,
                filter_expr=build_sniffer_filter(args),
                verbose=args.verbose,
            )
            pkts = parsed.get("packets", [])
            all_packets.extend(pkts)
            elapsed = session.ended_at - session.started_at if session.ended_at and session.started_at else 0.0
            hosts_summary[session.host] = {
                "elapsed_seconds": round(elapsed, 2),
                "packets_captured": len(pkts),
                "stop_reason": session.stop_reason,
                "error": session.error_text or None,
            }

        payload = {
            "metadata": {
                "generator": "diag_fgt_sniffer_ssh_standalone_v2",
                "exported_at": datetime.now().isoformat(),
                "mode": "multi_host_combined",
                "hosts": args.hosts,
                "total_hosts": len(args.hosts),
                "total_packets": len(all_packets),
                "interface": args.interface,
                "verbose_level": args.verbose,
                "active_filter": build_sniffer_filter(args),
                "hosts_summary": hosts_summary,
            },
            "packets": all_packets,
        }
        _write_text(path, json.dumps(payload, indent=2))
        return path

    def stop(self) -> None:
        if not self.sessions:
            return
        self.logger(LOG_INFO, "Stop requested. Sending Ctrl+C to active sniffer session(s).")
        for session in self.sessions:
            if not session.completed.is_set():
                session.send_ctrl_c("Manual stop button clicked.")
        self.stop_button.configure(state="disabled")


def run_gui() -> None:
    if tk is None:
        raise RuntimeError("Tkinter is not available in this Python environment.")
    root = tk.Tk()
    root.geometry("1120x900")
    SnifferSshGui(root)
    root.mainloop()


def main() -> int:
    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

