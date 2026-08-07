# network-tools

This repository contains a small set of standalone utilities for network administration tasks. The main tool is a FortiGate debug-flow collector that opens an SSH session to one or more devices, sends FortiOS debug commands, and saves the resulting output to timestamped text files.

## Main tool

- Script: [FortiNet/FortiOS/diag_fgt_debug_flow_v2.py](FortiNet/FortiOS/diag_fgt_debug_flow_v2.py)
- Purpose: run FortiOS debug-flow traces over SSH, apply optional filters, and capture the session output for later review.
- Runtime requirements: Python with Tkinter available and the `paramiko` package installed.
- Previous version: [FortiNet/FortiOS/diag_fgt_debug_flow_v1.py](FortiNet/FortiOS/diag_fgt_debug_flow_v1.py) is kept as-is for reference; v2 supersedes it (see "Known follow-ups" below).

## How to run

```bash
python3 FortiNet/FortiOS/diag_fgt_debug_flow_v2.py
```

The GUI collects:
- one or more hostnames/IPs,
- SSH credentials (password, or a private key file with optional passphrase),
- trace count and timer settings,
- address/port/protocol filters, each optionally negated ("Not"),
- output directory and file label.

Hover over any field, checkbox, or button in the GUI for an explanation of what it does.

## Notes

- Output files are written into the script's `output/` folder and named with a timestamp to avoid overwriting previous runs.
- The script sends cleanup commands at the end of each session so the firewall debug state is reset.
- The helper functions near the top of the script are intentionally separate from the GUI code so the validation and filter-building logic can be reused or tested independently.
- SSH host keys are trusted on first connection and saved to the script's own `known_hosts` file (OpenSSH format, next to the script), so repeat runs verify against the saved key instead of trusting blindly every time. A host key that changes later raises a clear error instead of being silently accepted.
- Trace count is tracked by watching `trace_id=` in the live output rather than relying solely on the FortiGate's own counter, since FortiGate trace IDs do not start at 0 and a single trace_id can span multiple lines. As soon as any one target host reaches its requested trace count, every other still-running host in that run is stopped too, and each host's output file records whether it stopped on its own count or because another host reached its count first.

## Known follow-ups

Resolved in v2 ([diag_fgt_debug_flow_v2.py](FortiNet/FortiOS/diag_fgt_debug_flow_v2.py)):

- **Packet count now stops the flow reliably.** Each session watches the live output for `trace_id=`, remembers the first trace_id it sees, and stops right after the Nth trace_id's lines finish printing.
- **Trace-count completion now propagates to all target firewalls.** As soon as any one host reaches its own trace count, every other still-running host in that run is stopped too, with the reason recorded per host.
- **Hover help text** now explains every GUI field, checkbox, and button.
- **SSH host keys are trusted automatically on first connection** and persisted to a local `known_hosts` file. A host key that changes on a later connection is rejected instead of silently accepted.

Possible future ideas (not implemented):

- Optionally also load the user's own `~/.ssh/known_hosts` so hosts already trusted from a terminal do not need to be re-trusted here.
- A GUI toggle to require strict host-key checking instead of trust-on-first-use.
