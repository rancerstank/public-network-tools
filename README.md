# network-tools

This repository contains a small set of standalone utilities for network administration tasks. The main tool is a FortiGate debug-flow collector that opens an SSH session to one or more devices, sends FortiOS debug commands, and saves the resulting output to timestamped text files.

## Main tool

- Script: [FortiNet/FortiOS/diag_fgt_debug_flow_v1.py](FortiNet/FortiOS/diag_fgt_debug_flow_v1.py)
- Purpose: run FortiOS debug-flow traces over SSH, apply optional filters, and capture the session output for later review.
- Runtime requirements: Python with Tkinter available and the `paramiko` package installed.

## How to run

```bash
python3 FortiNet/FortiOS/diag_fgt_debug_flow_v1.py
```

The GUI collects:
- one or more hostnames/IPs,
- SSH credentials,
- trace count and timer settings,
- address/port/protocol filters,
- output directory and file label.

## Notes

- Output files are written into the script's `output/` folder and named with a timestamp to avoid overwriting previous runs.
- The script sends cleanup commands at the end of each session so the firewall debug state is reset.
- The helper functions near the top of the script are intentionally separate from the GUI code so the validation and filter-building logic can be reused or tested independently.

## Known follow-ups

- Packet count does not always stop the flow as expected.
- The first completed run does not propagate to all target firewalls automatically.
- The GUI still lacks hover help text for some controls.
- SSH key acceptance and auto-accept options are still future enhancements.
