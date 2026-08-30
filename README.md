# network-tools

This repository contains a small set of standalone utilities for network administration tasks. The main tool is a FortiGate debug-flow collector that opens an SSH session to one or more devices, sends FortiOS debug commands, and saves the resulting output to timestamped text files.

## Main tool

- Script: [FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py](FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py)
- Purpose: run FortiOS debug-flow traces over SSH, apply optional filters, and capture the session output for later review.
- Runtime requirements: Python with Tkinter available, `paramiko` (for SSH), and `cryptography` (for AES-256-GCM encrypted profiles). Missing packages can be installed directly from the GUI via the "Check / Install Requirements" button.
- Previous versions: [v2](FortiNet/FortiOS/Standalone/archived/diag_fgt_debug_flow_v2.py), [v1](FortiNet/FortiOS/Standalone/archived/diag_fgt_debug_flow_v1.py) kept for reference.

## How to run

```bash
python FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py
```

The GUI collects:
- one or more hostnames/IPs and SSH port (default: 22),
- SSH credentials (password, or a private key file with optional passphrase),
- Strict host-key checking mode toggle and Known Hosts Manager,
- trace count and timer settings,
- address/port/protocol filters, each optionally negated ("Not"),
- display options (function name, iprope, console timestamp),
- live regex filter pattern (Show / Hide matching lines),
- encrypted session profiles (save and reload entire session configurations),
- output directory and file label.

Hover over any field, checkbox, or button in the GUI for an explanation of what it does.

## Notes

- Output files are written into the script's `output/` folder and named with a timestamp to avoid overwriting previous runs.
- The script sends cleanup commands at the end of each session so the firewall debug state is reset.
- The helper functions near the top of the script are intentionally separate from the GUI code so the validation and filter-building logic can be reused or tested independently.
- SSH host keys are trusted on first connection in standard mode and saved to the script's own `known_hosts` file (OpenSSH format, next to the script), so repeat runs verify against the saved key instead of trusting blindly every time. A host key that changes later raises a clear error instead of being silently accepted.
- Trace count is tracked by watching `trace_id=` in the live output rather than relying solely on the FortiGate's own counter, since FortiGate trace IDs do not start at 0 and a single trace_id can span multiple lines. As soon as any one target host reaches its requested trace count, every other still-running host in that run is stopped too, and each host's output file records whether it stopped on its own count or because another host reached its count first.
- SSH output is reassembled into complete lines before it's scanned, since a single line can be split across two SSH receive chunks; scanning each raw chunk independently could silently miss the trace count entirely.
- Each run (one Start click) also produces a single `run_report_<label>_<timestamp>.txt` alongside the per-host files, containing only program-level events (connections, stop reasons, errors, warnings) for every host in that run - no raw trace output.

## Known follow-ups

Resolved in v3 ([diag_fgt_debug_flow_v3.py](FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py)):

- **User's SSH known_hosts are now loaded automatically.** The script loads host keys from both its own local `known_hosts` file and your user's `~/.ssh/known_hosts`, so hosts already trusted from the terminal do not need to be re-trusted.
- **Strict host-key checking enabled by default with interactive verification wizard.** Strict host-key checking is enabled by default to prevent man-in-the-middle attacks. When an unverified host key is encountered (e.g. connecting to a new firewall or custom SSH port), an interactive **Host Key Verification Wizard** modal appears displaying target host, port, key algorithm, bit length, SHA-256 fingerprint, and MD5 fingerprint. Users can choose **Trust & Save Key** (persists to known_hosts), **Trust Once** (session only), or **Do Not Trust** (rejects connection safely).
- **Known Host Manager GUI.** A button in the SSH Connection section opens a dialog to view and manage all known hosts from both the script's local file and your user's `~/.ssh/known_hosts`, allowing you to delete stale or re-keyed entries as needed.
- **Black terminal console with whole-line per-host coloring.** The live output window uses a high-contrast dark terminal theme (`Consolas` monospace font on black background) with entire log lines color-coded in distinct vibrant palette colors per host (Cyan, Mint Green, Gold, Pink, Violet, Orange, Sky Blue, Lime, Fuchsia, Teal).
- **Advanced Boolean & Regex Filter Chaining.** A dedicated live filter panel supports full boolean expressions with `AND`, `OR`, `NOT` (and symbolic `&&`, `||`, `!`, `-`), parentheses grouping, and quoted strings. Supports expressions like `(10.0.0.1 OR 10.0.0.2) AND NOT drop` or `"vd-root:0" && (SYN || ACK)` with real-time "Show Matching" and "Hide Matching" modes.
- **Structured JSON trace export.** Every session run automatically exports a companion structured `.json` trace file alongside the `.txt` output. In addition, an "Export JSON" button in the GUI allows exporting the live log or trace history at any time. The parser extracts VDOM, protocol, source/destination IPs and ports, ingress/egress interfaces, gateway routes, policy ID, policy verdict (Allowed/Denied/Dropped), SNAT/DNAT mappings, session IDs, and timestamped internal execution steps for programmatic analysis.
- **Fully encrypted session profiles (AES-256-GCM).** All session settings (target hostnames, IP addresses, subnets, ports, filter rules, usernames, passwords, and private key passphrases) can be saved to a 100% encrypted profile file protected by a master passphrase using authenticated AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation. Zero plaintext network topology or credentials ever exist in saved profile files on disk.

Resolved in v2:

- **Packet count now stops the flow reliably.** Each session watches the live output for `trace_id=`, remembers the first trace_id it sees, and stops right after the Nth trace_id's lines finish printing.
- **Trace-count completion now propagates to all target firewalls.** As soon as any one host reaches its own trace count, every other still-running host in that run is stopped too, with the reason recorded per host.
- **Hover help text** now explains every GUI field, checkbox, and button.
- **SSH host keys are trusted automatically on first connection** and persisted to a local `known_hosts` file. A host key that changes on a later connection is rejected instead of silently accepted.

Possible future ideas (not yet implemented):

- A GUI "Compare Traces" tool to side-by-side view traces from different hosts to spot divergent behavior. 