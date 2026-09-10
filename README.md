# network-tools

This repository contains a small set of standalone utilities for network administration tasks.

## Main Tools

### 1. FortiGate Debug Flow (`diag_fgt_debug_flow_v3.py`)
- Script: [FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py](FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py)
- Purpose: run FortiOS debug-flow traces over SSH, apply optional filters, and capture the session output for later review.
- Runtime requirements: Python with Tkinter available, `paramiko` (for SSH), and `cryptography` (for AES-256-GCM encrypted profiles). Missing packages can be installed directly from the GUI via the "Check / Install Requirements" button.
- Previous versions: [v2](FortiNet/FortiOS/Standalone/archived/diag_fgt_debug_flow_v2.py), [v1](FortiNet/FortiOS/Standalone/archived/diag_fgt_debug_flow_v1.py) kept for reference.

### 2. FortiGate Packet Sniffer & PCAP Tool (`diag_fgt_sniffer_pcap_v3.py`)
- Script: [FortiNet/FortiOS/Standalone/diag_fgt_sniffer_pcap_v3.py](FortiNet/FortiOS/Standalone/diag_fgt_sniffer_pcap_v3.py)
- Purpose: capture live packets across one or more FortiGate firewalls using `diagnose sniffer packet`, stream color-coded console logs, automatically generate per-host and combined chronological Wireshark `.pcap` files, and export structured JSON.
- Wireshark Integration: Point to any Wireshark installation directory with auto-detect and validation, automatic per-host and combined PCAP conversion on capture, and a standalone "Convert Log to PCAP" tool for converting past captures.
- Runtime requirements: Python with Tkinter available, `paramiko`, `cryptography`, and Wireshark (`text2pcap`).
- Previous versions: [v2](FortiNet/FortiOS/Standalone/archived/diag_fgt_sniffer_ssh_standalone_v2.py), [v1](FortiNet/FortiOS/Standalone/archived/diag_fgt_sniffer_ssh_standalone_v1.py) kept for reference.

## How to run

```bash
# FortiGate Debug Flow utility
python FortiNet/FortiOS/Standalone/diag_fgt_debug_flow_v3.py

# FortiGate Packet Sniffer & PCAP utility
python FortiNet/FortiOS/Standalone/diag_fgt_sniffer_pcap_v3.py
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
- **Structured JSON trace export (Per-Host and Multi-Host Combined).** Every session run automatically exports structured trace data. Checkboxes in the Debug Flow Options allow selectively enabling Text output (`.txt`) and JSON output (`.json`), with dynamic sub-options for Separate (Per-Host) JSON and Combined Multi-Host JSON. When running across multiple firewalls simultaneously, the runner can produce both individual per-host JSON files and an aggregated `combined_ssh_debug_flow_<label>_<timestamp>.json` trace file containing all hosts, trace statistics, and per-host summaries. In addition, an "Export JSON" button in the GUI allows exporting the live log or trace history (including any active boolean/regex filters) at any time.
- **Fully encrypted session profiles (AES-256-GCM).** All session settings (target hostnames, IP addresses, subnets, ports, filter rules, usernames, passwords, private key passphrases, and output format preferences) can be saved to a 100% encrypted profile file protected by a master passphrase using authenticated AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation. Zero plaintext network topology or credentials ever exist in saved profile files on disk.
- **Standardized `os.path` and standalone file I/O helpers.** All path joining, directory creation, profile persistence, and trace output exports are standardized on native Python `os.path` (`os.path.join`, `os.path.dirname`, `os.path.basename`, `os.path.splitext`) and lightweight file I/O helpers (`_read_text`, `_write_text`), guaranteeing clean string path handling and resilience in PyInstaller frozen executables.

Resolved in v2:

- **Packet count now stops the flow reliably.** Each session watches the live output for `trace_id=`, remembers the first trace_id it sees, and stops right after the Nth trace_id's lines finish printing.
- **Trace-count completion now propagates to all target firewalls.** As soon as any one host reaches its own trace count, every other still-running host in that run is stopped too, with the reason recorded per host.
- **Hover help text** now explains every GUI field, checkbox, and button.
- **SSH host keys are trusted automatically on first connection** and persisted to a local `known_hosts` file. A host key that changes on a later connection is rejected instead of silently accepted.

### FortiGate Packet Sniffer & PCAP Tool v3 ([diag_fgt_sniffer_pcap_v3.py](FortiNet/FortiOS/Standalone/diag_fgt_sniffer_pcap_v3.py)):

- **Chronological Combined Text Output**: A new checkbox **"Save Combined Text (.txt)"** generates a single consolidated capture file (`combined_ssh_sniffer_<label>_<timestamp>.txt`) interleaving packet blocks from all targeted firewalls in exact ascending chronological order, complete with per-device provenance (`[hostname]`).
- **Combined Multi-Device PCAP Generation**: A new checkbox **"Create Combined PCAP (.pcap)"** converts the sorted chronological multi-device text capture directly into a single Wireshark `.pcap` file (`combined_ssh_sniffer_<label>_<timestamp>.pcap`). Network engineers can inspect transit flows across multiple firewall boundaries in a single Wireshark timeline.
- **Streamlined Symmetrical Output Options (3x3 Layout)**:
  - **Per-Host Row**: *Save Text Output (.txt)*, *Create PCAP (.pcap)*, *Save JSON (.json)*.
  - **Combined Row**: *Save Combined Text (.txt)*, *Create Combined PCAP (.pcap)*, *Combined JSON (.json)*.
- **Strict Reactive Checkbox Interlocking**:
  - Unchecking *Save Text Output* automatically locks out *Create PCAP*.
  - Unchecking *Save Combined Text* automatically locks out *Create Combined PCAP*.
  - Per-Host and Combined JSON operate as independent, non-locking toggles.
- **High-Volume GUI Responsiveness Optimization**: Decoupled Tkinter log drainage with a 200-line batch cap and deferred `see("end")` redraw, completely eliminating GUI freezes during high-throughput sniffer bursts at verbose level 6.
- **AES-256-GCM Profile Persistence**: Fully persists and restores all 6 output format preferences within master-passphrase encrypted session profiles.

### FortiGate Packet Sniffer v2 ([archived/diag_fgt_sniffer_ssh_standalone_v2.py](FortiNet/FortiOS/Standalone/archived/diag_fgt_sniffer_ssh_standalone_v2.py)):

- **Paramiko Worker Architecture**: Standardized on pure synchronous Paramiko worker threads per firewall, eliminating Tkinter async event-loop collisions and aligning with workspace standards.
- **Wireshark Path Configuration & PCAP Conversion**: Added an explicit Wireshark installation folder entry with auto-detection fallback, Browse picker, path validation badge, automatic PCAP conversion during live runs, and a standalone "Convert Log to PCAP" button to convert past captures. Fixed timestamp format alignment with `%Y-%m-%d %H:%M:%S.` so text2pcap executes cleanly with zero timestamp errors.
- **Requirements Check & Auto-Installer**: Integrated dependency check on startup for `paramiko`, `cryptography`, and Wireshark `text2pcap`, complete with a one-click GUI installer.
- **Dark Console Live View with Whole-Line Host Colors**: High-contrast dark console terminal (`Consolas` on black) with vibrant 10-color whole-line coloring per host and color-tagged log levels (`info`, `warning`, `error`). Complete line buffering across SSH receive chunks ensures packet headers and hex dumps are never fragmented.
- **Structured JSON Sniffer Export**: Parses packet headers and hex payloads into structured 5-tuples, interface direction, protocols, and payload data. Exports Per-Host JSON, Combined Multi-Host JSON, and GUI live-filtered JSON.
- **100% AES-256-GCM Encrypted Profiles**: All targets, credentials, filter settings, and paths are encrypted using authenticated AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation.
- **Strict Host-Key Checking & Known Hosts Manager**: Strict host-key verification wizard and known hosts manager to guard against MITM attacks.
- **Live Boolean & Regex Filter Chaining**: Real-time log searching (`Show Matching`, `Hide Matching`, `Clear Filter`) supporting `AND`, `OR`, `NOT`, quotes, and parentheses.

Possible future ideas (not yet implemented):

- A GUI "Compare Traces" tool to side-by-side view traces from different hosts to spot divergent behavior.
- Advanced Multi-Flow JSON Analysis and Visualization engine for troubleshooting complex packet life-cycles across large multi-firewall transit paths.

## License & Commercial Tiers

This project is licensed under a **Source-Available / Fair Source Commercial Tiered License**. See [LICENSE.md](LICENSE.md) for full terms.

### Free Individual Use
The software is **100% free** for individuals, students, lab testing, and single independent network consultants.

### Commercial & Enterprise Tiers
Commercial deployment across organizations with multiple named users requires an annual commercial subscription:

| Tier | Active Users / Named Seats | Licensing Requirement | Inquiry Method |
| :--- | :--- | :--- | :--- |
| **Individual / Free** | 1 User (Personal, Lab, Solo Consultant) | **Free** | No license required |
| **Small Business** | 1 – 25 Named Users | Annual Subscription | GitHub Discussions / Issues |
| **Medium Business** | 26 – 100 Named Users | Annual Subscription | GitHub Discussions / Issues |
| **Large Business** | 101 – 500 Named Users | Annual Subscription | GitHub Discussions / Issues |
| **Enterprise** | 501+ Named Users | Custom Enterprise Agreement | GitHub Discussions / Issues |

For purchasing inquiries or commercial license quotes, please open a thread in **GitHub Discussions** or submit an inquiry via **GitHub Issues**.
