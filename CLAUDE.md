# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository overview

This repo is the **public-consumption** copy of standalone, single-file Python GUI utilities for interacting with network gear (currently FortiGate firewalls). There is no package structure, build system, test suite, or linter configured — each tool is a self-contained script meant to be run directly with `python3`/`py`.

A companion repo, `network-tools`, is the private/working repo for the same tooling and may be ahead of this one. When fixing bugs or adding features here, consider whether the change should also be ported to/from `network-tools`.

## Running the tool

```bash
python3 diag_fgt_debug_flow_v1.py
```

- Requires Tkinter (bundled with most desktop Python installs; if missing, the script raises `RuntimeError: Tkinter is not available`).
- Requires `paramiko` for the SSH functionality. The script does **not** assume it's pre-installed: it checks for missing packages at startup (`missing_requirements()`) and offers a "Check / Install Requirements" button that runs `pip install --upgrade paramiko` (`install_requirements()`). Install manually with `py -m pip install --upgrade paramiko` if preferred.
- There is no CLI mode — `main()` only launches the Tkinter GUI (`run_gui()`).

## Verifying changes

No test suite or linter exists. To sanity-check changes:
- `python3 -m py_compile diag_fgt_debug_flow_v1.py` for a syntax check.
- Manually launch the GUI (`python3 diag_fgt_debug_flow_v1.py`) and exercise the affected flow, since GUI wiring (button → variable → validation → session) is easy to break silently.
- The pure helper functions (`parse_host_list`, `validate_int_range`, `validate_ip`, `validate_port`, `validate_proto`, `sanitize_component`, `build_filter_commands`, `active_filters`) are decoupled from Tkinter and are the easiest place to add ad-hoc/regression checks if you need to verify logic without a display.

## Architecture (`diag_fgt_debug_flow_v1.py`)

Single file, roughly four layers top to bottom:

1. **Requirements bootstrap** — `REQUIRED_PACKAGES`, `missing_requirements()`, `load_optional_modules()`, `install_requirements()`. `paramiko` is imported lazily/optionally at module scope so the script can still start (and show a helpful error) even if the dependency isn't installed yet.
2. **Pure argument/command helpers** — `DebugFlowSshArgs` (dataclass holding all session parameters: hosts, credentials, trace/timer settings, address/port filter ranges, output flags), plus free functions that parse and validate raw GUI input (`parse_host_list`, `validate_int_range`, `validate_ip`, `validate_port`, `validate_proto`, `sanitize_component`) and translate an `DebugFlowSshArgs` into the actual FortiOS CLI command sequence (`build_filter_commands`, `active_filters`). Keep new filter/option fields flowing through all three: the dataclass, `collect_args()` validation in the GUI, and `build_filter_commands`.
3. **`SshDebugSession`** — one instance per target host. Owns a paramiko `SSHClient`/interactive shell, sends the `diagnose debug flow ...` command sequence, polls the channel non-blockingly (`drain_channel`), supports an optional timer or manual stop (`send_ctrl_c`, `stop_requested` / `completed` threading `Event`s), always runs `cleanup_remote_debug()` on exit to leave the firewall's debug state clean, and writes a timestamped result `.txt` file per host under `output/` (`write_file`).
4. **`DebugFlowSshGui`** — Tkinter UI. One `SshDebugSession` (and one Python thread) is spawned per host, all joined by a single "manager" thread so the GUI thread never blocks. Log lines from worker threads are pushed onto a thread-safe `queue.Queue` and drained on the Tk main loop via `root.after(100, self.drain_log_queue)` — **never touch Tkinter widgets directly from a session/worker thread**; go through `self.logger(level, message)` instead.

## Conventions

- Output files land in `output/` (git-ignored) and are named `{host}_ssh_debug_flow_{label}_{YYYYMMDD-HHMMSS}.txt`; filenames are sanitized via `sanitize_component` to strip unsafe characters from user-supplied host/label values.
- `README.md` doubles as a lightweight per-tool issue/backlog tracker (`Issues:` / `Fixes:` / `Feature Requests:` sections keyed by script name) instead of GitHub Issues — update it when you resolve or add an item there.
- Never commit secrets or credentials — this is a public repo. SSH passwords are entered at runtime through the GUI and are not persisted by the script.
