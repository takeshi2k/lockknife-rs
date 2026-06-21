# Migration scope

This Rust crate is the first-shipping rewrite target for the Python portions of
LockKnife that are stable, deterministic, and practical to own in a compiled
runtime.

## Ship now in Rust

- `device`: real `adb` wrapper for device listing, connect, info, shell, and
  pull
- `config`: TOML plus legacy `.conf` compatibility
- `tui`: minimal Rust terminal UI
- `crack`: offline `pin`, `password`, and `password-rules`
- `extract`: structured extraction outputs for core acquisition paths
- `forensics`: snapshot, sqlite inventory, timeline, correlation, carving, and
  related structured outputs
- `report`: `html`, `json`, `csv`, chain-of-custody, and integrity flows
- `security`: device checks, `OWASP` mapping, attack-surface, malware pattern
  heuristics
- `apk`: archive extraction, permission review, and static heuristics

## Keep deferred or external

- `runtime` / `Frida`
- `pdf` reporting
- `YARA` rule-based scanning (parked in `lockknife-core`'s `yara_scan`; this
  crate ships substring `--pattern` matching for `security malware` and
  `apk scan` instead)
- `ai`
- `threat-intel`
- `network` / `pcap`
- `crypto-wallet`
- best-effort cracking extras:
  - `gesture`
  - `wifi`
  - `keystore`
  - `passkeys`

## Workspace layout

This crate is one of three workspace members (`lockknife-cli-rs`,
`lockknife-core`, `lockknife-tui`). The workspace `default-members` is set to
this crate only, so the deferred/sidecar scope above (which mostly lives in
`lockknife-core`, plus the separate PyO3-bound `lockknife-tui`) stays in the
tree without being part of the default build.

## Current policy

- Deferred features should fail explicitly and never silently fall back to
  Python.
- The Rust crate should preserve the command vocabulary of the original tool as
  much as practical.
- Security-sensitive cracking support stays limited to offline deterministic
  workflows in this phase.
