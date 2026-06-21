# lockknife-cli-rs

Rust-first LockKnife CLI runtime based on the uploaded rewrite blueprint.

This crate is the primary Rust migration target for the original Python-heavy
LockKnife workflow at `https://github.com/ImKKingshuk/LockKnife`.

## Shipped in this first pass

- `CLI` command tree in Rust with preserved vocabulary:
  - `device`
  - `crack`
  - `extract`
  - `forensics`
  - `report`
  - `security`
  - `apk`
- `config` loader with TOML and legacy `.conf` compatibility
- minimal Rust `TUI`
- real `ADB` wrapper for `list`, `connect`, `info`, `shell`, and `pull`
- offline `credentials/cracking` for PIN and password workflows, including
  structured artifact output, selectable `json` / `text` formats, and
  case/custody integration
- structured `extraction` and `forensics` outputs
- `HTML` / `JSON` / `CSV` reporting
- case manifest, artifact registry, integrity, and chain-of-custody tracking
- device `security` checks and basic `OWASP` mapping
- `APK` archive extraction and static heuristics

## Migration boundary

- Keep in Rust now:
  - `CLI`, `config`, `TUI`
  - `ADB` core
  - `credentials/cracking`: offline `PIN` and `password` flows
  - `extraction`
  - `forensics`
  - `HTML` / `JSON` / `CSV` reporting
  - chain-of-custody and integrity
  - `security` / `OWASP` checks
  - `APK` static analysis
- Keep deferred or sidecar for now:
  - `Frida`
  - `PDF reports`
  - `ML/AI workflows`
  - `threat-intel`
  - `network / PCAP`
  - `crypto-wallet`
  - best-effort cracking extras: `gesture`, `WiFi`, `keystore`, `passkeys`

## Deferred behavior

- `Frida` exits with an explicit deferred-feature error.
- `PDF` report generation exits with an explicit deferred-feature error and
  points callers to `HTML` instead.
- `security malware --yara` and `apk scan --yara` exit with an explicit
  deferred-feature error pointing at the parked `lockknife-core` `yara-x`
  engine; substring `--pattern` matching ships now in both commands.
- `ML/AI`, `threat-intel`, `network / PCAP`, and `crypto-wallet` remain marked
  as later-phase or external sidecar capabilities.
- best-effort cracking extras are intentionally not promoted into the Rust
  first-ship path.

## Explicitly deferred

- `Frida`
- `PDF reports`
- `YARA` rule-based scanning (substring `--pattern` matching ships instead)
- `ML/AI workflows`
- `threat-intel`
- `network / PCAP`
- `crypto-wallet`
- best-effort cracking extras: `gesture`, `WiFi`, `keystore`, `passkeys`

## Workspace layout

This crate lives in a Cargo workspace alongside two parked crates carried over
from the original Python + PyO3/Rust hybrid project:

- `lockknife-core` — native extension crate holding the deferred/sidecar
  scope: `exploit/` (WPS, handshake, packet, scanner), `network`, `pcap`,
  `gesture`, `crypto` (wallet forensics), `intel` (threat-intel), and
  `yara_scan`. Depends on PyO3 and `yara-x`.
- `lockknife-tui` — the larger, PyO3-bound legacy TUI (catalog/playbook/
  async-dispatch system). Distinct from this crate's own minimal, dependency-
  free `src/tui/mod.rs`, which is the one in the Rust-first ship path.

Both are workspace `members` so they stay buildable with `cargo build -p
lockknife-core` / `-p lockknife-tui` and stay visible to CI, but the workspace
`default-members` is set to `["lockknife-cli-rs"]` only, so a plain `cargo
build` / `cargo check` / `cargo run` from the repo root touches only this
crate and never pulls in PyO3, `yara-x`, `ring`, `goblin`, `nom`,
`aho-corasick`, or `socket2`.

## Notes

- This crate is intended to promote Rust into the primary runtime while preserving the current command vocabulary.
- Deferred capabilities fail clearly instead of silently falling back to Python.
- Use `lockknife.toml.example` as the baseline config for the Rust-first phase.
- Offline cracking commands now support `--case-dir` and `--output`, matching the
  artifact-oriented workflow used by extraction, forensics, security, and APK
  analysis paths.
- Offline cracking commands now support `--format json|text` and emit
  deterministic run metadata including candidate space, input size, strategy,
  and elapsed time.
- The Rust crate now includes shared structured output helpers for `json` /
  `text` persistence, reducing duplicate artifact-writing logic in CLI modules.
- Bundled local verification examples now live under
  `examples/crack-smoke/`, including sample commands, a wordlist, and an
  expected artifact tree.
- See `PROGRESS.md` for the full increment log, including known gaps found
  during the most recent review (`attack-surface`/`apk scan` device-pull-by-
  package paths not yet wired, `apk analyze` permission extraction being a
  heuristic regex sweep rather than a real binary-AXML parser, and no
  `#[test]` coverage yet inside this crate).
- The current environment used for this task did not provide a Rust toolchain on `PATH`, so verification here is limited to careful static/manual consistency review rather than a real `cargo check`.
