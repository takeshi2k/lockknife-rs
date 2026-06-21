# Progress

## Increment: repo merge — parked core/tui crates, fixed silent --yara drop

- merged this crate into the full project tree (`lockknife-core`, `lockknife-tui`,
  upstream `README.md`/`CHANGELOG.md`/`LICENSE`/`SECURITY.md`, and Rust tooling
  configs: `rust-toolchain.toml`, `clippy.toml`, `rustfmt.toml`, `deny.toml`)
- `lockknife-core` (exploit/network/pcap/gesture/crypto-wallet/intel/yara-x) and
  `lockknife-tui` (the PyO3-bound legacy hybrid TUI) are now workspace members
  but were removed from the workspace `default-members`, so a plain
  `cargo build` / `cargo check` / `cargo run` only touches this crate
  (`lockknife-cli-rs`); the parked crates remain reachable with
  `cargo build -p lockknife-core` / `-p lockknife-tui`
- confirmed `lockknife-cli-rs`'s own `Cargo.toml` has zero path dependency on
  either parked crate, so nothing in the default ship-first build pulls in
  PyO3, yara-x, ring, goblin, nom, aho-corasick, or socket2
- fixed a policy violation found during this merge: `security malware --yara`
  and `apk scan --yara` accepted a `--yara` flag but silently dropped it via
  a `..` wildcard destructure instead of failing explicitly; both now return
  an explicit `yara-rule-scan` deferred-feature error pointing at the parked
  `lockknife-core` yara-x engine, matching the "deferred features must fail
  explicitly, never silently fall back" policy in `MIGRATION_SCOPE.md`

## Increment: shared output rollout and local verification docs

- applied the shared structured output helper to `report integrity`
- aligned `report integrity` default filename generation with the shared helper
- added bundled local smoke-test examples under `examples/crack-smoke/`
- added an expected artifact tree for quick local validation

## Previous increment: shared structured output helper

- extracted reusable structured output helpers for `json` / `text` persistence
- added shared default filename generation for structured outputs
- refactored the `crack` CLI path to use the shared helper instead of custom
  file-writing and artifact-registration logic
- kept case manifest and chain-of-custody behavior unchanged while reducing
  duplication in the CLI layer

## Previous increment: cracking format and metadata

- promoted offline cracking output selection to a first-class CLI option
- `crack pin`, `crack password`, and `crack password-rules` now accept:
  - `--format json`
  - `--format text`
- cracking results now include deterministic metadata:
  - candidate space
  - input size
  - strategy
  - elapsed milliseconds
- persisted cracking artifacts keep the same case manifest and chain-of-custody
  behavior introduced in the previous increment

## Previous increment: cracking artifact integration

- promoted the shipped offline cracking paths to the same artifact model used by
  other Rust-first commands
- `crack pin`, `crack password`, and `crack password-rules` now accept:
  - `--case-dir`
  - `--output`
- cracking results now:
  - print structured JSON to stdout
  - write structured JSON to disk
  - register artifacts when a case manifest is active
  - append chain-of-custody entries for persisted results

## Current deferred scope

- `Frida`
- `PDF` reporting
- `ML/AI`
- `threat-intel`
- `network / PCAP`
- `crypto-wallet`
- `YARA` rule-based scanning (parked in `lockknife-core`; substring `--pattern`
  matching ships now in `security malware` and `apk scan`)
- best-effort cracking extras:
  - `gesture`
  - `WiFi`
  - `keystore`
  - `passkeys`

## Known gaps found during this increment's review (not yet fixed)

- `security attack-surface --package` / `--serial` (pull an installed APK from
  a connected device by package name) and `--artifacts` (attack surface from a
  pre-existing artifacts JSON) are accepted by the CLI parser but not wired up;
  only `--apk <path>` is implemented today. Not a silent-fallback violation
  (the command still hard-errors asking for `--apk`), but the unused fields
  should either be implemented or removed from the signature next.
- `apk scan --serial` (pull-then-scan an installed package straight from a
  device) is accepted but not wired; only `--apk`/positional `target` (local
  file) is implemented today.
- `AndroidManifest.xml` permission extraction in `apk analyze` is a regex
  sweep over every archive member's raw bytes rather than a real binary-AXML
  parser, so it can both miss permissions encoded outside string pools and
  pick up false positives from unrelated files. Works as a heuristic; a real
  AXML parser is a good next hardening step.
- no `#[test]` coverage yet inside `lockknife-cli-rs` itself (the bundled
  `examples/crack-smoke/` fixture is a manual smoke test, not an automated one).

## Suggested next increment

- pick one: (a) wire `attack-surface`/`apk scan` device-pull-by-package paths,
  (b) add a real AXML parser for `apk analyze`/`apk permissions`, or
  (c) add `#[test]` coverage for `case/mod.rs` (manifest round-trip, integrity
  verification) and `modules/credentials.rs` (cracking correctness) — case/
  credentials are the highest-value modules to lock down with tests first
- run `cargo check` / `cargo clippy` and tighten any compile issues once a Rust
  toolchain is available in the execution environment

