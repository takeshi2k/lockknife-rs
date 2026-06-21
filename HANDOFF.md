# LockKnife Rust-first CLI migration — handoff report

This document is a handoff for whichever agent (human or AI) picks up this
work next. It captures the task, the source materials, a correction made
mid-task that matters for trusting earlier analysis, what has actually been
done, the invariants to preserve, and a prioritized roadmap for what's left.

## 1. The task

Upstream project: `https://github.com/ImKKingshuk/LockKnife` — an Android
security research / forensics toolkit currently built as a Python
orchestration layer with a PyO3/Rust-accelerated native core.

Goal: rewrite the Python parts into a standalone Rust CLI, scoped narrowly
for this phase. The user's explicit instruction was:

> Disable Frida and PDF-report for now. Ship first: CLI, config, TUI, ADB
> core, credentials/cracking, extraction, forensics, HTML/JSON/CSV
> reporting, chain-of-custody, security/OWASP checks, APK static analysis.
> Ship later or keep as Python/external sidecar indefinitely: PDF reports,
> Frida, ML/AI workflows, threat-intel, network/PCAP, crypto-wallet, and the
> inherently best-effort device-cracking extras (gesture/WiFi/keystore/
> passkey).

That scope split is the single most important constraint on this project.
Anything in the "ship later" list should stay out of the default build
surface and should fail **explicitly** if invoked, never silently no-op or
fall back to Python.

## 2. Source materials

Two zips were uploaded at the start of this work:

- `LockKnife-rust-rewrite.zip` — a full snapshot of the upstream repo
  (Python-first README/CHANGELOG/LICENSE/SECURITY.md, `pyproject.toml`/
  `maturin.toml`/`uv.lock` for the PyO3 side) plus a 3-crate Cargo workspace:
  `lockknife-cli-rs`, `lockknife-core`, `lockknife-tui`. Also had real
  project hygiene: `Cargo.lock`, `rust-toolchain.toml`, `clippy.toml`,
  `rustfmt.toml`, `deny.toml`, `cargo-fuzz` targets.
- `lockknife-cli-rs-full.zip` — just the standalone `lockknife-cli-rs` crate
  on its own, with its own `MIGRATION_SCOPE.md`, `PROGRESS.md`,
  `lockknife.toml.example`, `examples/crack-smoke/`.

## 3. Important correction (read this before trusting any earlier summary)

Mid-task, an initial comparison concluded `zip1`'s copy of `lockknife-cli-rs`
was more advanced than `zip2`'s. **That was backwards** — it came from
reading a `diff` old/new direction wrong. The verified, re-checked fact is:

- `zip2`'s `lockknife-cli-rs` was the more advanced code: it had the shared
  `write_structured_with_format`/`default_structured_output_name` helpers,
  the `CrackMetadata` struct, and `--format`/`--case-dir`/`--output` wired
  into the `crack` subcommands. `zip1`'s copy of the same crate was missing
  all of that.
- This was confirmed three independent ways (labeled `diff`, direct
  `grep -c` counts on both copies, and full manual reads of the differing
  files) before acting on it, since the first read was wrong.

**Action taken:** the final merged crate uses `zip2`'s `lockknife-cli-rs` as
the source of truth, not `zip1`'s. If you inherit any earlier summary that
says otherwise, prefer this document and the actual code in the deliverable
zip.

## 4. Current state of the deliverable

The merged repo (zipped and delivered to the user as
`lockknife-rust-rewrite-increment1.zip`) is structured as:

```
lockknife-rust/
├── README.md, CHANGELOG.md, LICENSE, SECURITY.md   (from zip1; README/CHANGELOG
│                                                      now have a migration-status
│                                                      banner pointing at the cli crate)
├── Cargo.toml          (workspace; default-members = ["lockknife-cli-rs"])
├── Cargo.lock           (from zip1; not yet re-validated against a real toolchain)
├── rust-toolchain.toml, clippy.toml, rustfmt.toml, deny.toml  (from zip1)
├── pyproject.toml, maturin.toml, uv.lock, bandit.yaml          (from zip1; legacy
│                                                                  Python/PyO3 side,
│                                                                  untouched)
├── lockknife-cli-rs/     ← THE SHIP-FIRST CRATE. Base = zip2. No path-dependency
│   │                       on lockknife-core or lockknife-tui (verified).
│   ├── README.md, MIGRATION_SCOPE.md, PROGRESS.md, lockknife.toml.example
│   ├── examples/crack-smoke/   (manual smoke-test fixture; README, wordlist,
│   │                             expected artifact tree)
│   └── src/
│       ├── main.rs
│       ├── app/         (Config, AppContext, error types, deferred/sidecar/
│       │                 best-effort gating functions)
│       ├── adb/mod.rs    (real adb wrapper: list/connect/info/shell/pull,
│       │                  single-device auto-targeting with explicit error
│       │                  on ambiguity)
│       ├── case/mod.rs   (case manifest, artifact registry, SHA-256 integrity
│       │                  verification, chain-of-custody — the evidentiary core)
│       ├── cli/          (clap command tree + per-domain dispatchers: device,
│       │                  crack, extract, forensics, report, security, apk)
│       ├── modules/      (actual logic: credentials, extraction, forensics,
│       │                  reporting, security, apk; shared structured-output
│       │                  helpers in modules/mod.rs)
│       └── tui/mod.rs    (minimal ratatui+crossterm TUI — currently just a
│                           device-list screen, no other command access)
├── lockknife-core/       ← PARKED. workspace member, NOT in default-members.
│                            Holds the deferred/sidecar scope: exploit/ (wps,
│                            handshake, packet, scanner), network.rs, pcap.rs,
│                            gesture.rs, crypto.rs (wallet), intel.rs,
│                            yara_scan.rs, bruteforce.rs, correlation.rs,
│                            binary.rs, plus 3 cargo-fuzz targets. Depends on
│                            PyO3 + lockknife-tui.
└── lockknife-tui/        ← PARKED. workspace member, NOT in default-members.
                             The larger, PyO3-bound legacy TUI (~91 files:
                             catalog/playbook/async-dispatch system, overlays,
                             20+ test modules). Distinct from the lightweight
                             tui/mod.rs inside lockknife-cli-rs, which is what
                             ships in this phase.
```

## 5. Work completed so far (increment 1)

1. Merged `zip2`'s `lockknife-cli-rs` (the more advanced copy) into `zip1`'s
   full project scaffold (top-level docs/tooling + `lockknife-core` +
   `lockknife-tui`).
2. Set workspace `default-members = ["lockknife-cli-rs"]` so a plain
   `cargo build`/`check`/`run` only touches the ship-first crate; the parked
   crates stay reachable via `cargo build -p lockknife-core` / `-p
   lockknife-tui`.
3. **Fixed a real policy violation found during review:** `security malware
   --yara` and `apk scan --yara` accepted a `--yara` flag but silently
   dropped it via a `..` wildcard destructure instead of failing explicitly.
   Both now return an explicit `yara-rule-scan` deferred-feature error (see
   `app/mod.rs::deferred_feature`), matching the "fail explicitly, never
   silently fall back" rule stated in `MIGRATION_SCOPE.md`.
4. **Fixed a broken example:** the bundled `examples/crack-smoke/README.md`
   password-cracking demo used a target hash that didn't match anything in
   its own bundled wordlist (so it would always report "no match", silently
   failing to demonstrate the feature). Replaced with the verified SHA-256
   of `secret`, which is present in `wordlist.txt`.
5. Updated `PROGRESS.md`, `MIGRATION_SCOPE.md`, `lockknife-cli-rs/README.md`,
   the top-level `README.md`, and `CHANGELOG.md` to document all of the
   above and to log known-but-unfixed gaps (see §7).

All of this was done via careful manual/static code review — **there is no
Rust toolchain and no network access in the sandbox this work was done in**,
so none of it has been compiler-verified. This is the single most important
caveat for whoever continues this work. See §8, Tier 0.

## 6. Invariants to preserve

These were established deliberately and should not be casually reverted:

- `lockknife-cli-rs` must have **zero path-dependency** on `lockknife-core`
  or `lockknife-tui`. This is what makes the ship-first scope buildable
  without PyO3/yara-x/ring/goblin/nom/aho-corasick/socket2.
- Workspace `default-members` stays `["lockknife-cli-rs"]`. `lockknife-core`
  and `lockknife-tui` stay in `members` (so they're not lost / still
  CI-visible via explicit `-p`) but never become part of the default build.
- Deferred/sidecar features must **fail explicitly** (return a
  `LockKnifeError::FeatureDeferred` via `deferred_feature(...)` /
  `delegated_sidecar(...)` / `best_effort_feature(...)` in `app/mod.rs`).
  Never silently accept-and-ignore a flag for deferred scope (this is
  exactly the bug fixed in §5.3 — watch for the same pattern, i.e. a `..`
  wildcard swallowing a field that maps to deferred/sidecar scope, anywhere
  else in the `cli/` dispatchers).
- `Config::enforce_migration_policy()` in `app/config.rs` hardcodes
  `disable_frida = true` and `disable_pdf_reports = true` regardless of what
  a user's config file says. Don't let a config option silently re-enable
  these in this phase.

## 7. Known gaps (logged, not yet fixed)

From `lockknife-cli-rs/PROGRESS.md`:

- `security attack-surface --package`/`--serial`/`--artifacts` and
  `apk scan --serial` are accepted by the CLI parser but not wired up (only
  `--apk <path>` works today). Not a silent-fallback violation — the command
  still hard-errors asking for `--apk` — but the unused fields should be
  implemented or removed.
- `apk analyze`/`apk permissions` extract Android permissions via a regex
  sweep over every archive member's raw bytes, not a real binary-AXML
  (AndroidManifest.xml) parser. Works as a heuristic; can both miss and
  false-positive.
- No `#[test]` coverage yet inside `lockknife-cli-rs` itself. The bundled
  `examples/crack-smoke/` fixture is a manual smoke test, not automated.
- `lockknife-cli-rs/src/tui/mod.rs` is a single 84-line device-list screen
  with no access to crack/extract/forensics/report/security/apk commands —
  a real gap relative to "TUI" being named as ship-first scope.
- No CI workflow exists yet (`.github/workflows` is absent) despite
  `clippy.toml`/`rustfmt.toml`/`deny.toml` already being present and ready
  to wire up.

## 8. Prioritized roadmap (what's left, by essentiality)

**Tier 0 — foundational, blocks trusting everything else**
1. Run real `cargo check` / `cargo clippy` / `cargo fmt --check` against the
   merged crate. This has never been compiler-verified. Fix whatever it
   turns up before trusting anything downstream.
2. Re-validate `Cargo.lock` (`cargo generate-lockfile` / `cargo metadata`)
   once a toolchain is available.

**Tier 1 — correctness/safety of the evidentiary core**
3. Test coverage for `case/mod.rs`: manifest persistence, artifact
   registration, chain-of-custody append, integrity verification
   (matched/modified/missing detection). This is the chain-of-custody
   backbone for a forensics tool — it has to be provably correct.
4. Test coverage for `modules/credentials.rs`: crack functions against known
   hash/plaintext pairs, candidate-space math, length-bound edge cases.
5. Resolve the §7 accept-but-ignore gaps (`attack-surface`, `apk scan
   --serial`) — implement device-pull-by-package, or trim the flags so the
   CLI surface doesn't promise more than it does.

**Tier 2 — feature completeness on the 9 named ship-first pillars**
6. Real AndroidManifest.xml (binary AXML) parser, replacing the regex sweep.
7. TUI build-out — give it real access to crack/extract/forensics/report/
   security/apk, not just a device list.
8. Extraction module hardening — current per-category remote-path lists are
   a thin hardcoded set (one path per app), not resilient to OEM path
   variance, multiple installed browsers/messengers, or newer Android
   profile layouts.

**Tier 3 — depth/robustness, lower urgency**
9. Forensics depth: `decode_protobuf_like` is a naive varint scanner (not
   schema-aware); `carve_patterns` is regex-only (no magic-byte file carving
   for deleted-file recovery).
10. OWASP mapping depth: `map_owasp` is a crude string-contains check rather
    than structured MASVS rule evaluation.
11. CI workflow wiring `clippy.toml`/`rustfmt.toml`/`deny.toml` into
    `.github/workflows`, scoped to `default-members`.

**Tier 4 — polish, not blocking**
12. Shell completion generation (bash/zsh/fish) via `clap_complete`.
13. Full top-level `README.md` rewrite (currently just has a banner; the
    rest of the doc still describes the old Python-hybrid architecture as
    current).
14. Error-message/exit-code/`--help` text polish.

## 9. Recommended next step

Start at Tier 1 (items 3–4, automated tests for `case/mod.rs` and
`modules/credentials.rs`) while arranging for Tier 0 (a real `cargo check`)
to happen in an environment that has a Rust toolchain and network access,
since the environment this work was done in had neither. Flag anything
`cargo check`/`clippy` surfaces and fix forward — nothing past this point
should be assumed correct until that happens.
