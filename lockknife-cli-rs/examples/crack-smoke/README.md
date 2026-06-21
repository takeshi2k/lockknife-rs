# Crack smoke examples

These examples are intended for quick local verification once `cargo` is
available.

## Sample wordlist

Use the bundled `wordlist.txt` file in this directory.

## Example commands

### PIN cracking

```bash
cargo run -- crack pin \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  --algo sha256 \
  --length 4 \
  --format json \
  --output ./out/crack_pin.json
```

### Password dictionary cracking

```bash
cargo run -- crack password \
  2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b \
  --algo sha256 \
  --wordlist ./examples/crack-smoke/wordlist.txt \
  --format text \
  --output ./out/crack_password.txt
```

This target hash is the verified SHA-256 digest of `secret`, which is present
in the bundled `wordlist.txt`, so a successful run should report
`"matched": true` / `recovered_secret: "secret"` (text format renders this as
`Matched: true` / `Recovered secret: secret`).

### Password rules cracking with case tracking

```bash
cargo run -- crack password-rules \
  2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b \
  --algo sha256 \
  --wordlist ./examples/crack-smoke/wordlist.txt \
  --max-suffix 25 \
  --format json \
  --case-dir ./case-demo
```

### Integrity report

```bash
cargo run -- report integrity \
  --case-dir ./case-demo \
  --format text
```

## What to verify

- the selected `--format` matches the created file extension
- `crack` outputs include:
  - `summary`
  - `result`
  - `metadata`
- `metadata` includes:
  - `candidate_space`
  - `input_size`
  - `strategy`
  - `elapsed_ms`
- when `--case-dir` is used:
  - `manifest.json` is created
  - generated artifacts are appended to the manifest
  - chain-of-custody entries are added for written artifacts

See `expected-tree.txt` for a sample artifact layout.
