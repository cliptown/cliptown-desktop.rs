# ClipTown native desktop

This is the independent Rust/GPUI implementation of ClipTown for macOS, Windows,
and Linux. It is developed side-by-side with
[`cliptown-flutter`](https://github.com/cliptown/cliptown-flutter); neither client is
a prototype, fallback, wrapper, or replacement for the other.

It also contains an independent Windows/macOS/Linux BLE central and the shared
fail-closed proximity contract. See
[`docs/BLUETOOTH_PROXIMITY.md`](docs/BLUETOOTH_PROXIMITY.md); Bluetooth never
counts as an authentication factor, and hosted compilation is not radio proof.

The first functional slice provides:

- native text, PNG image, and file-list clipboard reads;
- bounded local history with a user-configurable item count;
- SQLCipher-encrypted SQLite FTS search and SQLite-resident 384-dimensional text vectors;
- pinned items that survive ordinary retention pruning;
- a native GPUI history window; and
- a headless conformance probe used on Windows, macOS, and Linux CI runners.

Cloud synchronization remains end-to-end encrypted. Images and file bytes belong in
randomly named encrypted Cloudflare R2 objects; Postgres and CockroachDB receive the
encrypted clip/object manifests and encrypted, explicitly opted-in vector backups.
Local absolute paths, plaintext clip text, and plaintext embeddings are not remote
database fields.

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run -- contract-probe
cargo run
```

`cargo run` opens the GPUI window and reads the same SQLite database used by the
headless commands. `capture-once`, `search`, and `set-history-limit` are useful for
diagnostics without opening a window; their output never contains clipboard content
unless the user explicitly requests search results in their own terminal.

The disk database is encrypted with a random 256-bit key held by macOS Keychain,
Windows Credential Manager, or Linux Secret Service. If that credential is missing or
invalid for an existing database, startup fails closed; ClipTown never recreates the
vault or silently falls back to plaintext.

See [docs/DESKTOP_TOOLKIT.md](docs/DESKTOP_TOOLKIT.md) and
[docs/STORAGE_AND_SYNC.md](docs/STORAGE_AND_SYNC.md) for the long-lived boundaries.
