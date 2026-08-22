# Desktop toolkit contract

ClipTown native desktop uses Zed's GPUI and does not embed a WebView. GPUI is pinned
through `Cargo.lock`; upgrades require native builds and functional probes on Windows,
macOS, and Linux. The toolkit remains pre-1.0, so lockfile review and exact-head CI are
release requirements.

Platform adapters are narrow:

- GPUI owns windows, rendering, focus, and keyboard event delivery.
- `clipboard-rs` owns native text/image/file clipboard representations.
- SQLite owns the local item index, FTS index, settings, and vectors.
- future tray and global-shortcut adapters must expose capability state rather than
  pretending initialization succeeded.

Both the Rust and Flutter clients consume the same item/storage fixtures and must pass
the same semantic acceptance cases. Native behavior may have different code, but a
one-sided feature needs a recorded parity gap and owner.

