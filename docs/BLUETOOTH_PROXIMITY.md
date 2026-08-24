# Native Bluetooth proximity transport

The Rust desktop app independently implements the ClipTown BLE central role on
Windows, macOS, and Linux through `btleplug`. It discovers only the fixed
ClipTown service (plus a local `CT-xxxxxx` post-filter), connects to the selected
peripheral, reads the rotating advertisement characteristic, and exchanges
bounded frames through write-with-response and notification characteristics.

The transport is not a trust decision. `src/proximity.rs` separately enforces
the shared signed-envelope contract: closed fields, two-minute expiry, enrolled
Ed25519 device signature, recipient/sender/session/scope binding, ciphertext
digest, sequence/replay protection, transcript-derived matching code, and
separate one-use consent. Bluetooth, bonding, RSSI, and delivery never raise
Shared Auth AAL. Only an opaque `shared-auth:step-up:relay` request may cross the
radio; the 3FA app and Shared Auth complete that ceremony through their normal
authenticated channel.

`cliptown-desktop nearby-scan --seconds 5` performs an explicit bounded scan and
prints only an index, rotating display name, and RSSI. It deliberately omits the
OS transport identifier so diagnostics do not become a stable nearby-device
log. The reusable library session supports encrypted send/receive, but product
UI must supply the enrolled key lookup and consent workflow before calling it.

Linux builds require BlueZ/D-Bus development libraries and runtime access to the
Bluetooth service. A packaged macOS application must include
`NSBluetoothAlwaysUsageDescription`; running the unbundled CLI requires the
invoking terminal to have Bluetooth permission. Windows packaging must declare
the required Bluetooth/radios capabilities. These are deployment gates, not
conditions silently bypassed by the code.

Unit tests and Windows/macOS/Linux builds prove parser/framing parity and native
compilation. They are not physical-radio proof. Release enablement additionally
requires phone-to-each-desktop canaries for both this Rust app and the Flutter
desktop app, including radio-off, permission denial, wrong-code, one-sided
consent, replay, reorder, expiry, revocation, oversize, digest/signature mismatch,
background, disconnect, and reconnect cases.
