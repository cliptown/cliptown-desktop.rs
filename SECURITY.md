# Security policy

ClipTown processes unusually sensitive data. Never include real clipboard contents,
tokens, credentials, private paths, encryption keys, database URLs, or signed object
URLs in issues, test fixtures, screenshots, logs, telemetry, or crash reports.

Report suspected vulnerabilities privately through GitHub Security Advisories.

The local history database is an implementation boundary, not a cloud trust change.
Remote services receive only end-to-end encrypted clip/object payloads and bounded
routing metadata. Vector backup is opt-in and encrypted on the originating device;
the service must not receive a plaintext embedding derived from clipboard text.

