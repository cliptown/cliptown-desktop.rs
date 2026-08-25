# Storage and synchronization contract

## Local SQLite

`clips` is the authoritative local index inside a SQLCipher-encrypted database. The
random 256-bit database key is stored in the operating-system credential store; a
missing or wrong key locks an existing vault instead of resetting it. The index stores text, PNG previews, file URI lists,
organization state, hashes, and timestamps. `clip_embeddings` stores fixed-size
little-endian `float32` vectors and the embedding model identifier. SQLite FTS5 and
`sqlite-vec` execute lexical and vector-distance queries locally.

The configured unpinned history limit is enforced transactionally after every insert
and limit change. Pinned items do not consume that allowance. Limits are bounded from
1 through 100,000 so corrupt configuration cannot disable pruning or exhaust memory.

The current deterministic local hash embedding is a network-free bootstrap model. It
proves the vector storage/query boundary and gives token-similarity ranking; it must not
be described as a production semantic model. A reviewed on-device model can replace it
behind the same `EmbeddingEngine` contract and must record its model ID and dimensions.

## R2 and relational backup

Text and metadata are encrypted on the originating device. Image/file payloads are
chunked and authenticated with a fresh per-object key before upload to randomized R2
keys. Relational stores receive the encrypted manifest, per-device wrapped object keys,
bounded routing metadata, and upload state—never source file paths or plaintext bytes.

PostgreSQL and CockroachDB are independently verified backup targets for the same
portable desired schema. `github.com/declarative-migrations` owns catalog diff,
shadow-replay convergence, and apply safety. The canonical shared desired-state
definitions live under `github.com/ORESoftware/k8s-libs-and-shared-defs`; application
startup never runs migrations.

Embedding backup is separately opt-in. The client encrypts the model ID, dimensions,
and vector bytes before upload. Server-side semantic search is out of scope unless the
privacy model is explicitly changed and reviewed.
