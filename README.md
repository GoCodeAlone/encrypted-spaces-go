# encrypted-spaces-go

Go Encrypted Spaces operation-log and proof compatibility library.

This module carries Workflow-facing Encrypted Spaces primitives while tracking
the upstream `signalapp/libsignal` compatibility source. The current scaffold is
pinned to `signalapp/libsignal` `v0.96.4`, published 2026-06-25.

Initial releases are intentionally staged:

- `v0.1.0`: operation log, epochs, retention, and fake/no-proof verification for
  Workflow composition tests.
- `v0.2.0`: upstream vector-tested proof verification ports for membership,
  proof transcript, and key transparency domains.
- `v0.3.0`: upstream vector parity manifest and drift metadata for downstream
  Workflow plugins.
- `v0.4.0`: proof policy and evidence APIs over the vector-backed membership,
  operation commitment, and key-transparency checkpoint surfaces.

The upstream vector manifest records `zkgroup`, `zkcredential`, `poksho`, and
`keytrans` as vector-backed against `signalapp/libsignal` `v0.96.4`. Message
backup and SVR/SVRB proof semantics are explicitly deferred until their proof
fixtures and package boundaries are implemented.

Fake/no-proof verification is not production-ready. Production callers should
require structured proof reports from the vector-tested proof ports before
accepting untrusted space operations.

This module is an offline proof and operation-log compatibility library. It
does not register Signal accounts, link devices, send or receive Signal
messages, reserve usernames, upload backups, or contact the official Signal
service.

## Proof APIs

`proof.VectorPolicy()` composes the existing vector-backed primitives into a
single readiness surface:

- membership credentials are verified through `zkgroup` vectors;
- operation commitments are checked against deterministic `operationlog`
  digests without exposing operation ciphertext;
- key-transparency checkpoints are verified through `keytrans` vectors and
  rejected when they are stale relative to the caller's previous tree size;
- `proof.NewOperationEvidence` serializes operation ID, digest, epochs,
  ciphertext size, and proof reports without plaintext operation bodies, nonces,
  associated data, or key material.

`verification.ProofCoverageReport()` remains conservative: it reports
message-backup and SVR/SVRB as deferred with the upstream input needed before a
production-equivalence claim can be made.

## Packages

- `operationlog`: deterministic commitments, idempotent append replay, conflict
  reports, retention boundaries, and fast-forward checkpoints for encrypted
  operations.
- `epochs`: key epoch rotation and membership epoch updates used to reject
  removed members before appending operations.
- `proof`: vector-backed proof policy adapters for membership credentials,
  operation commitments, key-transparency checkpoint freshness, and redacted
  proof evidence serialization.
- `verification`: fake/no-proof verification reports for Workflow composition
  tests plus coverage reports for vector-backed and deferred proof domains.
  Fake reports always set `ProductionReady` to `false`; message-backup and
  SVR/SVRB remain deferred until stable upstream proof vectors are carried.
- `internal/upstream`: upstream release and vector coverage manifest used by
  drift checks and downstream Workflow plugins.
