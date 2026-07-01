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

The upstream vector manifest records `zkgroup`, `zkcredential`, `poksho`, and
`keytrans` as vector-backed against `signalapp/libsignal` `v0.96.4`. Message
backup and SVR/SVRB proof semantics are explicitly deferred until their proof
fixtures and package boundaries are implemented.

Fake/no-proof verification is not production-ready. Production callers should
require structured proof reports from the vector-tested proof ports before
accepting untrusted space operations.

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
