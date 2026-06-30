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

Fake/no-proof verification is not production-ready. Production callers should
require structured proof reports from the vector-tested proof ports before
accepting untrusted space operations.
