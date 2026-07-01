These fixtures are compatibility harness inputs for APIs modeled after
`signalapp/libsignal` `v0.96.4`.

They are not copied Signal production secrets. The fixture names preserve the
upstream domain boundaries (`zkgroup`, `zkcredential`, `poksho`, `keytrans`) so
drift tests can track which compatibility surface each vector exercises.

`message-backup` and `svr-svrb` proof domains are intentionally absent from this
fixture set and are recorded as `deferred` in `internal/upstream.CurrentManifest`.
