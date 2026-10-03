# Emergency algorithm governance

This opt-in implementation requires a client containing the emergency governance
upgrade and a new genesis with explicit key bindings. It is not enabled on the
public testnet by these instructions. Existing genesis configurations retain
legacy behavior; adding bindings to an initialized legacy chain is rejected.

Every genesis validator supplies its ML-DSA-65 primary key in
`consensus.authority_pubkeys` and an SLH-DSA-SHA2-256f fallback key in
`governance_fallback_keys`, indexed by its primary address. Set
`emergency_governance_height` explicitly. The primary key must derive the
configured validator address. The bindings and activation height contribute to
the genesis identity and cannot be replaced on restart.

Generate separate encrypted keys with `shell-node key generate --algorithm
mldsa65` and `shell-node key generate --algorithm slhdsa`, using distinct
`--output` paths and the normal password-file option. The keystore JSON exposes
`address` and `public_key` for genesis configuration; never publish its secret
material or password.

At activation, registered validators can sign registry mutations with either
algorithm. Votes count separately by signing algorithm; mixed votes cannot make
up one quorum. The fallback path requires its embedded registered key and does
not replace the primary key. It cannot authorize ordinary transfers or
non-registry governance.

`tx send --from PRIMARY_ADDRESS --data CALLDATA` submits a call using the account
identity selected by `--from`. Supply the fallback keystore to sign with SLH-DSA;
node authorization still applies. An explicit `--gas-limit` avoids relying on a
read-only gas estimate for governance authorization. `--to` must be the registry
address and `--value` must be zero. Existing transfer commands without these
options retain their original behavior.

## Local acceptance

Build the client, then run the single acceptance entry from the repository root:

```sh
cargo build -p shell-cli
NODE_BIN=target/debug/shell-node python3 tests/e2e/run-emergency-governance.py
```

Python 3 and the normal Rust/native build dependencies are required. The test
creates fresh encrypted ML/SLH keys, an isolated genesis, loopback RPC ports and
RocksDB data. It submits a genuine fallback-signed deprecation transaction,
checks its receipt and registry result, rejects a fallback-signed transfer,
and restarts the node to verify the receipt, nonce and primary key persist.
Temporary keys, processes and data are removed on exit.

This single-validator test retires Dilithium3 while consensus continues with
ML-DSA. It does not establish a live-network consensus-key retirement procedure
or production-scale quorum behavior. Library and node regressions separately
cover mixed-quorum rejection, fallback governance after ML retirement, activation
boundaries and historical block validation.
