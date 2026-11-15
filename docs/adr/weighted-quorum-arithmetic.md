# Weighted quorum arithmetic component

The white paper requires signer weight strictly greater than two thirds of
total active weight. A valid proposer seal or transaction signature graph does
not prove that threshold. Keep this arithmetic ingredient separate from Native
commit certificates until signer cryptography and authenticated consensus
context are composed with it.

Version one accepts an independently expected public context containing the
chain ID, parent hash, block hash, block number, sorted unique authority weights
and sorted unique signer addresses. It supports at most 1000 authorities and
effective weights from zero through 1000000. Zero weights contribute nothing;
zero total weight and equality at two thirds fail. These are fixed proof-format
bounds, not a change to Native limits or consensus behavior.

The artifact carries public cumulative weights. AIR assertions connect every
prefix to the expected weight and signer bit; constraints check additions and
signed additions. A nonzero total and a 32-bit nonnegative value equal to
`3 * signed - 2 * total - 1` establish the strict inequality. All bounded sums
and differences are far below the existing 128-bit field modulus. Verification
checks the actual certificate with the existing proof options instead of
replacing it with a native quorum calculation. All context fields and prefixes
are included in the proof transcript. Intermediate values are public.

The component uses an exclusively owned, separate `ProductionStore` job. Cold
reentry verifies cached proof bytes against the exact source before reuse.
Changed sources and conflicting output files fail without overwriting existing
artifacts. Verification opens neither a mutable job nor a Native database.

From a repository checkout with the stable Rust toolchain and the existing
RocksDB build prerequisites:

```bash
mkdir quorum-demo
cargo run --locked -p shell-stark-prover --example weighted-quorum -- \
  sample quorum-demo/context.json
cargo run --locked -p shell-stark-prover --example weighted-quorum -- \
  prove quorum-demo/context.json quorum-demo/job quorum-demo/proof.json
cargo run --locked -p shell-stark-prover --example weighted-quorum -- \
  verify quorum-demo/context.json quorum-demo/proof.json
# A separate invocation reopens the same job and verifies its cached component.
cargo run --locked -p shell-stark-prover --example weighted-quorum -- \
  prove quorum-demo/context.json quorum-demo/job quorum-demo/proof.json
```

The sample uses public mathematical inputs with weights `[2, 1, 1]` and signer
weight 3. It creates no accounts, keys, signatures or Native blocks. Commands
return a failing exit status for invalid inputs or certificates. Keep the
context as the independently expected verifier input; a context bundled with
an untrusted proof cannot authenticate itself.

`arithmeticVerified: true` explicitly accompanies `nativeAuthorization: false`.
This component authenticates neither the supplied authority set and effective
weights nor signatures, historical penalty effects, proposer selection, view
changes, execution or finality. It is not accepted as a canonical signature
batch, settlement proof or commit certificate. Full quorum AIR composition and
the Node import/finality path remain unfinished. Existing activation schedules,
wire formats and Native cryptographic checks stay in force.
