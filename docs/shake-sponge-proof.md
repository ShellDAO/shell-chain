# SHAKE sponge proofs and ML-DSA hash inputs

This development source implementation proves byte-oriented SHAKE128 and
SHAKE256, including domain padding, XOR absorption, complete Keccak-f1600
permutations and extended squeezing. It composes a sponge bridge AIR with the
[full permutation AIR](keccak-permutation-proof.md). All messages, outputs and
intermediate states are public. This is neither a private nor a compact
attestation, and it does not prove a complete PQ signature or activate node
settlement.

The specification is [FIPS 202, sections 4–6.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
August 2015. The hash example follows [FIPS 204, Algorithms 3 and 8](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
August 13, 2024: `tr = SHAKE256(pk, 64)` and, with an empty context,
`mu = SHAKE256(tr || 0x00 || 0x00 || message, 64)`. Lengths here are bytes.
This implementation is not a NIST-validated module.

## Run the source example

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), the
repository's stable Rust toolchain and locked dependencies. Run from the
repository root; no node, account, funds or saved keys are required:

```bash
cargo run -p shell-stark-prover --example mldsa-hash -- prove hashes.json
cargo run -p shell-stark-prover --example mldsa-hash -- verify hashes.json
```

`prove` generates a temporary ML-DSA-65 key in memory, signs a public example
message, proves the hash of all 1952 public-key bytes and then proves the message
representative linked to that hash. The key hash uses 15 full permutations; this
example's message representative uses one. Proving can take several minutes.
Only public key, message, signature and proof data are persisted. The private key
is not printed or stored. Creating an existing artifact path fails.

After syncing the new JSON, the example reloads and verifies it. A separate
`verify` invocation reads the existing file without generating another proof.
It checks the native signature and independent native SHAKE256 outputs as
controls, plus the actual sponge and permutation proofs. Wrong input, output,
state links or payloads return a nonzero exit code. The JSON includes unsigned
64-bit lane values; use an integer-preserving reader. The Rust example preserves
them exactly.

This is a development source example, not a released node CLI. The native
signature control is separate from the AIR: signature validity, sampling,
matrix/norm/hint relations, canonical transaction binding, private witnesses and
actual admission, settlement, persistence and replay remain unfinished. Other
signature contexts and pre-hash modes are not claimed by this example.

## Sponge constraints and composition

SHAKE128 uses a 168-byte rate; SHAKE256 uses 136 bytes. The bridge routes raw
message bits to the rate portion, adds `0x1f` after the final message byte and
`0x80` at the final rate byte, then constrains bitwise XOR with the previous
state. The two padding markers share a byte when only one byte remains. A
message exactly divisible by the rate gets a new padding block. Capacity bytes
remain unchanged during absorption. The initial state is zero.

Every absorption is followed by a full 24-round Keccak proof. Output bytes come
from the rate portion of the final absorption result. Additional output blocks
reuse the previous complete state as the next permutation input without
absorbing another message block. Zero output length is supported; all absorption
steps still have proofs. The verifier derives the exact number of steps from
message length, output length and variant, and rejects removed or extra steps.

The bridge has 43 columns and 16 constraints of degree at most three. One real
even row handles one byte position of a 200-byte state. Fixed sequence assertions
bind the before-state, raw message, permutation input, permutation output,
requested output bits and padding/emission selectors. Booleanity follows from
public typed-byte bit extraction. The before-state is wired to the previous
verified permutation output; emission is wired to the requested output bytes.
Only the final unused odd row carries statement-derived trace padding.

The verifier does bit extraction and fixed routing, then verifies the real
bridge AIR and every full permutation proof. It does not evaluate native SHAKE,
padding XOR or a native Keccak permutation to substitute for those proofs.
All public input lengths, the variant/rate and the complete permutation endpoints
are included in a separate `SHKSP001` statement domain.

`ShakeProof` version is 1. `verify_shake` requires the expected variant, message
and output independently from the caller. Applications must authenticate those
inputs and limit untrusted JSON before parsing. This standalone development API
accepts messages and outputs up to 4096 bytes each; larger inputs are rejected
before proving. Its bridge traces range from 512 to 32768 rows. Each bridge or
permutation proof payload is limited to 1 MiB; the complete artifact may exceed
that because it contains multiple proofs and public states. These local resource
bounds do not set consensus gas, fees or network input limits. Arbitrary-length
protocol input acceptance is not established by this component.

## Regression entry

```bash
cargo test -p shell-stark-prover shake_sponge -- --nocapture --test-threads=1
```

The tests generate real proofs for empty input/zero output, overlapping suffix
and final padding, exact-rate messages for both variants, and outputs crossing
the rate boundary. They compare all requested bytes with independent native
SHAKE implementations, check a fixed SHAKE128 empty-message answer, verify JSON
reload and exercise the bridge constraints directly. Regressions reject changed
message/output/capacity/squeeze links, reordered or missing steps, an altered
internal Keccak round, variant/version/shape changes and malformed or foreign
proof layouts. The example separately covers a genuine multi-block public key
and the linked default-context message representative.
