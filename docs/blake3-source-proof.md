# BLAKE3 source hash proofs

The development source verifier proves the complete unkeyed BLAKE3 digest of
public bytes, including every compression round and the block, chunk, tree and
root relations. It can bind the existing outer transaction signing payload and
the entire raw public key to their 32-byte hashes. Production acceptance verifies
the actual STARK certificates and fixed public routing; it does not recompute a
native BLAKE3 hash as a substitute.

The algorithm references are the [BLAKE3 1.8.7 portable implementation](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.7/src/portable.rs)
and [official vectors](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.7/test_vectors/test_vectors.json).
The source bound is 4096 bytes and output is the ordinary 32-byte unkeyed digest.
Keyed hashing, key derivation and general XOF output are outside this hash API.
These bounds do not alter transaction limits, gas, fees or activation rules.

This adds the missing hash computation needed for source binding. It does not
prove canonical chain history, account authority, private witnesses, the AA
sender bundle wrapper or node settlement. The complete public ML-DSA-65
signature verifier is described [separately](mldsa-verification-proof.md).
The generated identity in this example needs its own signature proof graph;
existing certificates for a different message/key cannot establish that graph.

## Runnable source entry

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), its
stable Rust toolchain and locked dependencies. From the repository root:

```bash
cargo run -p shell-stark-prover --example blake3-sources -- prove source-dir
cargo run -p shell-stark-prover --example blake3-sources -- verify source-dir
cargo run -p shell-stark-prover --example blake3-sources -- check-rejections source-dir
```

No node, funds, preexisting account or saved key is required. The producer creates
a temporary ML-DSA-65 key in memory and an outer transaction with a 32-byte
recipient. It signs the transaction's actual existing signing hash. Only the
public key, signature, message and transaction are written. The private key is
neither serialized nor printed. The example submits no transaction to a network.

The directory contains `identity.json`, `source.json`, `transaction-hash.json`
and `public-key-hash.json`. Each new proof is created without overwriting an
existing file, flushed, synced, reloaded and checked. A resumed `prove` invocation
reuses completed hash files. The independent `verify` invocation generates no
proofs. Invalid existing files cause a nonzero exit; keep them for diagnosis.
Interrupted partial-file recovery remains unqualified.

Both hash proof chains are verified before independent native hash and signature
controls run. `check-rejections` first checks the valid sources, then rejects
changed nonce/algorithm tag/key bytes, chunk counter, root flags, missing parent,
block order, final digest, last round operation, last feedforward word and final
chunk padding. It reports the rejection phases, creates no proofs and succeeds
only when all expected rejections occur.

The public identity is compatible with the existing signature source examples:

```bash
cargo run -p shell-stark-prover --example mldsa-matrix -- prove source-dir
cargo run -p shell-stark-prover --example mldsa-equation -- prove source-dir equation-dir
cargo run -p shell-stark-prover --example mldsa-verify -- prove source-dir equation-dir signature-dir
```

Those commands construct a new graph for this exact key and 32-byte message;
the matrix stage can take tens of minutes. Source-hash and signature graphs
remain separate entry points until their combined caller/account/history
acceptance is qualified. Running one graph does not establish the other.

## Compression AIR

`CompressionProof` version 1 uses statement domain `B3COMP01`. It carries the
eight-word chaining value, sixteen-word block, 64-bit counter, block length and
flags, plus every public operation result. All seven rounds and eight G calls
per round are executed. Each G has four modular additions and four XOR/rotate
operations. Sixteen final XORs prove both halves of the feedforward output.
There are 464 actual operations in 512 slots and 1024 trace rows.

The AIR has 140 columns, 167 constraints with maximum degree three and ten fixed
public sequence assertions. Six selector columns choose addition or XOR with
rotation 16, 12, 8, 7 or 0. Four public columns bind the three operands and result.
Four sets of 32 private Boolean bits reconstruct those words; two private
Boolean carry bits establish addition modulo 2^32. The bounded integer addition
relation excludes proof-field aliases. Each XOR result bit is constrained after
the fixed rotation; a native XOR/rotate calculation is not used in verification.

The verifier reconstructs only register/message routing from the claimed
intermediate results. Fixed message schedules, initial state, counter halves,
block length, flags and all feedforward operands are therefore bound to the
caller-supplied compression input and output. Dummy rows have zero public
selectors/operands. Only the final unused odd row carries padding. Layout,
version, operation count and proof size are checked before AIR verification.

## Complete digest and transaction binding

`Blake3HashProof` version 1 composes all compression certificates in depth-first
order. Public byte packing binds each 64-byte block, including zero padding and
the actual final block length. Chunks contain at most 1024 bytes, use their
actual 64-bit chunk counter, and set CHUNK_START/CHUNK_END at the correct blocks.
A left-balanced tree binds both child chaining values into each parent block.
Parent chaining values use the IV, zero counter and PARENT flag. Only the actual
final root operation sets ROOT; even an honestly proved nonroot compression
cannot replace it. The first eight root words encode the 32-byte digest in
little-endian order. Empty input and exact block/chunk boundaries follow the
same routing. Missing, extra or reordered certificates are rejected.

`verify_hash` requires the expected raw message and digest. It checks every
compression mathematically, binds all chaining values and requires exact
coverage. The 4096-byte bound permits at most 67 compression certificates.
Applications must bound untrusted JSON before parsing and budget full proof
verification work.

`Transaction::signing_payload` exposes the exact existing PQ signing preimage.
`Transaction::signing_hash` hashes that shared encoder, preserving its previous
bytes and behavior. `prove_transaction_signing_hash` and
`verify_transaction_signing_hash` use this encoder for the expected public outer
transaction and algorithm byte. They do not substitute a supplied native digest
for the proof. Native AA sender signatures additionally commit to bundle
framing; this outer-payload helper does not establish that wrapper.

The full public-key hash is an independent source primitive. It does not change
the existing batch-entry identifier mapping: Embedded entries use the first
32 key bytes, while Reference entries use the sender address. That legacy
identifier is not a full-key hash or proof of account authority. No address
derivation, consensus carrier or activation rule changes here.

## Design decision and focused checks

Status: accepted for the bounded public source-hash component.

Reuse the existing proof backend and options. Constrain BLAKE3 ARX directly,
compose real compression certificates with explicit public routing and share
the existing canonical encoder. Keep native arithmetic in witness construction
and independent controls. Avoid changing transaction or batch identifier
semantics to simplify the proof.

```bash
cargo test -p shell-stark-prover blake3_hash -- --nocapture
```

Real proofs cover complete compressions, root hashes, all sixteen feedforward
words against official XOF prefixes, saved JSON and honest nonroot-certificate
rejection. Private field-valued words and fractional carries satisfy linear
relations but fail Boolean constraints. Boundary cases cover zero/max words,
all rotations, both counter halves, every round, malformed layouts and payloads.
Native graph controls match official digest vectors at block/chunk boundaries
through 4096 bytes; actual full source proofs exercise the generated canonical
transaction and a 1952-byte key across two chunks and a parent. Real maximal
four-chunk proof generation and other transaction/algorithm/profile combinations
remain unqualified unless explicitly exercised.
