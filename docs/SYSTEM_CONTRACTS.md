# System Contracts

Shell-Chain ships two native system contracts. They live at well-known addresses
and are executed as native Rust code — no Solidity bytecode, no compiler needed.
The PQVM/revm execution adapter intercepts calls to these addresses before
running bytecode.

For opt-in dual-key algorithm registry voting and local acceptance, see
[Emergency algorithm governance](EMERGENCY_GOVERNANCE.md).

---

## Addresses

| Contract | Address | Description |
|----------|---------|-------------|
| `ValidatorRegistry` | `0x0000000000000000000000000000000000000000000000000000000000000001` | Manages the active validator set |
| `AccountManager` | `0x0000000000000000000000000000000000000000000000000000000000000002` | Per-account PQ key rotation and custom validation code |

---

## ValidatorRegistry

Direct native transactions and AA inner calls have separate dispatch paths.
AA dispatch requires the independent `aa_validator_registry_height` activation;
`aa_account_manager_height` alone is insufficient. Once enabled, reads and
writes use the same native methods and caller authorization, with batch-wide
rollback of account state, native metadata and runtime algorithm policy.
See [AA execution and acceptance](ACCOUNT_ABSTRACTION_GUIDE.md#native-validatorregistry-calls-in-aa-bundles).

### Purpose

Maintains the canonical set of block-producing validators. All writes go through
governance transactions (see `shell_proposeAddValidator` / `shell_proposeRemoveValidator`)
to prevent split-brain scenarios.

### Interface

```solidity
interface IValidatorRegistry {
    // ── Write (validator-only) ──────────────────────────────────────────────
    function addValidator(address validator) external;
    function removeValidator(address validator) external;
    function setValidatorWeight(address validator, uint64 weight) external;
    function proposeAlgorithmActivation(
        uint8 algo, uint64 activationHeight, bytes32 verifierHash
    ) external returns (bool approved);
    function deprecateAlgorithm(uint8 algo) external;

    // ── Read (anyone) ───────────────────────────────────────────────────────
    function getValidators() external view returns (address[] memory);
    function isValidator(address account) external view returns (bool);
}
```

### Function selectors

| Function | Selector | Access |
|----------|----------|--------|
| `addValidator(address)` | `0x4d238c8e` | validators only |
| `removeValidator(address)` | `0x40a141ff` | validators only |
| `setValidatorWeight(address,uint64)` | `0xa6d5d626` | validators only |
| `proposeAlgorithmActivation(uint8,uint64,bytes32)` | `0x1b7520b8` | validators only |
| `deprecateAlgorithm(uint8)` | `0xa4b88278` | validators only |
| `getValidators()` | `0xb7ab4db5` | anyone |
| `isValidator(address)` | `0xfacd743b` | anyone |

### Submitting an algorithm activation vote

Send a signed native transaction to `ValidatorRegistry` with selector
`0x1b7520b8`, followed by three 32-byte ABI words in this order:

1. `algo`: the installed algorithm identifier (`uint8`, left-padded with zeros).
2. `activationHeight`: the proposed activation block (`uint64`, left-padded with zeros).
3. `verifierHash`: the candidate verifier hash (`bytes32`).

The one-argument `proposeAlgorithmActivation(uint8)` interface is not supported.
Every vote on the same candidate must use matching height and verifier hash, and
the height must satisfy the applicable [timelock rules](CONSENSUS_DETAILS.md#algorithm-governance-timelock-activation).
The method returns ABI `false` for an accepted vote below quorum and `true` when
that vote reaches quorum. A successful transaction receipt therefore does not by
itself mean the proposal was approved. The executed return value is available in
`debug_traceTransaction` output when the node enables debug RPC and retains the
required history; receipts do not contain native return values.

With [proposal staging](CONSENSUS_DETAILS.md#algorithm-proposal-staging) enabled,
a sub-quorum vote leaves live algorithm policy unchanged. The quorum-reaching
vote publishes a pending entry; actual activation still waits for the target
height. The separate [voting window](CONSENSUS_DETAILS.md#algorithm-voting-window)
can reject expired votes. These optional upgrades and their legacy behavior are
specified in the linked activation rules.

### Calling from Solidity

Use the independently activated **NativeRegistryView** at full address
`0x0000000000000000000000000000000000000000000000000000000100000001`
(ID `2^32 + 1`). It is outside the reserved PQ precompile range. Contract calls
to low address `0x01` invoke ML-DSA verification, even though direct native
Registry transactions use that address. Routing depends on the execution entry;
the two interfaces must not be interchanged.

The optional `native_registry_view_height` enables this view at and after the
configured block. It defaults to disabled and is independent of both native AA
schedules. Existing databases accept only a future activation; persisted schedules
are immutable and trusted snapshots must match. At activation the view address
is reserved for the protocol; operators must account for that reservation when
choosing a genesis allocation or upgrade schedule.

The view exposes `getValidators()` and `isValidator(bytes32)`, accepts zero-value
CALL/STATICCALL, and rejects writes, unknown/malformed calldata, attached value
and delegate calls. It uses the native read gas cost of 21,000 plus ordinary
PQVM call overhead. Each PQVM execution captures the current bounded validator
set, including changes made by preceding native AA operations. Historical calls
use the historical world-state root. Validation and paymaster execution use the
same height gate and read-only surface.

Solidity `address` is only 20 bytes. Represent validator members as `bytes32`,
including function arguments and arrays; zero-padding `msg.sender` cannot
recover a truncated PQ address. Pass the complete account identifier explicitly.

```solidity
interface INativeRegistryView {
    function getValidators() external view returns (bytes32[] memory);
    function isValidator(bytes32 account) external view returns (bool);
}

contract ValidatorCheck {
    INativeRegistryView constant REGISTRY =
        INativeRegistryView(address(uint160(0x100000001)));

    function currentValidators() external view returns (bytes32[] memory) {
        return REGISTRY.getValidators();
    }

    function isActiveValidator(bytes32 account) external view returns (bool) {
        return REGISTRY.isValidator(account);
    }
}
```

The complete [compilable example](../tests/e2e/fixtures/native-registry-view.sol)
uses Solidity `^0.8.24`. Native writes continue through direct transactions or
the independently activated AA native dispatcher; this view does not implement
contract-originated governance or AccountManager writes.

### Reproduce the contract view

Build with `cargo build -p shell-cli --features libp2p`. Use Node.js 20 or later,
a compatible source `shell-sdk` exposing transaction wire format v2
(`0.14.0-rc.1` tested), and a local `solc` package (`0.8.35` tested). From the
node repository:

```sh
SHELL_SDK_ENTRY=/path/to/shell-sdk/dist/index.js \
SOLC_ENTRY=/path/to/solc/index.js \
node tests/e2e/native-registry-view.mjs
```

The script compiles the example for Cancun and exercises real signed deployment,
activation-boundary reads, full-address membership, rejection paths and AA
calls on an isolated producer and follower. It also verifies unchanged valid
and tampered ML-DSA behavior at the original precompile, historical nonmutation,
finality and follower restart catch-up. Child processes stop on exit; fresh
keys and node data remain in the private temporary report directory. The fixture
uses one authority, not multiple-authority quorum, and does not prove public
SDK availability or live network activation. See the
[design decision](adr/native-registry-view.md).

### Events

The optional `native_validator_events_height` enables the indexed event format
below at and after the configured block. It defaults to disabled; existing
schedules can only be added at a future height and cannot subsequently change.
The same schedule must be used by producers, importers and historical replay;
trusted snapshots must match. This upgrade changes receipt logs and blooms,
so a source update alone does not activate it on any network.

After activation, topic 0 is the signature hash and topic 1 is the **complete
32-byte native validator identifier**; event data is empty. The signature keeps
its native `address` spelling. Direct transactions and activated native AA calls
use the same encoding. Only a quorum-reaching, committed membership change
emits an event; an accepted pending vote, rejected operation or reverted AA
bundle emits none. Log order follows successful inner-call order.

Before activation, direct calls retain the legacy single-topic event with a
zero-padded, truncated 20-byte member in the data word; AA calls retain their
legacy lack of native membership logs. Historical receipts retain the format
selected by their execution height. Do not query legacy events using topic 1.
The new encoding preserves full native identities for `eth_getLogs` filters;
standard Solidity address decoders cannot recover a native identity from a
legacy truncated word.

| Event | Signature | Emitted when |
|-------|-----------|-------------|
| `ValidatorAdded` | `ValidatorAdded(address indexed validator)` | Addition reaches quorum and commits |
| `ValidatorRemoved` | `ValidatorRemoved(address indexed validator)` | Removal reaches quorum and commits |

The existing [two-node Registry acceptance](../tests/e2e/native-aa-registry.mjs)
checks the event activation boundary, direct and AA full-address topics, failed
batch rollback, filtered RPC logs, block/receipt agreement, finality, historical
nonmutation and follower restart. Build with
`cargo build -p shell-cli --features libp2p`, then run:

```sh
SHELL_SDK_ENTRY=/path/to/shell-sdk/dist/index.js \
node tests/e2e/native-aa-registry.mjs
```

Use Node.js 20 or later and a compatible built source SDK (`0.14.0-rc.1` tested,
including its `viem` dependency). The fixture uses isolated nodes and fresh test
keys, stops child processes on exit and retains private test data. Its initially
single-authority producer keeps quorum weight when a candidate is added; it is
not a multi-authority availability test. Public SDK availability and network
activation are separate requirements. See the [event format decision](adr/native-validator-events.md).

### Access control

Only existing validators can call `addValidator` / `removeValidator`. Calls from
non-validators revert with `SystemContractError::Unauthorized`.

Writes are governed by weighted majority of the current active validator set:

- each validator address can vote once for an `(operation, target, validator-set)`
  tuple;
- the change is pending until voted weight is greater than half of current total
  validator weight;
- accepted changes update the validator set in world state and are reloaded by
  consensus at the configured epoch boundary;
- `addValidator` requires the target address to have a registered PQ public key
  in chain storage, so a newly legal validator can immediately verify/produce
  proposer seals;
- `removeValidator` cannot remove the last remaining validator.
- `setValidatorWeight` updates the in-memory and persisted validator weights used by wPoA proposer selection, finality, and slash-weight accounting.
- `proposeAlgorithmActivation` / `deprecateAlgorithm` update the runtime algorithm registry; clients can read the live state via `shell_getAlgorithmRegistry`.

### Algorithm Governance Protocol

Algorithm registry changes require a $\lceil 2N/3 \rceil$ weighted validator quorum.
The quorum must be met using **ML-DSA-65 or SLH-DSA-SHA2-256f** signatures only —
this dual-algorithm bootstrap safety rule ensures the governance process itself is
not bound to Dilithium3 even if Dilithium3 is later deprecated.

Each proposal has a unique ID derived as:
```text
proposal_id = BLAKE3(algo_id ‖ spec_bytes ‖ activation_height ‖ proposer_pk)
```

For activation enforcement, the optional `algorithm_quorum_activation_height`
requires recorded approval for proposals created at or after the configured block.
Legacy pending proposals retain their previous behavior; without this upgrade,
maturity processing can activate a proposal that has not reached quorum. The
first-vote pending transition is unchanged unless the independent
`algorithm_proposal_staging_height` is configured. With staging, sub-quorum
candidates leave live policy intact; the quorum-reaching vote publishes pending
parameters. See [proposal staging](CONSENSUS_DETAILS.md#algorithm-proposal-staging) and
[quorum compatibility and remaining limitations](CONSENSUS_DETAILS.md#algorithm-activation-quorum-guard).
The separate optional
`algorithm_voting_window_activation_height` adds seven-day nominal block expiry
for newly staged candidates; see [voting windows](CONSENSUS_DETAILS.md#algorithm-voting-window).
Older proposals retain their previous behavior. The independent
`algorithm_proposal_identity_height` enables complete installed-spec submission,
explicit ID-bound votes, duplicate-ID rejection and expired-candidate replacement.
See [proposal identity](#explicit-algorithm-proposal-identity) for the native ABI.

The white-paper target is **Δ_min = 30 days** (1,296,000 blocks at 2 s/block).
It is enforced from the explicitly configured `algorithm_timelock_activation_height`:
a vote in block `N` requires an algorithm activation height of at least
`N + 1,296,000`. Missing configuration and historical blocks before that upgrade
retain the legacy parent-height-plus-500,000 rule. The delay is checked for each
vote; finish shorter-delay voting rounds before upgrading. See
[activation and compatibility rules](CONSENSUS_DETAILS.md#algorithm-governance-timelock-activation).
This timelock upgrade does not complete the separate voting-window and emergency
signature-policy requirements.

---

## Explicit algorithm proposal identity

`algorithm_proposal_identity_height` is optional and disabled when omitted.
Its height must be at or after `algorithm_voting_window_activation_height`,
which itself requires proposal staging. Schedules are immutable once recorded;
existing databases accept only future activation heights. This changes no
network configuration automatically.

After activation, use these native ValidatorRegistry calls:

```solidity
function submitAlgorithmProposal(
    uint8 algo, bytes32 name, uint32 pkSize, uint32 sigSize,
    uint64 verifyGas, uint64 batchGas, bytes32 verifierHash,
    uint64 activationHeight
) external returns (bytes32 proposalId);
function voteAlgorithmProposal(uint8 algo, bytes32 proposalId)
    external returns (bool approved);
function getAlgorithmProposal(bytes32 proposalId) external view returns (
    uint8 algo, bytes32 name, uint32 pkSize, uint32 sigSize,
    uint64 verifyGas, uint64 batchGas, bytes32 verifierHash,
    uint64 activationHeight, uint64 deadline, bool approved
);
```

The native ABI requires exactly eight, two and one 32-byte argument words,
respectively, with zero-padded unsigned integers. Names are ASCII, right-padded
with zero bytes to 32 bytes. The accepted installed descriptors are:

| ID | Name | Public key bytes | Signature bytes | Verify gas | Batch gas per signature |
| --- | --- | ---: | ---: | ---: | ---: |
| 0 | Dilithium3 | 1952 | 3309 | 46000 | 12000 |
| 1 | ML-DSA-65 | 1952 | 3309 | 46000 | 12000 |
| 2 | SLH-DSA-SHA2-256f | 64 | 49856 | 2300000 | 0 (no batch entry point) |

Other descriptors and zero verifier hashes are rejected. This flow describes
installed algorithms; adding a new primitive or changing their execution costs
still requires a compatible client implementation. The verifier hash is bound
and stored, but matching it against reference verifier bytecode remains a
separate implementation requirement. Emergency dual-key signing policy and
signature admission for approved-but-not-yet-active algorithms are also separate
from this upgrade.

The proposal ID hashes the following concatenation with BLAKE3. All integers
use big-endian encoding, and there are no separators or ABI padding:

```text
algo:u8 || name:32 bytes || pkSize:u32 || sigSize:u32 ||
verifyGas:u64 || batchGas:u64 || verifierHash:32 bytes ||
requestedStatus:u8(Active=0) || activationHeight:u64 || proposerPublicKey:bytes
```

The key comes from the submitting validator's registered key in the executed
state. Submission opens a window and returns the ID without casting a vote or
changing live policy. Each active validator explicitly votes for that ID at most
once. Quorum is the ceiling of two thirds of current validator weight; votes of
removed validators do not count. Approval is persisted and is not recalculated
after validator changes. Each vote also enforces the applicable timelock.

At the exclusive deadline, voting fails. A different ID can replace the expired
candidate; changing the target height or proposer key changes the ID. Previously
used IDs remain rejected, and their votes never count toward the replacement.
Only one unexpired candidate per algorithm can be open. Once quorum publishes a
pending activation, replacement waits until that pending entry has matured or
been deprecated. The getter preserves full records and approval status even
after expiry or replacement; unknown IDs revert.

Before activation these selectors remain unknown. Legacy pending or staged
rounds can finish through their original ABI after activation, subject to their
existing deadline and timelock. An expired legacy staged round can be replaced
by a new explicit proposal. New unbound rounds are rejected after activation;
legacy calldata cannot vote on an explicit proposal. See the
[compatibility and encoding decision](adr/algorithm-proposal-identity.md).

## AccountManager

### Purpose

Allows accounts to:
1. **Rotate their PQ signing key** without changing address — critical for
   post-quantum key lifecycle management.
2. **Set a custom validation contract** — enables account abstraction patterns
   where transaction validation is handled by on-chain code.

### Interface

```solidity
interface IAccountManager {
    /// Rotate the caller's PQ public key.
    /// pubkey: raw Dilithium3, ML-DSA-65, or SPHINCS+ public key bytes
    /// algo:   0 = Dilithium3, 1 = ML-DSA-65, 2 = SPHINCS+-SHA2-256f
    function rotateKey(bytes calldata pubkey, uint8 algo) external;

    /// Configure guardian-based account recovery.
    function setGuardians(address[] calldata guardians, uint8 threshold, uint64 timelockBlocks) external;
    function submitRecovery(address target, bytes calldata newPubkey, uint8 algo) external;
    function executeRecovery(address target) external;
    function cancelRecovery(address target) external;

    /// Set a custom validator contract for this account.
    /// validationCodeHash: keccak256 hash of the deployed validator bytecode.
    ///   New validators should implement IAccountValidator.validateTransactionV2.
    ///   Legacy validateTransaction(bytes32,bytes,bytes) is used only as fallback.
    function setValidationCode(bytes32 validationCodeHash) external;

    /// Remove the custom validator — revert to default PQ signature check.
    function clearValidationCode() external;
}
```

### Function selectors

| Function | Selector | Access |
|----------|----------|--------|
| `rotateKey(bytes,uint8)` | `0xb746c079` | self only (`msg.sender == tx.origin account`) |
| `setValidationCode(bytes32)` | `0x0e3cf096` | self only |
| `clearValidationCode()` | `0xd1c4b175` | self only |
| `setGuardians(address[],uint8,uint64)` | computed at compile time | self only |
| `submitRecovery(address,bytes,uint8)` | computed at compile time | guardian only |
| `executeRecovery(address)` | computed at compile time | anyone (after timelock) |
| `cancelRecovery(address)` | computed at compile time | self only |

Guardian thresholds are vote counts, not percentages, and timelocks are measured
in blocks. An account with an active recovery proposal must call
`cancelRecovery` before replacing its guardian configuration so votes collected
under the old configuration cannot remain executable.

### Guardian recovery procedure

Use native AccountManager calls with full 32-byte Shell addresses. The interface
above lists selector signatures; use compatible SDK native calldata encoders,
not an Ethereum encoder that truncates `address` arguments to 20 bytes.

1. The account owner calls `setGuardians` with 1–5 distinct guardians, a required
   vote count from 1 to the guardian count, and a delay of at least 100 blocks.
   The owner cannot be one of its own guardians.
2. Each guardian signs its own `submitRecovery` transaction for the **same**
   target account, replacement public key, and algorithm. Use the intended
   algorithm ID (`0` Dilithium3, `1` ML-DSA-65, `2` SPHINCS+-SHA2-256f).
   One guardian submitting repeatedly contributes only one vote. A conflicting
   replacement key or algorithm is rejected while the proposal is active.
3. Wait for the threshold-reaching transaction's successful receipt. If it was
   included in block `N` and the configured delay is `D`, execution is first
   eligible in block `N + D`. The existing implementation stores the parent-head
   marker `N - 1 + D` and compares it with the execution block's parent head;
   do not interpret that marker as an eligible transaction inclusion height.
   Additional votes do not restart the delay. A successful individual vote
   receipt alone does not prove the threshold has been reached.
4. Once the delay has elapsed, any funded account may submit
   `executeRecovery(target)`. Confirm its successful receipt before using the
   replacement key. The account address is unchanged, and the proposal is
   removed. Subsequent transactions from the recovered account use its current
   nonce and replacement key. Key commitment semantics follow
   [the configured rotation activation](ACCOUNT_ABSTRACTION_GUIDE.md#persist-the-replacement-algorithm).
5. The account itself may instead call `cancelRecovery(target)` before
   execution, either below or above the voting threshold. Guardians cannot
   cancel on its behalf. Cancelling removes all collected votes; a new proposal
   starts from zero. Cancel an active proposal before changing guardians.

Recovery rotates the registered root key; it preserves the account's balance,
nonce, code and custom validation policy. Transaction fees and the submitting
account's nonce still follow ordinary transaction processing. A custom validator
must therefore authorize later transactions according to its own policy; root
key recovery does not remove that policy.

The native lifecycle regressions run in the existing test suite:

```bash
cargo test -p shell-pqvm submit_recovery_and_execute_rotates_key
cargo test -p shell-pqvm cancel_recovery
```

These tests cover distinct votes, the exact elapsed-block boundary, unchanged
account state on premature execution, successful key replacement, proposal
removal and cancellation isolation. They do not establish public SDK package
availability or activate a network upgrade.

### Key rotation example

Use a compatible `shell-sdk` native calldata encoder and a **signed** transaction.
The node binary is `shell-node`; it has no `encode-rotate-key`,
`encode-set-validation-code` or `encode-clear-validation-code` subcommands.
`shell_sendTransaction` accepts the signed Shell transaction structure, not an
unsigned Ethereum-style `{ from, to, data, gas }` object. The SDK constructs the
signed wire format for you.

Before broadcasting, securely store the replacement key. Load `currentSigner`
from the account's current keystore and `nextSigner` from the replacement
keystore, explicitly binding the replacement signer to the **existing full
32-byte account address**. Deriving a new address from the new public key would
create a different account. Construct the bound signer with
`new ShellSigner(loadedReplacement.signatureType, loadedReplacement.adapter, currentSigner.getAddress())`,
where `loadedReplacement` is the decrypted replacement signer and `ShellSigner`
is imported from `shell-sdk`. Keep the replacement keystore unchanged and store
the existing account address separately so you can restore this binding on reload.
The two signer objects share the adapter; dispose them only after signing is done.
This example assumes the existing account is funded and uses the built-in PQ
validation policy; an installed custom policy must also authorize the operation.

The following SDK code submits the rotation after `provider`, `currentSigner`
and `nextSigner` have been initialized for the intended network:

```javascript
import {
  accountManagerAddress,
  buildTransaction,
  encodeRotateKeyCalldata,
} from "shell-sdk";

const account = currentSigner.getAddress();
if (nextSigner.getAddress() !== account) {
  throw new Error("Bind the replacement signer to the existing account address");
}
const chainId = Number(BigInt(await provider.client.request({
  method: "eth_chainId", params: [],
})));
const nonce = Number(BigInt(await provider.client.request({
  method: "eth_getTransactionCount", params: [account, "pending"],
})));
const tx = buildTransaction({
  chainId,
  nonce,
  to: accountManagerAddress,
  value: 0n,
  data: encodeRotateKeyCalldata(nextSigner.getPublicKey(), nextSigner.algorithmId),
  gasLimit: 3000000,
});
const signed = await currentSigner.buildSignedTransaction({
  tx,
  includePublicKey: true,
});
const hash = await provider.sendTransaction(signed);
```

Use the **current key** to authorize rotation. Poll `eth_getTransactionReceipt`
for `hash` and require `status === "0x1"`; submission alone is not success.
Then query `shell_getPqPubkey(account)` and compare it with the replacement public
key. Only after successful inclusion should subsequent transactions use
`nextSigner` and a freshly queried nonce. The address stays unchanged. With the
built-in validation policy, the old key is rejected after replacement.

The signed wire format must match the node version. Source SDK `0.14.0-rc.1`
was used for this acceptance; availability from npm is a separate prerequisite.
Algorithm binding, key commitments and legacy compatibility depend on the
[configured rotation activation](ACCOUNT_ABSTRACTION_GUIDE.md#persist-the-replacement-algorithm). No network upgrade is activated
by running these examples.

### Custom validation code

The native `setValidationCode(bytes32)` method takes the **Keccak-256 hash of
already deployed runtime bytecode**, not a contract address or creation bytecode
hash. Use a policy that implements the account validation ABI and authorizes its
own update or removal. A permissive test policy is not account authentication.

Use the same signed transaction construction above, replacing `data` with one of
these SDK encoder results:

```javascript
import {
  encodeSetValidationCodeCalldata,
  encodeClearValidationCodeCalldata,
} from "shell-sdk";

const setData = encodeSetValidationCodeCalldata(validationCodeHash);
const clearData = encodeClearValidationCodeCalldata();
```

Submit each operation separately with the current signer and nonce, wait for a
successful receipt, then verify the intended allowed and rejected behavior.
Setting a policy does not change the root key; clearing it restores built-in PQ
verification using the currently registered key. A policy that rejects its own
clear operation cannot be bypassed merely by supplying that calldata. See the
[account validation guide](ACCOUNT_ABSTRACTION_GUIDE.md) for the ABI and execution rules.

### Reproduce the AccountManager lifecycle

From a node checkout containing the
[lifecycle acceptance script](../tests/e2e/native-aa-lifecycle.mjs), use Node.js 20 or later and a compatible built
source SDK (`0.14.0-rc.1` tested):

```sh
cargo build -p shell-cli
SHELL_SDK_ENTRY=/path/to/shell-sdk/dist/index.js \
node tests/e2e/native-aa-lifecycle.mjs
```

This isolated test provisions fresh funded accounts, exercises direct signed
rotation, rejects the unsigned request shape, verifies replacement-key success
and stale-key rejection before and after restart, and replays historical
transactions without changing current state. It also tests native AA guardian
recovery and custom policy set/replace/clear, including rollback after a later
inner call fails. Its value-filter policies are test-only and do not authenticate
users. The test uses explicit dev mining and synthetic timestamps, stops its
node on exit, and retains keys, node data and results in a private temporary
directory. It does not demonstrate public SDK availability or network activation.

---

## Gas costs

System contract calls use a flat base gas charge:

| Operation | Gas |
|-----------|-----|
| `addValidator` | `SYSTEM_CALL_BASE_GAS` + state write |
| `removeValidator` | `SYSTEM_CALL_BASE_GAS` + state write |
| `getValidators` | `SYSTEM_CALL_BASE_GAS` + read × n |
| `isValidator` | `SYSTEM_CALL_BASE_GAS` + read |
| `rotateKey` | `SYSTEM_CALL_BASE_GAS` + pubkey write |
| `setValidationCode` | `SYSTEM_CALL_BASE_GAS` + hash write |
| `clearValidationCode` | `SYSTEM_CALL_BASE_GAS` + delete |

`SYSTEM_CALL_BASE_GAS` is a constant defined in `shell-pqvm` — use
`shell_estimateGovernanceGas` to get accurate estimates before submitting.

---

## Implementation notes

- System contracts are **intercepted by the PQVM/revm execution adapter** before bytecode
  execution. There is no bytecode at these addresses — `eth_getCode` returns an
  empty result.
- Both contracts produce standard EVM-style `logs` (topics + data) that appear
  in `eth_getLogs` responses.
- State is stored in the `WorldState` trie alongside regular account state —
  system contract storage is persistent and survives node restarts.
- System contracts do **not** use ABI-encoded reverts. Errors are translated to
  EVM-style failures (empty returndata, gas consumed).
