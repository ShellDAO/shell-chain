# System Contracts

Shell-Chain ships two native system contracts. They live at well-known addresses
and are executed as native Rust code — no Solidity bytecode, no compiler needed.
The PQVM/revm execution adapter intercepts calls to these addresses before
running bytecode.

---

## Addresses

| Contract | Address | Description |
|----------|---------|-------------|
| `ValidatorRegistry` | `0x0000000000000000000000000000000000000000000000000000000000000001` | Manages the active validator set |
| `AccountManager` | `0x0000000000000000000000000000000000000000000000000000000000000002` | Per-account PQ key rotation and custom validation code |

---

## ValidatorRegistry

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

Shell-Chain system contracts live in the native 32-byte address space. When calling
from Solidity tooling that still models `address` as 20 bytes, use the alloy/EVM shim:
the last 20 bytes of the native 32-byte address are passed into the contract constant below.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IValidatorRegistry {
    function getValidators() external view returns (address[] memory);
    function isValidator(address account) external view returns (bool);
}

contract ValidatorCheck {
    // Shell-Chain addresses are 32 bytes; use the last 20 bytes for the alloy/EVM shim
    IValidatorRegistry constant REGISTRY =
        IValidatorRegistry(0x0000000000000000000000000000000001);

    function currentValidators() external view returns (address[] memory) {
        return REGISTRY.getValidators();
    }

    function amIAValidator() external view returns (bool) {
        return REGISTRY.isValidator(msg.sender);
    }
}
```

### Events

| Event | Signature | Emitted when |
|-------|-----------|-------------|
| `ValidatorAdded` | `ValidatorAdded(address indexed validator)` | `addValidator` succeeds |
| `ValidatorRemoved` | `ValidatorRemoved(address indexed validator)` | `removeValidator` succeeds |

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

### Key rotation example

```bash
# Encode a rotateKey calldata with shell-node
shell-node encode-rotate-key --pubkey /path/to/new_pubkey.bin --algo dilithium3

# Submit via RPC
curl -s http://localhost:8545 -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"shell_sendTransaction",
    "params":[{
      "from": "0xMYADDRESS",
      "to":   "0x0000000000000000000000000000000000000000000000000000000000000002",
      "data": "0x<rotateKey calldata>",
      "gas":  "0x186a0"
    }],
    "id":1
  }'
```

After the transaction is included, future transactions from `0xMYADDRESS` are
validated using the new key. The old key is invalidated immediately.

### Custom validation code

Setting `validationCode` delegates transaction validation for this account to
the contract at the specified code hash. This is the foundation of Shell-Chain's
native account abstraction. See [ACCOUNT_ABSTRACTION_GUIDE.md](ACCOUNT_ABSTRACTION_GUIDE.md)
for the full `IAccountValidator` interface and examples.

```bash
# Set validation code
shell-node encode-set-validation-code --code-hash 0xabc123...

# Clear (revert to PQ default)
shell-node encode-clear-validation-code
```

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
