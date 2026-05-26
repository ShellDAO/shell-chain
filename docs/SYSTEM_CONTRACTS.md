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
    function proposeAlgorithmActivation(uint8 algo) external;
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
| `proposeAlgorithmActivation(uint8)` | `0x487aee59` | validators only |
| `deprecateAlgorithm(uint8)` | `0xa4b88278` | validators only |
| `getValidators()` | `0xb7ab4db5` | anyone |
| `isValidator(address)` | `0xfacd743b` | anyone |

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

The minimum delay between proposal and activation is **Δ_min = 30 days** (approximately
1,296,000 blocks at 2 s/block). This prevents rapid algorithm switches that could
destabilise the network.

---

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
    function setGuardians(address[] calldata guardians, uint8 thresholdPct, uint64 timelockSecs) external;
    function submitRecovery(address target, bytes calldata signature, uint8 algo) external;
    function executeRecovery(address target) external;
    function cancelRecovery(address target) external;

    /// Set a custom validator contract for this account.
    /// validationCodeHash: keccak256 hash of the deployed validator bytecode.
    ///   The contract at that address must implement IAccountValidator.
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
