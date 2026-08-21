# Smart Contract Deployment Guide

Deploy and interact with smart contracts on Shell-Chain.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) · [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md) · [Native Account Abstraction Guide](ACCOUNT_ABSTRACTION_GUIDE.md)

---

## Overview

Shell-Chain runs the **PQVM** (Post-Quantum Virtual Machine): an execution environment that retains Cancun-style arithmetic, memory, storage, logs, and control flow while replacing Ethereum's classical cryptographic surfaces.

Key differences from standard Ethereum execution:

1. **`SELFDESTRUCT` and `CALLCODE` are removed** — these opcodes are unavailable in PQVM-1.
2. **32-byte native addresses** — Shell-Chain addresses are 32-byte BLAKE3 digests (not 20-byte keccak truncations). The PQABI encoding uses a 32-byte full slot for addresses.
3. **PQ-native authentication** — transactions use PQ signatures and PQTx semantics, not ECDSA EOAs.

For retained non-cryptographic opcodes, Shell-Chain keeps EVM-familiar behavior. Standard tooling such as Hardhat, Foundry, and Remix can be used with the caveats above and Shell-aware address/signing support.

---

## Prerequisites

- **Node.js** 18+ (for Hardhat)
- **Hardhat** or **Foundry** installed
- A running shell-chain node (see [Quickstart](QUICKSTART.md))
- A funded account (pre-allocated in genesis or received via transfer)

---

## Connecting to Shell Chain

| Network | RPC URL | Chain ID |
|---------|---------|----------|
| **Local** | `http://localhost:8545` | 1337 |
| **Public Testnet** | `https://testnet-rpc.shell.org` | 10 |

The local endpoint is the default JSON-RPC server started by `shell-node run`. The alpha testnet endpoint is served via nginx reverse proxy (see [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md)).

---

## Hardhat Setup

### Install Hardhat

```bash
mkdir my-shell-project && cd my-shell-project
npm init -y
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat init
```

### Configure networks

```js
// hardhat.config.js
module.exports = {
  solidity: "0.8.26",
  networks: {
    shell: {
      url: "http://localhost:8545",
      chainId: 1337,
    },
    shellAlpha: {
      url: "https://testnet-rpc.shell.org",
      chainId: 10,
    }
  }
};
```

Deploy to a local node:

```bash
npx hardhat run scripts/deploy.js --network shell
```

Deploy to the alpha testnet:

```bash
npx hardhat run scripts/deploy.js --network shellAlpha
```

---

## Foundry Setup

### Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Deploy with Foundry

```bash
forge create --rpc-url http://localhost:8545 --chain-id 1337 src/Counter.sol:Counter
```

For the alpha testnet:

```bash
forge create --rpc-url https://testnet-rpc.shell.org --chain-id 10 src/Counter.sol:Counter
```

---

## PQVM Native Opcodes

Shell-Chain adds three post-quantum opcodes not present in the standard EVM:

| Opcode | Hex | Gas | Description |
|--------|-----|-----|-------------|
| `PQVERIFY` | `0xB0` | 46,000 (ML-DSA-65) | Verify a PQ signature on-chain |
| `PQHASH` | `0xB1` | `30 + 6 × ⌈len/32⌉` | BLAKE3 hash of input data |
| `PQADDR` | `0xB2` | `200 + 6 × ⌈pk_len/32⌉` | Derive a 32-byte address from algo_id + pubkey |

The runtime installs all three opcodes in the PQVM interpreter. `PQADDR`
uses stack input `algo_id, pk_ptr, pk_len, out_ptr`, reads the public key from
memory, and writes `BLAKE3(algo_id || pubkey)` as a 32-byte Shell address.
Unknown `algo_id` values write the zero address.

### Precompile addresses (0x0001–0x0006)

| Address | Function | Input wire format |
|---------|----------|------------------|
| `0x...0001` | ML-DSA-family Verify (ML-DSA-65 primary, Dilithium3 legacy) | `[4-byte pk_len][pk][4-byte msg_len][msg][sig]` |
| `0x...0002` | SLH-DSA-SHA2-256f Verify | `[pk (64 B)][sig (49 856 B)][msg]` |
| `0x...0003` | ML-DSA-65 Batch Verify | `[4-byte count][sig_0]...[sig_n]` |
| `0x...0004` | BLAKE3-256 Hash | raw bytes → 32-byte digest |
| `0x...0005` | BLAKE3-512 Hash | raw bytes → 64-byte digest |
| `0x...0006` | PQ Address Derive | `[1-byte algo_id][pubkey]` → 32-byte address |

Use the 32-byte precompile address `0x0000...000N` (31 zero bytes + 1 index byte).

---

## Example: Deploy a Counter Contract

### 1. Write the contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Counter {
    uint256 public count;

    event CountChanged(uint256 newCount);

    function get() public view returns (uint256) {
        return count;
    }

    function increment() public {
        count += 1;
        emit CountChanged(count);
    }

    function decrement() public {
        require(count > 0, "Counter: cannot decrement below zero");
        count -= 1;
        emit CountChanged(count);
    }

    function reset() public {
        count = 0;
        emit CountChanged(count);
    }
}
```

### 2. Deploy with Hardhat

Create `scripts/deploy.js`:

```js
const hre = require("hardhat");

async function main() {
  const Counter = await hre.ethers.getContractFactory("Counter");
  const counter = await Counter.deploy();
  await counter.waitForDeployment();
  console.log("Counter deployed to:", await counter.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

```bash
npx hardhat run scripts/deploy.js --network shell
```

### 3. Deploy with Foundry

```bash
forge create \
  --rpc-url http://localhost:8545 \
  --chain-id 1337 \
  src/Counter.sol:Counter
```

---

## Interacting with a Deployed Contract

### Read calls (no gas required)

Use `eth_call` to read state without submitting a transaction:

```bash
# Call the get() function (selector: 0x6d4ce63c)
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"eth_call",
    "params":[{
      "to":"0xYOUR_CONTRACT_ADDRESS",
      "data":"0x6d4ce63c"
    },"latest"],
    "id":1
  }'
```

Or with Hardhat:

> **Compatibility note:** Shell-native EOA and contract addresses use canonical 32-byte `0x...` format. Tooling that hardcodes 20-byte hex inputs (e.g., default Hardhat scripts) will fail at the Shell RPC boundary; use 32-byte hex addresses end-to-end.

```js
const counter = await hre.ethers.getContractAt("Counter", "0x...YOUR_CONTRACT_ADDRESS");
const count = await counter.get();
console.log("Current count:", count.toString());
```

### Write calls (submits a transaction)

Use `eth_sendRawTransaction` or `shell_sendTransaction` to modify state:

```bash
# Increment the counter (selector: 0xd09de08a)
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"eth_sendRawTransaction",
    "params":["0x...signed_tx_bytes..."],
    "id":1
  }'
```

Or with Hardhat:

```js
const counter = await hre.ethers.getContractAt("Counter", "0x...YOUR_CONTRACT_ADDRESS");
const tx = await counter.increment();
await tx.wait();
console.log("Incremented! New count:", (await counter.get()).toString());
```

---

## Using PQ Signatures for Deployment

Shell-Chain uses post-quantum Dilithium3 signatures instead of ECDSA. To deploy contracts using PQ signatures, use the `shell_sendTransaction` RPC method:

```bash
# Sign the deployment transaction with the shell-node CLI
shell-node tx deploy \
  --code 0x608060405234801561001057600080fd5b50... \
  --keystore my-key.json \
  --rpc-url http://127.0.0.1:8545

# Or submit via JSON-RPC
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"shell_sendTransaction",
    "params":[{
      "from": "0xYOUR_ADDRESS",
      "data": "0x608060405234801561001057600080fd5b50...",
      "gas": "0x100000",
      "maxFeePerGas": "0x5f7609",
      "maxPriorityFeePerGas": "0x0",
      "nonce": "0x0",
      "pqSignature": "0x...dilithium3_signature...",
      "pqPubkey": "0x...dilithium3_pubkey..."
    }],
    "id":1
  }'
```

> **Fee note:** `maxFeePerGas` is only an example. In real deployments, query
> `eth_gasPrice` and use a value greater than or equal to the current base fee.
>
> **Note:** Standard Ethereum wallets (MetaMask, etc.) use ECDSA signatures. For full PQ security, use the `shell-node` CLI or PQ-aware SDKs. See [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md) for details.

---

## Verifying Contracts with debug_traceTransaction

After deploying a contract, use `debug_traceTransaction` to inspect the execution trace:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"debug_traceTransaction",
    "params":["0xYOUR_TX_HASH"],
    "id":1
  }' | python3 -m json.tool
```

The trace shows the full call tree including:
- `CREATE` / `CREATE2` frames for contract deployment
- Gas consumption per opcode
- Storage reads and writes
- Internal calls between contracts

> **Note:** The `debug` namespace must be enabled on the node with `--rpc-api eth,net,web3,shell,debug`.

---

## EVM Compatibility Notes

Shell-Chain implements the **Cancun** EVM specification. Key compatibility details:

### Supported Cancun opcodes

| Opcode | EIP | Description |
|--------|-----|-------------|
| `TSTORE` / `TLOAD` | EIP-1153 | Transient storage (cleared after each tx) |
| `MCOPY` | EIP-5656 | Efficient memory copy |
| `BLOBHASH` | EIP-4844 | Access blob versioned hashes |
| `BLOBBASEFEE` | EIP-7516 | Read blob base fee |

### Signature behavior

- **Ethereum `ecrecover` is unavailable.** Address `0x01` is repurposed for
  ML-DSA-family verification. ECDSA-formatted calldata is interpreted as PQ
  verifier input and returns the 32-byte false value, not an Ethereum address.
- **Use the PQ precompile suite instead.** The current runtime exposes six native precompiles at `0x0001`–`0x0006`.

### PQ precompile suite (`0x0001`–`0x0006`)

| Address | Function | Gas model |
|---------|----------|-----------|
| `0x0000000000000000000000000000000000000001` | ML-DSA-family verify (ML-DSA-65 primary, Dilithium3 legacy) | flat `46,000` |
| `0x0000000000000000000000000000000000000002` | SLH-DSA-SHA2-256f verify | flat `2,300,000` |
| `0x0000000000000000000000000000000000000003` | ML-DSA-65 batch verify | `12,000 × sig_count` |
| `0x0000000000000000000000000000000000000004` | BLAKE3-256 hash | `30 + 6 × ⌈len/32⌉` |
| `0x0000000000000000000000000000000000000005` | BLAKE3-512 hash | `30 + 6 × ⌈len/32⌉` |
| `0x0000000000000000000000000000000000000006` | PQ address derive | `200 + 6 × ⌈pubkey_len/32⌉` |

The verify precompile uses the ML-DSA-65/Dilithium-compatible wire format below.

**Input format** (length-prefixed binary, no ABI encoding):
```
[4 bytes: pubkey_len  (big-endian u32)] [pubkey bytes]
[4 bytes: msg_len     (big-endian u32)] [message bytes]
[remaining bytes]                       [signature bytes]
```

**Output:** 32 bytes — `0x...01` if valid, `0x...00` if invalid or any error.

**Example (Solidity):**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library PQVerify {
    address constant PQ_PRECOMPILE = 0x0000000000000000000000000000000000000001;

    /// Verify a Dilithium3 signature. Returns true on valid.
    function verify(
        bytes memory pubkey,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        bytes memory input = abi.encodePacked(
            uint32(pubkey.length), pubkey,
            uint32(message.length), message,
            signature
        );
        (bool ok, bytes memory result) = PQ_PRECOMPILE.staticcall(input);
        return ok && result.length >= 32 && result[31] == 0x01;
    }
}
```

### Transaction types supported

| Type | EIP | Description |
|------|-----|-------------|
| Legacy (type 0) | — | Traditional transactions |
| Access list (type 1) | EIP-2930 | Transactions with access lists for gas savings |
| EIP-1559 (type 2) | EIP-1559 | Dynamic fee transactions with base fee + priority fee |
| Blob (type 3) | EIP-4844 | Blob-carrying transactions for data availability |

### Gas model

Shell-Chain uses the **EIP-1559** gas model:
- `baseFeePerGas` adjusts per-block based on gas utilization
- `maxPriorityFeePerGas` is always `0x0` on this PoA chain
- Use `eth_gasPrice` to get the current base fee
- Use `eth_feeHistory` for historical fee data

---

## Gas Estimation Tips

1. **Use `eth_estimateGas`** before submitting transactions. The estimate includes a 20% buffer (gas_used × 1.2) with a minimum of 21,000.

2. **Check the base fee** with `eth_gasPrice`. Set `maxFeePerGas` ≥ the base fee or the transaction will be rejected.

3. **Access lists save gas** for contracts that touch many storage slots. Use `eth_createAccessList` to generate one:

   ```bash
   curl -s http://localhost:8545 \
     -H "Content-Type: application/json" \
     -d '{
        "jsonrpc":"2.0",
        "method":"eth_createAccessList",
        "params":[{
         "to":"0xYOUR_CONTRACT_ADDRESS",
         "data":"0x..."
        },"latest"],
        "id":1
     }'
   ```

4. **Transient storage** (`TSTORE`/`TLOAD`) is cheaper than regular storage for data only needed within a single transaction.

5. **Gas limit** is set in genesis (default: 30,000,000). Check with `eth_getBlockByNumber`.

---

## Further Reading

- [JSON-RPC API Reference](JSON_RPC_API.md) — Full list of all 79 RPC methods
- [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md) — Post-quantum signature details
- [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) — Running testnet nodes
- [Quickstart Guide](QUICKSTART.md) — Get a node running in 5 minutes

---

*Last updated: 2026-06-17*
