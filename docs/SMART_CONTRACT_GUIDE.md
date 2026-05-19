# Smart Contract Deployment Guide

Deploy and interact with smart contracts on Shell-Chain.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) · [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md) · [Native Account Abstraction Guide](ACCOUNT_ABSTRACTION_GUIDE.md)

---

## Overview

Shell-Chain is fully EVM-compatible (Cancun spec). Any contract written in Solidity or Vyper that compiles to EVM bytecode will work on Shell-Chain without modification. Standard tooling — Hardhat, Foundry, Remix — all work out of the box.

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
| **Alpha Testnet** | `http://testnet.shell.xyz` | 10 |

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
      url: "http://testnet.shell.xyz",
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
forge create --rpc-url http://testnet.shell.xyz --chain-id 10 src/Counter.sol:Counter
```

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
      "to":"pq1YOUR_CONTRACT_ADDRESS",
      "data":"0x6d4ce63c"
    },"latest"],
    "id":1
  }'
```

Or with Hardhat:

> **Compatibility note:** Shell-native EOA and contract addresses use bech32m `pq1...` format. Tooling that hardcodes 20-byte hex inputs (e.g., default Hardhat scripts) will fail at the Shell RPC boundary; use the shell-sdk pq1 helpers.

```js
const counter = await hre.ethers.getContractAt("Counter", "pq1...YOUR_CONTRACT_PQ1_ADDRESS");
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
const counter = await hre.ethers.getContractAt("Counter", "pq1...YOUR_CONTRACT_PQ1_ADDRESS");
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
      "from": "pq1YOUR_ADDRESS",
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

- **`ecrecover` (0x01) is disabled.** The precompile exists at address `0x01` but is a no-op — it returns empty bytes to force PQ migration. Contracts that call `ecrecover` will receive an empty result, not `address(0)`. Do not rely on it.
- **Use the PQ precompile instead.** See [PQ_DILITHIUM_VERIFY precompile](#pq_dilithium_verify-precompile-0x0100) below.

### PQ_DILITHIUM_VERIFY precompile (`0x0100`)

Shell-Chain exposes a native Dilithium3 signature verification precompile at address `0x0000000000000000000000000000000000000100`.

**Gas cost:** 10,000 (flat, regardless of message length)

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
    address constant PQ_PRECOMPILE = 0x0000000000000000000000000000000000000100;

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
         "to":"pq1YOUR_CONTRACT_ADDRESS",
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

*Last updated: 2026-05-13*
