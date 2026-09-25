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

- **Node.js** 20+
- A **matching shell-sdk source build** for compilation, PQ-native signing, Shell 32-byte address handling, and contract calls
- **solc 0.8.30+** for Node-side Solidity compilation, plus **tsx** to run the TypeScript examples
- A running local shell-chain node built from the verified revision below (see [Quickstart](QUICKSTART.md))
- A funded account (pre-allocated in genesis or received via transfer)

### Match the node and SDK

The npm release `shell-sdk@0.13.0` uses the V1 transaction signing format.
The current node source requires V2, which also commits the transaction's
access list. Mixing these versions fails with `PQ signature verification failed`.
The SDK source already implements V2; use the verified source pair for this
local tutorial until a compatible npm release is available:

| Component | Verified source revision |
|-----------|--------------------------|
| shell-chain | [`e5e759c`](https://github.com/ShellDAO/shell-chain/commit/e5e759c68948e30ccff671bfe9cb7041f0bbec10) |
| shell-sdk | [`86c5b68`](https://github.com/ShellDAO/shell-sdk/commit/86c5b689ecaeb41c3cdc883af865cac4e30bab07) |

Build the node from that revision using the Quickstart, then create a separate
SDK checkout and local example project:

```bash
git clone --no-checkout https://github.com/ShellDAO/shell-sdk.git
cd shell-sdk
git checkout 86c5b689ecaeb41c3cdc883af865cac4e30bab07
npm ci
npm run build
npm pack
cd ..

mkdir shell-counter
cd shell-counter
npm init -y
npm pkg set type=module
npm install ../shell-sdk/shell-sdk-0.13.0.tgz
npm install --save-dev solc@^0.8.30 tsx
mkdir -p contracts scripts
```

The source archive still has `0.13.0` in its filename; it contains the pinned
source revision above and is different from the npm registry release.
The SDK's compiler dependency is optional so browser applications can use the
runtime helpers without bundling Solidity tooling. Install `solc` explicitly
for the compiler and CLI examples below. Use the funded `my-key.json` from the
Quickstart, or set `SHELL_KEYSTORE_PATH` to its location; keep the keystore and
password out of source control.

---

## Connecting to Shell Chain

| Network | RPC URL | Chain ID |
|---------|---------|----------|
| **Local** | `http://localhost:8545` | 1337 |
| **Public Testnet** | `https://testnet-rpc.shell.org` | 10 |

The local endpoint is the default JSON-RPC server started by `shell-node run`. The alpha testnet endpoint is served via nginx reverse proxy (see [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md)).

---

## Deployment tools and signing

Use the Shell SDK or `shell-node tx deploy` for deployment. Both produce
post-quantum signatures and submit the native transaction format. The complete
Counter example below compiles, deploys, waits for confirmation, writes state,
and reads the result.

Hardhat, Foundry, and Remix can help compile Solidity or inspect artifacts.
Their default Ethereum signer/deployment flows do not provide Shell-native
signing or 32-byte address handling. Configure any custom integration to use
the Shell SDK for transactions; an RPC URL and chain ID alone are insufficient.
For a standalone Hardhat project, use its current `npx hardhat --init` command
and supported configuration; it is not a prerequisite for this tutorial.

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

Save this as `contracts/Counter.sol`:

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

### 2. Compile and deploy with Shell SDK

Create `scripts/deploy-counter.ts`:

```ts
import { readFile } from "node:fs/promises";
import { createShellProvider, decryptKeystore } from "shell-sdk";
import { deployContract, readContract, writeContract } from "shell-sdk/contracts";
import { compileSolidity } from "shell-sdk/contracts/compiler";

const rpcHttpUrl = process.env.SHELL_RPC_URL ?? "http://127.0.0.1:8545";
const chainId = Number(process.env.SHELL_CHAIN_ID ?? 1337);
const keystorePath = process.env.SHELL_KEYSTORE_PATH ?? "my-key.json";
const password = process.env.SHELL_KEYSTORE_PASSWORD;

if (!password) {
  throw new Error("Set SHELL_KEYSTORE_PASSWORD before deploying");
}

const provider = createShellProvider({ rpcHttpUrl });
const keystore = JSON.parse(await readFile(keystorePath, "utf8"));
const signer = await decryptKeystore(keystore, password);

const artifact = await compileSolidity({
  sources: [{ path: "contracts/Counter.sol" }],
  contractName: "Counter",
  outputPath: "artifacts/Counter.json",
});

const deployed = await deployContract({
  provider,
  signer,
  chainId,
  artifact,
  gasLimit: 1_500_000,
  wait: true,
});

console.log("contract:", deployed.contractAddress);

await writeContract({
  provider,
  signer,
  chainId,
  address: deployed.contractAddress!,
  abi: artifact.abi,
  functionName: "increment",
  gasLimit: 120_000,
  wait: true,
});

const count = await readContract({
  provider,
  address: deployed.contractAddress!,
  abi: artifact.abi,
  functionName: "get",
});

console.log("count:", count);
```

Run it against a local node:

```bash
SHELL_RPC_URL=http://127.0.0.1:8545 \
SHELL_CHAIN_ID=1337 \
SHELL_KEYSTORE_PATH=my-key.json \
SHELL_KEYSTORE_PASSWORD=dev-password \
npx tsx scripts/deploy-counter.ts
```

The script should print a 32-byte contract address and `count: 1n`: deployment
and the increment transaction have both confirmed, and the read returns the
updated state.

For public testnet, first confirm that the deployed node and SDK use the same
signing format; the source pair above is verified against a local node only.
Then set `SHELL_RPC_URL=https://testnet-rpc.shell.org`, `SHELL_CHAIN_ID=10`,
and use a funded Shell keystore.

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

Use the SDK CLI to read the same value (replace `0x...` with the complete
32-byte address printed by deployment):

```bash
npx shell-sdk contract read --artifact artifacts/Counter.json --address 0x... --function get
```

### Write calls (submits a transaction)

Use the same funded keystore as deployment. Set `SHELL_KEYSTORE_PASSWORD` in
your shell to its password first; the inline assignment for the earlier
TypeScript command does not persist. The SDK CLI waits for a successful receipt
before returning:

```bash
npx shell-sdk contract write --artifact artifacts/Counter.json --address 0x... --function increment --keystore my-key.json --password "$SHELL_KEYSTORE_PASSWORD"
npx shell-sdk contract read --artifact artifacts/Counter.json --address 0x... --function get
```

After the TypeScript example's first increment, this additional increment should
produce a successful receipt and a read of `"2"`. A write that reverts must not
be treated as successful just because its transaction was submitted.

---

## Using the node CLI for deployment

The node CLI can deploy the same compiled artifact. Supply its full init bytecode
and a password file for the funded keystore:

```bash
CODE=$(node --input-type=module -e 'import fs from "node:fs"; console.log(JSON.parse(fs.readFileSync("artifacts/Counter.json", "utf8")).bytecode)')
TX_HASH=$(shell-node --password-file .quickstart-password tx deploy \
  --code "$CODE" \
  --keystore my-key.json \
  --chain-id 1337 \
  --rpc-url http://127.0.0.1:8545)
```

Use the password file created in the [Quickstart](QUICKSTART.md), or provide the
correct password file for your keystore. Keep it out of source control.
Submission returns a transaction hash, not a confirmation. Query its receipt:

```bash
shell-node tx receipt "$TX_HASH" --rpc-url http://127.0.0.1:8545
```

A `null` receipt is still pending. Poll the same hash until a receipt is
available, require `status: "0x1"`, and use its `contractAddress` for reads.
A failed receipt must not be treated as a deployed contract. This fresh Counter
starts at zero; it is a separate deployment from the SDK example.

```bash
shell-node tx call --to 0x... --data 0x6d4ce63c --rpc-url http://127.0.0.1:8545
```

The read returns a zero-filled 32-byte ABI word. `shell_sendTransaction` expects
a fully signed native transaction envelope; use these helpers to construct it
instead of submitting a flat object with `pqSignature`/`pqPubkey` placeholder fields.

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

The trace replays the transaction from its block’s parent state, including earlier
transactions in that block. It returns the executed call tree and `structLogs`
opcode observations, including:
- `CREATE` / `CREATE2` frames for contract deployment
- Gas consumption per opcode
- Storage reads and writes
- Internal calls between contracts

> **Note:** The `debug` namespace must be enabled on the node with `--rpc-api eth,net,web3,shell,debug`.

The call tree includes actual return or revert bytes; failed nested calls remain
visible even when their state changes are rolled back. `structLogs` records
`pc`, `op`, `gas`, `gasCost`, `depth`, operand `stack`, hexadecimal `memory`, and
accessed `storage` slots for `SLOAD` / `SSTORE`. The trace does not commit changes
to the node. Use `disableStack`, `disableMemory`, or `disableStorage` in an
optional second parameter to omit those payloads; nested calls remain included.

Tracing requires the parent state to be retained. Capture is limited to 50,000
instructions and 8 MiB per transaction, with a 16 MiB block response limit and
two concurrent replays. Missing state, receipt mismatches, or exhausted limits
return an error rather than a partial successful trace. Native system-contract
transactions and prefixes containing them also return an error until their
historical address metadata can be reconstructed safely; ordinary contract
calls, deployments, and AA execution are replayed through the normal executor.


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
