//! Shared test utilities for E2E tests.
//!
//! Provides a [`TestEnv`] that wires up an in-memory chain store, world state,
//! mempool, and RPC handler — mirroring the real node without network or disk I/O.

use std::sync::Arc;

use parking_lot::RwLock;

use shell_consensus::FinalityState;
use shell_core::{Block, BlockHeader, SignedTransaction, Transaction, TransactionReceipt};
use shell_crypto::{DilithiumSigner, SignatureType, Signer};
use shell_mempool::TxPool;
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_rpc::RpcHandler;
use shell_storage::{ChainStore, MemoryDb, WorldState};

/// Chain ID used across all E2E tests.
pub const TEST_CHAIN_ID: u64 = 42;

/// Pre-allocated balance for funded test accounts.
pub const FUNDED_BALANCE: u64 = 1_000_000_000_000_000; // 1e15

/// A complete test environment with accessible inner components.
pub struct TestEnv {
    pub handler: RpcHandler<MemoryDb>,
    pub chain_store: Arc<ChainStore<MemoryDb>>,
    pub world_state: Arc<RwLock<WorldState<MemoryDb>>>,
    pub tx_pool: Arc<TxPool>,
}

/// Creates a fresh in-memory test environment matching the pattern used by the
/// RPC handler's own unit tests.
pub fn setup() -> TestEnv {
    let db = Arc::new(MemoryDb::new());
    let chain_store = Arc::new(ChainStore::new(db.clone()));
    let world_state = Arc::new(RwLock::new(WorldState::new(db)));
    let tx_pool = Arc::new(TxPool::new(shell_mempool::MempoolConfig {
        chain_id: TEST_CHAIN_ID,
        ..Default::default()
    }));
    let (block_events, _) = tokio::sync::broadcast::channel(16);
    let finalized_number = Arc::new(RwLock::new(0u64));
    let finality = Arc::new(RwLock::new(FinalityState::new()));

    let handler = RpcHandler::new(
        chain_store.clone(),
        world_state.clone(),
        tx_pool.clone(),
        TEST_CHAIN_ID,
        None,
        block_events,
        finalized_number,
        finality,
    );

    TestEnv {
        handler,
        chain_store,
        world_state,
        tx_pool,
    }
}

/// Creates a minimal block at the given `number` with optional `parent_hash`.
pub fn make_block(number: u64, parent_hash: ShellHash) -> Block {
    Block {
        header: BlockHeader {
            parent_hash,
            state_root: ShellHash::default(),
            transactions_root: ShellHash::default(),
            receipts_root: ShellHash::default(),
            logs_bloom: Bytes::default(),
            number,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1_700_000_000 + number * 2,
            extra_data: Bytes::default(),
            proposer: Address::from_public_key(
                b"proposer-key-data",
                SignatureType::Dilithium3.as_u8(),
            ),
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        },
        transactions: vec![],
        system_transactions: vec![],
        proposer_seal: None,
    }
}

/// Creates a genesis block (number 0, zero parent hash).
pub fn make_genesis_block() -> Block {
    make_block(0, ShellHash::default())
}

/// Stores a block, marks it canonical, and sets it as head.
pub fn store_block(env: &TestEnv, block: &Block) {
    let hash = block.hash();
    env.chain_store.put_block(block).unwrap();
    env.chain_store
        .set_canonical(block.header.number, &hash)
        .unwrap();
    env.chain_store.set_head(&hash).unwrap();
}

/// Helper that creates a DilithiumSigner, derives its address, pre-funds the
/// account in world state, and registers its public key in the chain store.
pub struct FundedAccount {
    pub signer: DilithiumSigner,
    pub address: Address,
    pub pubkey: Vec<u8>,
}

pub fn make_funded_account(env: &TestEnv) -> FundedAccount {
    let signer = DilithiumSigner::generate();
    let pubkey = signer.public_key().to_vec();
    let address = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

    {
        let mut ws = env.world_state.write();
        ws.add_balance(&address, U256::from(FUNDED_BALANCE))
            .unwrap();
    }
    env.chain_store.put_pubkey(&address, &pubkey).unwrap();

    FundedAccount {
        signer,
        address,
        pubkey,
    }
}

/// Creates a simple EIP-1559 transfer transaction.
pub fn make_transfer(chain_id: u64, nonce: u64, to: Address, value: U256) -> Transaction {
    Transaction {
        chain_id,
        nonce,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        gas_limit: 21_000,
        to: Some(to),
        value,
        data: Bytes::default(),
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

/// Signs a transaction with the given signer.
pub fn sign_tx(signer: &DilithiumSigner, from: Address, tx: Transaction) -> SignedTransaction {
    let sig = signer.sign(tx.hash().0.as_slice()).unwrap();
    SignedTransaction::new(from, tx, sig)
}

/// Simulates mining a block that includes the given signed transactions.
/// Simulates mining a block containing the given transactions.
/// Creates receipts and stores everything in the chain store.
/// Returns the block hash.
///
/// NOTE: This does NOT execute transactions through the EVM or update
/// world state (balances, nonces, storage). Callers must manually update
/// world state if post-execution assertions are needed. Receipts are
/// hardcoded to status=1, gas_used=21000 per tx.
pub fn mine_block(
    env: &TestEnv,
    number: u64,
    parent_hash: ShellHash,
    txs: Vec<SignedTransaction>,
) -> ShellHash {
    let mut block = make_block(number, parent_hash);
    block.header.gas_used = txs.len() as u64 * 21_000;
    block.transactions = txs.clone();

    let hash = block.hash();

    // Store the block (also stores tx → location index)
    env.chain_store.put_block(&block).unwrap();
    env.chain_store.set_canonical(number, &hash).unwrap();
    env.chain_store.set_head(&hash).unwrap();

    // Create and store receipts
    let mut cumulative_gas = 0u64;
    let receipts: Vec<TransactionReceipt> = txs
        .iter()
        .enumerate()
        .map(|(i, signed_tx)| {
            cumulative_gas += 21_000;
            TransactionReceipt {
                tx_hash: signed_tx.hash(),
                block_number: number,
                tx_index: i as u32,
                status: 1,
                gas_used: 21_000,
                cumulative_gas_used: cumulative_gas,
                contract_address: None,
                logs_bloom: Bytes::default(),
                logs: vec![],
            }
        })
        .collect();
    env.chain_store.put_receipts(&hash, &receipts).unwrap();

    // Remove mined transactions from the mempool
    for tx in &txs {
        env.tx_pool.remove(&tx.hash());
    }

    hash
}

/// Returns a reference to the [`RpcHandler`] inside the [`TestEnv`].
pub fn make_rpc(env: &TestEnv) -> &RpcHandler<MemoryDb> {
    &env.handler
}

// ---------------------------------------------------------------------------
// pqvm-e2e stubs — compiled only when `pqvm-e2e` feature is enabled.
//
// These helpers require a full PQVM executor with deployed contract bytecode
// and are intentionally left as stubs so that normal CI still compiles the
// test file while making the missing infrastructure explicit.
// ---------------------------------------------------------------------------

/// Compiled bytecode of a named paymaster test contract.
/// Populated only when actual bytecode fixtures are provided (pqvm-e2e infra).
#[cfg(feature = "pqvm-e2e")]
pub struct ContractBytecode {
    pub bytecode: Bytes,
}

/// Looks up pre-compiled bytecode for `name` (e.g. "SimplePaymaster").
/// Replace with real artifact loading when pqvm-e2e infra is in place.
#[cfg(feature = "pqvm-e2e")]
pub fn compile_contract(_name: &str) -> ContractBytecode {
    unimplemented!(
        "compile_contract requires PQVM executor + Solidity fixtures; \
         see workspace/projects/shell-chain/contracts/ and AA-PHASE-2-GUIDE.md"
    )
}

/// Builds a deploy transaction from the given bytecode.
#[cfg(feature = "pqvm-e2e")]
pub fn make_deploy_tx(sender: &FundedAccount, bytecode: &ContractBytecode) -> SignedTransaction {
    use shell_core::AA_BUNDLE_TX_TYPE;
    let tx = Transaction {
        chain_id: TEST_CHAIN_ID,
        nonce: 0,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        gas_limit: 500_000,
        to: None,
        value: U256::ZERO,
        data: bytecode.bytecode.clone(),
        access_list: None,
        tx_type: AA_BUNDLE_TX_TYPE,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    sign_tx(&sender.signer, sender.address, tx)
}

/// Submits a transaction, executes it through the PQVM, and mines a block.
/// Requires an RPC handler backed by a live PQVM executor.
#[cfg(feature = "pqvm-e2e")]
pub async fn execute_and_mine(
    _env: &TestEnv,
    _rpc: &RpcHandler<MemoryDb>,
    _tx: SignedTransaction,
) -> Result<ShellHash, String> {
    unimplemented!(
        "execute_and_mine requires a PQVM executor wired into the RPC handler; \
         pending Phase 3 integration"
    )
}

/// Computes the CREATE-address for a contract deployed by `sender` at `nonce`.
#[cfg(feature = "pqvm-e2e")]
pub fn compute_contract_addr(sender: &Address, nonce: u64) -> Address {
    // Deterministic CREATE address: blake3(sender || nonce_be) truncated to 32 bytes.
    use shell_primitives::blake3_hash;
    let mut preimage = Vec::with_capacity(32 + 8);
    preimage.extend_from_slice(sender.0.as_slice());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    let hash = blake3_hash(&preimage);
    Address(hash.0.into())
}
