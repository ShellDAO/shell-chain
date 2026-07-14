//! State database bridge from shell-chain storage to revm.
//!
//! [`ShellStateDb`] wraps a [`WorldState`] and [`ChainStore`] to satisfy
//! revm's [`Database`] trait, translating between shell-chain's account
//! model and the EVM account model.
//!
//! # Address model at the revm boundary
//!
//! revm's [`Database`] trait uses 20-byte [`alloy_primitives::Address`]
//! values throughout. Shell-Chain uses 32-byte BLAKE3 addresses
//! (`ShellAddress`). This file is the boundary where the translation happens.
//!
//! For EVM-compatible accounts (upper 12 bytes are all zero), the 20-byte
//! form is losslessly recovered by zero-padding. For PQ-derived accounts
//! (upper 12 bytes non-zero, produced by `PQADDR`), the 20-byte form is a
//! lossy truncation; full 32-byte-native execution requires a future revm
//! fork that passes `ShellAddress` through the EVM call stack.

use alloy_primitives::{Address as EvmAddress, B256, U256};
use revm::database_interface::{DBErrorMarker, Database};
use revm::primitives::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};
use shell_core::Account;
use shell_primitives::{Address as ShellAddress, ShellHash};
use shell_storage::{ChainStore, KvStore, StorageError, WorldState};
use std::collections::HashMap;

/// Error type for [`ShellStateDb`] operations.
#[derive(Debug, thiserror::Error)]
pub enum StateDbError {
    /// Underlying storage error.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
}

impl DBErrorMarker for StateDbError {}

/// Bridges shell-chain WorldState + ChainStore to revm's Database trait.
///
/// This adapter translates between the two account models:
/// - shell-chain: `Account { nonce, balance, code_hash, storage_root, ... }`
/// - revm: `AccountInfo { nonce, balance, code_hash, code }`
///
/// # Type Parameter
/// - `S`: The key-value store backend (e.g. `MemoryDb` or `RocksDbStore`)
///
/// # Address translation (revm compatibility bridge)
///
/// revm's [`Database`] trait uses 20-byte [`alloy_primitives::Address`].
/// Shell-Chain uses 32-byte BLAKE3 addresses (`ShellAddress`). For accounts
/// whose address has non-zero upper 12 bytes (PQ-derived via `PQADDR`), the
/// `address_registry` provides the full 32-byte address so that lookups
/// succeed when revm queries by the 20-byte truncated form.
///
/// Full 32-byte-native execution throughout the EVM call stack requires a
/// future revm fork; this registry is the compatibility shim until then.
pub struct ShellStateDb<S: KvStore + 'static> {
    world_state: WorldState<S>,
    chain_store: ChainStore<S>,
    /// Maps 20-byte revm address → full 32-byte Shell address for PQ-derived
    /// accounts (upper 12 bytes non-zero). Populated by the executor before
    /// each tx; cleared after commit.
    pub(crate) address_registry: HashMap<EvmAddress, ShellAddress>,
}

/// Read-only bridge used by simulation and validation paths.
///
/// revm journals transaction changes internally during `transact`; because
/// these callers never commit the result, borrowing the live state is enough
/// to guarantee that simulated writes are discarded.
pub(crate) struct ShellStateRefDb<'a, S: KvStore + 'static> {
    world_state: &'a WorldState<S>,
    chain_store: &'a ChainStore<S>,
}

impl<'a, S: KvStore + 'static> ShellStateRefDb<'a, S> {
    pub(crate) fn new(world_state: &'a WorldState<S>, chain_store: &'a ChainStore<S>) -> Self {
        Self {
            world_state,
            chain_store,
        }
    }

    pub(crate) fn world_state(&self) -> &WorldState<S> {
        self.world_state
    }
}

impl<S: KvStore + 'static> ShellStateDb<S> {
    /// Create a new state database bridge.
    ///
    /// * `world_state` — provides account data + contract storage
    /// * `chain_store` — provides contract bytecode + block hashes
    pub fn new(world_state: WorldState<S>, chain_store: ChainStore<S>) -> Self {
        Self {
            world_state,
            chain_store,
            address_registry: HashMap::new(),
        }
    }

    /// Register the full 32-byte Shell address for a PQ-derived account so
    /// that `basic()` and `storage()` can find it when revm queries by the
    /// 20-byte truncated form. Call this before executing any transaction
    /// whose `from` has non-zero upper 12 bytes.
    pub fn register_pq_address(&mut self, addr: ShellAddress) {
        let evm_addr: EvmAddress = addr.into();
        let zero_padded = ShellAddress::from(evm_addr);
        if zero_padded != addr {
            self.address_registry.insert(evm_addr, addr);
        }
    }

    /// Clear the address registry after a transaction has been committed.
    pub fn clear_address_registry(&mut self) {
        self.address_registry.clear();
    }

    /// Return a snapshot of the address registry (cloned).
    ///
    /// Use this to obtain the registry before `commit_pqvm_state` clears it,
    /// so it can be passed to `commit_pqvm_state_raw` for a second commit
    /// target (e.g. the node's persistent WorldState).
    pub fn address_registry_snapshot(
        &self,
    ) -> std::collections::HashMap<alloy_primitives::Address, ShellAddress> {
        self.address_registry.clone()
    }

    /// Resolve a 20-byte EVM address to a full 32-byte Shell address.
    /// Checks the registry first; falls back to zero-padding.
    #[inline]
    pub(crate) fn resolve_address(&self, addr: &EvmAddress) -> ShellAddress {
        self.address_registry
            .get(addr)
            .copied()
            .unwrap_or_else(|| ShellAddress::from(*addr))
    }

    /// Returns a reference to the underlying WorldState.
    pub fn world_state(&self) -> &WorldState<S> {
        &self.world_state
    }

    /// Returns a mutable reference to the underlying WorldState.
    pub fn world_state_mut(&mut self) -> &mut WorldState<S> {
        &mut self.world_state
    }

    /// Returns a reference to the underlying ChainStore.
    pub fn chain_store(&self) -> &ChainStore<S> {
        &self.chain_store
    }

    /// Returns mutable WorldState and shared ChainStore in one borrow,
    /// avoiding the split-borrow issue with separate accessors.
    pub(crate) fn world_state_and_chain_store(&mut self) -> (&mut WorldState<S>, &ChainStore<S>) {
        (&mut self.world_state, &self.chain_store)
    }

    /// Convert a shell-chain Account to revm AccountInfo.
    ///
    /// Maps `Option<ShellHash>` code_hash to B256, defaulting to
    /// `KECCAK_EMPTY` for accounts without contract bytecode.
    pub(crate) fn to_account_info(account: &Account) -> AccountInfo {
        let code_hash = match &account.code_hash {
            Some(h) => shell_hash_to_b256(h),
            None => KECCAK_EMPTY,
        };
        AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash,
            code: None, // loaded lazily via code_by_hash()
            account_id: None,
        }
    }
}

// revm Database trait uses alloy_primitives::Address directly.
// We convert to/from shell_primitives::Address at the boundary.
impl<S: KvStore + 'static> Database for ShellStateDb<S> {
    type Error = StateDbError;

    fn basic(
        &mut self,
        address: alloy_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        let shell_addr = self.resolve_address(&address);
        match self.world_state.get_account(&shell_addr)? {
            Some(account) => Ok(Some(Self::to_account_info(&account))),
            None => Ok(None),
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let hash = b256_to_shell_hash(&code_hash);
        match self.chain_store.get_code(&hash)? {
            Some(code) => {
                Ok(Bytecode::new_raw_checked(code.into()).unwrap_or_else(|_| Bytecode::default()))
            }
            None => Ok(Bytecode::default()),
        }
    }

    fn storage(
        &mut self,
        address: alloy_primitives::Address,
        index: U256,
    ) -> Result<U256, Self::Error> {
        let shell_addr = self.resolve_address(&address);
        let key = ShellHash::from(B256::from(index));
        let value_hash = self.world_state.get_storage(&shell_addr, &key)?;
        Ok(U256::from_be_bytes(*value_hash.as_bytes()))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        match self.chain_store.get_block_by_number(number)? {
            Some(block) => Ok(shell_hash_to_b256(&block.hash())),
            None => Ok(B256::ZERO),
        }
    }
}

impl<S: KvStore + 'static> Database for ShellStateRefDb<'_, S> {
    type Error = StateDbError;

    fn basic(&mut self, address: EvmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let shell_addr = ShellAddress::from(address);
        Ok(self
            .world_state
            .get_account(&shell_addr)?
            .map(|account| ShellStateDb::<S>::to_account_info(&account)))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let hash = b256_to_shell_hash(&code_hash);
        match self.chain_store.get_code(&hash)? {
            Some(code) => {
                Ok(Bytecode::new_raw_checked(code.into()).unwrap_or_else(|_| Bytecode::default()))
            }
            None => Ok(Bytecode::default()),
        }
    }

    fn storage(&mut self, address: EvmAddress, index: U256) -> Result<U256, Self::Error> {
        let shell_addr = ShellAddress::from(address);
        let key = ShellHash::from(B256::from(index));
        let value_hash = self.world_state.get_storage(&shell_addr, &key)?;
        Ok(U256::from_be_bytes(*value_hash.as_bytes()))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        match self.chain_store.get_block_by_number(number)? {
            Some(block) => Ok(shell_hash_to_b256(&block.hash())),
            None => Ok(B256::ZERO),
        }
    }
}

// ── Conversion helpers ────────────────────────────────────────

/// Convert ShellHash ([u8; 32] wrapper) to alloy B256.
#[inline]
pub(crate) fn shell_hash_to_b256(h: &ShellHash) -> B256 {
    B256::from_slice(h.as_bytes())
}

/// Convert alloy B256 to ShellHash.
#[inline]
pub(crate) fn b256_to_shell_hash(b: &B256) -> ShellHash {
    ShellHash::from(*b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::keccak256;
    use shell_storage::MemoryDb;
    use std::sync::Arc;

    fn setup() -> ShellStateDb<MemoryDb> {
        let state_store = Arc::new(MemoryDb::new());
        let chain_store_backend = Arc::new(MemoryDb::new());
        let world_state = WorldState::new(state_store);
        let chain_store = ChainStore::new(chain_store_backend);
        ShellStateDb::new(world_state, chain_store)
    }

    fn new_account(nonce: u64, balance: U256) -> Account {
        Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce,
            balance,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        }
    }

    #[test]
    fn basic_nonexistent_returns_none() {
        let mut db = setup();
        let addr = alloy_primitives::Address::ZERO;
        assert!(db.basic(addr).unwrap().is_none());
    }

    #[test]
    fn basic_existing_account() {
        let mut db = setup();
        let shell_addr = ShellAddress::ZERO;
        let account = new_account(42, U256::from(1_000_000));
        db.world_state_mut()
            .set_account(&shell_addr, &account)
            .unwrap();

        let info = db.basic(alloy_primitives::Address::ZERO).unwrap().unwrap();
        assert_eq!(info.nonce, 42);
        assert_eq!(info.balance, U256::from(1_000_000));
        // Accounts without contract bytecode use KECCAK_EMPTY
        assert_eq!(info.code_hash, KECCAK_EMPTY);
    }

    #[test]
    fn code_by_hash_returns_stored_code() {
        let mut db = setup();
        let code = b"\x60\x00\x60\x00\xf3"; // PUSH1 0 PUSH1 0 RETURN
        let hash = keccak256(code);
        db.chain_store().put_code(&hash, code).unwrap();

        let bytecode = db.code_by_hash(shell_hash_to_b256(&hash)).unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn code_by_hash_missing_returns_default() {
        let mut db = setup();
        let bytecode = db.code_by_hash(B256::ZERO).unwrap();
        assert!(bytecode.is_empty());
    }

    #[test]
    fn storage_returns_stored_value() {
        let mut db = setup();
        let shell_addr = ShellAddress::ZERO;
        let account = new_account(0, U256::ZERO);
        db.world_state_mut()
            .set_account(&shell_addr, &account)
            .unwrap();

        let slot = ShellHash::from(B256::from(U256::from(1)));
        let val_hash = ShellHash::from(B256::from(U256::from(999)));
        db.world_state_mut()
            .set_storage(&shell_addr, &slot, &val_hash)
            .unwrap();

        let val = db
            .storage(alloy_primitives::Address::ZERO, U256::from(1))
            .unwrap();
        assert_eq!(val, U256::from(999));
    }

    #[test]
    fn storage_empty_returns_zero() {
        let mut db = setup();
        let shell_addr = ShellAddress::ZERO;
        let account = new_account(0, U256::ZERO);
        db.world_state_mut()
            .set_account(&shell_addr, &account)
            .unwrap();

        let val = db
            .storage(alloy_primitives::Address::ZERO, U256::from(42))
            .unwrap();
        assert_eq!(val, U256::ZERO);
    }

    #[test]
    fn block_hash_returns_zero_for_missing() {
        let mut db = setup();
        let hash = db.block_hash(999).unwrap();
        assert_eq!(hash, B256::ZERO);
    }
}
