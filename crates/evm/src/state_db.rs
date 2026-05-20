//! State database bridge from shell-chain storage to revm.
//!
//! [`ShellStateDb`] wraps a [`WorldState`] and [`ChainStore`] to satisfy
//! revm's [`Database`] trait, translating between shell-chain's account
//! model and the EVM account model.

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
pub struct ShellStateDb<S: KvStore + 'static> {
    world_state: WorldState<S>,
    chain_store: ChainStore<S>,
    /// Maps 20-byte EVM address → full 32-byte Shell address for PQ-derived
    /// accounts. Populated by the executor before each tx so that `basic()`
    /// can locate accounts whose upper 12 bytes are non-zero.
    pub(crate) pq_hints: HashMap<EvmAddress, ShellAddress>,
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
            pq_hints: HashMap::new(),
        }
    }

    /// Register the full 32-byte Shell address for a PQ-derived account so
    /// that `basic()` can find it when the EVM queries by 20-byte suffix.
    /// Call this before executing any transaction whose `from` is PQ-derived
    /// (i.e. has non-zero upper 12 bytes).
    pub fn hint_pq_address(&mut self, addr: ShellAddress) {
        let evm_addr: EvmAddress = addr.into();
        let zero_padded = ShellAddress::from(evm_addr);
        if zero_padded != addr {
            self.pq_hints.insert(evm_addr, addr);
        }
    }

    /// Clear all PQ address hints registered for the previous transaction.
    pub fn clear_pq_hints(&mut self) {
        self.pq_hints.clear();
    }

    /// Resolve a 20-byte EVM address to the full 32-byte Shell address,
    /// using the PQ hints if available.
    pub(crate) fn resolve_shell_address(&self, evm_addr: EvmAddress) -> ShellAddress {
        self.pq_hints
            .get(&evm_addr)
            .copied()
            .unwrap_or_else(|| ShellAddress::from(evm_addr))
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

    /// Remap any zero-padded EVM address in `state` back to the full 32-byte
    /// PQ address where a hint exists. This ensures `commit_evm_state` writes
    /// nonce/balance updates to the same slot that `validate_tx` reads from.
    pub(crate) fn remap_state_to_pq(&self, state: revm::state::EvmState) -> revm::state::EvmState {
        if self.pq_hints.is_empty() {
            return state;
        }
        let mut remapped = revm::state::EvmState::default();
        for (evm_addr, acct) in state {
            let new_addr = if let Some(&pq_addr) = self.pq_hints.get(&evm_addr) {
                pq_addr.into()
            } else {
                evm_addr
            };
            remapped.insert(new_addr, acct);
        }
        remapped
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
        let shell_addr = ShellAddress::from(address);
        if let Some(account) = self.world_state.get_account(&shell_addr)? {
            return Ok(Some(Self::to_account_info(&account)));
        }
        // Fallback: check PQ hints — the EVM uses the 20-byte suffix of a
        // 32-byte PQ-derived address, so the zero-padded lookup above misses
        // accounts stored at the full PQ address.
        if let Some(&pq_addr) = self.pq_hints.get(&address) {
            if let Some(account) = self.world_state.get_account(&pq_addr)? {
                return Ok(Some(Self::to_account_info(&account)));
            }
        }
        Ok(None)
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
        let shell_addr = if let Some(&pq) = self.pq_hints.get(&address) {
            pq
        } else {
            ShellAddress::from(address)
        };
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
