use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use alloy_rlp::{Decodable, Encodable};
use lru::LruCache;
use parking_lot::Mutex;
use rlp::{Prototype, Rlp};
use shell_core::Account;
use shell_primitives::{keccak256, Address, ShellHash, U256};

use crate::{KvStore, MerkleTrie, StorageError, WriteBatch};

/// Approximate byte-size of one RLP-encoded [`Account`].
const ACCOUNT_SIZE_BYTES: usize = 100;

/// Default account cache capacity (64 MiB / ACCOUNT_SIZE_BYTES).
const DEFAULT_CACHE_CAPACITY_ACCOUNTS: usize = 64 * 1024 * 1024 / ACCOUNT_SIZE_BYTES;

/// Returns the system address used for the validator registry (0x0000…0001).
pub fn validator_registry_addr() -> Address {
    Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

/// Returns the system address used for the account manager (0x0000…0002).
pub fn account_manager_addr() -> Address {
    Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
}

/// Manages the world state (all accounts and their storage).
///
/// Accounts are stored in a Merkle Patricia Trie keyed by `keccak256(address)`.
/// Each account may have its own storage sub-trie whose nodes share the same
/// underlying [`KvStore`].
///
/// An LRU account cache sits in front of the trie to avoid re-decoding
/// on repeated reads.  The default capacity is 64 MiB worth of entries;
/// use [`WorldState::new_with_cache_mb`] to override.
pub struct WorldState<S: KvStore + 'static> {
    account_trie: MerkleTrie<S>,
    store: Arc<S>,
    /// `None` = account not in trie; `Some(account)` = cached account.
    account_cache: Mutex<LruCache<Address, Option<Account>>>,
}

impl<S: KvStore + 'static> WorldState<S> {
    /// Create a new empty world state with the default 64 MiB account cache.
    pub fn new(store: Arc<S>) -> Self {
        Self::new_with_cache_mb(store, 64)
    }

    /// Create a new empty world state with the given account cache size in MiB.
    pub fn new_with_cache_mb(store: Arc<S>, cache_mb: usize) -> Self {
        let cap = NonZeroUsize::new(
            cache_mb
                .saturating_mul(1024)
                .saturating_mul(1024)
                .checked_div(ACCOUNT_SIZE_BYTES)
                .unwrap_or(1),
        )
        .unwrap_or_else(|| {
            NonZeroUsize::new(DEFAULT_CACHE_CAPACITY_ACCOUNTS)
                .unwrap_or_else(|| unreachable!("DEFAULT_CACHE_CAPACITY_ACCOUNTS > 0"))
        });
        Self {
            account_trie: MerkleTrie::new(Arc::clone(&store)),
            store,
            account_cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Open world state at an existing state root with the default account cache.
    pub fn at_root(store: Arc<S>, state_root: &ShellHash) -> Result<Self, StorageError> {
        Self::at_root_with_cache_mb(store, state_root, 64)
    }

    /// Open world state at an existing state root with the given cache size in MiB.
    pub fn at_root_with_cache_mb(
        store: Arc<S>,
        state_root: &ShellHash,
        cache_mb: usize,
    ) -> Result<Self, StorageError> {
        let trie = MerkleTrie::at_root(Arc::clone(&store), state_root.as_bytes())?;
        let cap = NonZeroUsize::new(
            cache_mb
                .saturating_mul(1024)
                .saturating_mul(1024)
                .checked_div(ACCOUNT_SIZE_BYTES)
                .unwrap_or(1),
        )
        .unwrap_or_else(|| {
            NonZeroUsize::new(DEFAULT_CACHE_CAPACITY_ACCOUNTS)
                .unwrap_or_else(|| unreachable!("DEFAULT_CACHE_CAPACITY_ACCOUNTS > 0"))
        });
        Ok(Self {
            account_trie: trie,
            store,
            account_cache: Mutex::new(LruCache::new(cap)),
        })
    }

    /// Re-open the current world state at its latest root as an isolated snapshot.
    ///
    /// Useful for read-only simulations (e.g. RPC `eth_call`, AA validation
    /// contract execution) that must not mutate the live state handle.
    pub fn snapshot(&mut self) -> Result<Self, StorageError> {
        let root = self.state_root()?;
        let cap = self.account_cache.lock().cap();
        let cap_mb = cap
            .get()
            .saturating_mul(ACCOUNT_SIZE_BYTES)
            .div_ceil(1_048_576);
        Self::at_root_with_cache_mb(Arc::clone(&self.store), &root, cap_mb.max(1))
    }

    /// Re-open this world state at the given historical root **in place**,
    /// dropping any uncommitted trie mutations and clearing the account cache.
    ///
    /// Used by atomic execution paths (e.g. AA bundle dispatcher) that need
    /// to discard a partially-applied set of state changes when an inner
    /// step reverts. The previous root must already be reachable in the
    /// underlying KV store.
    pub fn rollback_to_root(&mut self, root: &ShellHash) -> Result<(), StorageError> {
        let trie = MerkleTrie::at_root(Arc::clone(&self.store), root.as_bytes())?;
        self.account_trie = trie;
        self.account_cache.lock().clear();
        Ok(())
    }

    fn account_key(address: &Address) -> Vec<u8> {
        keccak256(address.as_bytes()).as_bytes().to_vec()
    }

    /// Retrieve an account by address. Returns `None` if the account does not exist.
    ///
    /// Results are memoised in the LRU account cache.
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>, StorageError> {
        // Fast path: cache hit.
        if let Some(cached) = self.account_cache.lock().get(address) {
            return Ok(cached.clone());
        }
        // Slow path: trie lookup.
        let key = Self::account_key(address);
        let result = match self.account_trie.get(&key)? {
            Some(data) => {
                let account = Account::decode(&mut &data[..])
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Some(account)
            }
            None => None,
        };
        self.account_cache.lock().put(*address, result.clone());
        Ok(result)
    }

    /// Write an account to the state trie and update the LRU cache.
    pub fn set_account(
        &mut self,
        address: &Address,
        account: &Account,
    ) -> Result<(), StorageError> {
        let key = Self::account_key(address);
        let mut buf = Vec::new();
        account.encode(&mut buf);
        self.account_trie.insert(&key, &buf)?;
        self.account_cache
            .lock()
            .put(*address, Some(account.clone()));
        Ok(())
    }

    fn get_or_default(&self, address: &Address) -> Result<Account, StorageError> {
        Ok(self
            .get_account(address)?
            .unwrap_or_else(|| Account::new_user_account(ShellHash::ZERO, U256::ZERO)))
    }

    // ── Balance helpers ────────────────────────────────────────

    pub fn get_balance(&self, address: &Address) -> Result<U256, StorageError> {
        Ok(self.get_or_default(address)?.balance)
    }

    pub fn set_balance(&mut self, address: &Address, balance: U256) -> Result<(), StorageError> {
        let mut account = self.get_or_default(address)?;
        account.balance = balance;
        self.set_account(address, &account)
    }

    pub fn add_balance(&mut self, address: &Address, amount: U256) -> Result<(), StorageError> {
        let mut account = self.get_or_default(address)?;
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| StorageError::State("balance overflow".into()))?;
        self.set_account(address, &account)
    }

    pub fn sub_balance(&mut self, address: &Address, amount: U256) -> Result<(), StorageError> {
        let mut account = self.get_or_default(address)?;
        account.balance = account
            .balance
            .checked_sub(amount)
            .ok_or_else(|| StorageError::State("insufficient balance".into()))?;
        self.set_account(address, &account)
    }

    // ── Nonce helpers ──────────────────────────────────────────

    pub fn get_nonce(&self, address: &Address) -> Result<u64, StorageError> {
        Ok(self.get_or_default(address)?.nonce)
    }

    pub fn increment_nonce(&mut self, address: &Address) -> Result<(), StorageError> {
        let mut account = self.get_or_default(address)?;
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| StorageError::State("nonce overflow".into()))?;
        self.set_account(address, &account)
    }

    // ── Contract storage ───────────────────────────────────────

    /// Read a value from an account's storage trie.
    pub fn get_storage(
        &self,
        address: &Address,
        key: &ShellHash,
    ) -> Result<ShellHash, StorageError> {
        let account = match self.get_account(address)? {
            Some(a) => a,
            None => return Ok(ShellHash::ZERO),
        };
        if account.storage_root == ShellHash::ZERO {
            return Ok(ShellHash::ZERO);
        }
        let storage_trie =
            MerkleTrie::at_root(Arc::clone(&self.store), account.storage_root.as_bytes())?;
        let storage_key = keccak256(key.as_bytes());
        match storage_trie.get(storage_key.as_bytes())? {
            Some(data) => {
                ShellHash::try_from_slice(&data).map_err(|e| StorageError::Codec(e.to_string()))
            }
            None => Ok(ShellHash::ZERO),
        }
    }

    /// Write a value to an account's storage trie.
    /// Writing `ShellHash::ZERO` removes the key.
    pub fn set_storage(
        &mut self,
        address: &Address,
        key: &ShellHash,
        value: &ShellHash,
    ) -> Result<(), StorageError> {
        let mut account = self.get_or_default(address)?;

        let mut storage_trie = if account.storage_root == ShellHash::ZERO {
            MerkleTrie::new(Arc::clone(&self.store))
        } else {
            MerkleTrie::at_root(Arc::clone(&self.store), account.storage_root.as_bytes())?
        };

        let storage_key = keccak256(key.as_bytes());
        if *value == ShellHash::ZERO {
            storage_trie.remove(storage_key.as_bytes())?;
        } else {
            storage_trie.insert(storage_key.as_bytes(), value.as_bytes())?;
        }

        let new_root = storage_trie.root_hash()?;
        account.storage_root = ShellHash::from(new_root);
        self.set_account(address, &account)
    }

    // ── Code helpers ───────────────────────────────────────────

    pub fn get_code_hash(&self, address: &Address) -> Result<Option<ShellHash>, StorageError> {
        Ok(self.get_or_default(address)?.code_hash)
    }

    pub fn set_code_hash(
        &mut self,
        address: &Address,
        code_hash: ShellHash,
    ) -> Result<(), StorageError> {
        let mut account = self.get_or_default(address)?;
        account.code_hash = Some(code_hash);
        self.set_account(address, &account)
    }

    // ── Validator registry ──────────────────────────────────────

    fn validator_count_key() -> ShellHash {
        keccak256(b"validator_count")
    }

    fn validator_slot_key(i: u64) -> ShellHash {
        let label = format!("validator_{i}");
        keccak256(label.as_bytes())
    }

    fn validator_weight_key(address: &Address) -> ShellHash {
        let mut bytes = Vec::with_capacity(b"validator_weight:".len() + 32);
        bytes.extend_from_slice(b"validator_weight:");
        bytes.extend_from_slice(address.as_bytes());
        keccak256(&bytes)
    }

    fn validator_stake_key(address: &Address) -> ShellHash {
        let mut bytes = Vec::with_capacity(b"validator_stake:".len() + 32);
        bytes.extend_from_slice(b"validator_stake:");
        bytes.extend_from_slice(address.as_bytes());
        keccak256(&bytes)
    }

    fn staking_enabled_key() -> ShellHash {
        keccak256(b"staking_enabled")
    }

    fn total_supply_key() -> ShellHash {
        keccak256(b"total_supply")
    }

    fn total_staked_key() -> ShellHash {
        keccak256(b"total_staked")
    }

    fn stake_unit_key() -> ShellHash {
        keccak256(b"stake_unit")
    }

    fn max_validator_weight_key() -> ShellHash {
        keccak256(b"max_validator_weight")
    }

    fn u64_to_hash(value: u64) -> ShellHash {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        ShellHash::from(bytes)
    }

    fn hash_to_u64(value: ShellHash) -> Result<u64, StorageError> {
        Ok(u64::from_be_bytes(
            value.as_bytes()[24..32]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| StorageError::Codec(e.to_string()))?,
        ))
    }

    fn u256_to_hash(value: U256) -> ShellHash {
        ShellHash::from(value.to_be_bytes::<32>())
    }

    fn hash_to_u256(value: ShellHash) -> U256 {
        U256::from_be_slice(value.as_bytes())
    }

    /// Read the current validator set from the validator registry in world state.
    pub fn get_validators(&self) -> Result<Vec<Address>, StorageError> {
        let registry = validator_registry_addr();
        let count_hash = self.get_storage(&registry, &Self::validator_count_key())?;
        if count_hash == ShellHash::ZERO {
            return Ok(Vec::new());
        }
        let count = u64::from_be_bytes(
            count_hash.as_bytes()[24..32]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| StorageError::Codec(e.to_string()))?,
        );
        let count = usize::try_from(count)
            .map_err(|_| StorageError::Codec("validator count does not fit usize".into()))?;
        if count > Self::MAX_VALIDATORS {
            return Err(StorageError::Codec(format!(
                "validator count {} exceeds maximum {}",
                count,
                Self::MAX_VALIDATORS
            )));
        }
        let mut validators = Vec::with_capacity(count);
        for i in 0..count {
            let slot = self.get_storage(&registry, &Self::validator_slot_key(i as u64))?;
            // Address::ZERO is a valid validator (slot value is all zeros).
            // We trust the count field to determine how many validators exist.
            let addr = Address::try_from_slice(slot.as_bytes())
                .map_err(|e| StorageError::Codec(e.to_string()))?;
            validators.push(addr);
        }
        Ok(validators)
    }

    /// Maximum number of validators allowed (F-044: DoS protection).
    pub const MAX_VALIDATORS: usize = 1000;

    /// Write a validator set to the validator registry in world state.
    pub fn set_validators(&mut self, validators: &[Address]) -> Result<(), StorageError> {
        if validators.len() > Self::MAX_VALIDATORS {
            return Err(StorageError::Codec(format!(
                "validator set size {} exceeds maximum {}",
                validators.len(),
                Self::MAX_VALIDATORS
            )));
        }
        let registry = validator_registry_addr();
        let old_count_hash = self.get_storage(&registry, &Self::validator_count_key())?;
        let old_count =
            if old_count_hash == ShellHash::ZERO {
                0u64
            } else {
                u64::from_be_bytes(old_count_hash.as_bytes()[24..32].try_into().map_err(
                    |e: std::array::TryFromSliceError| StorageError::Codec(e.to_string()),
                )?)
            };

        let new_count = validators.len() as u64;
        for (i, addr) in validators.iter().enumerate() {
            let slot: [u8; 32] = addr.0;
            self.set_storage(
                &registry,
                &Self::validator_slot_key(i as u64),
                &ShellHash::from(slot),
            )?;
        }

        for i in new_count..old_count {
            self.set_storage(&registry, &Self::validator_slot_key(i), &ShellHash::ZERO)?;
        }

        let mut count_bytes = [0u8; 32];
        count_bytes[24..32].copy_from_slice(&new_count.to_be_bytes());
        self.set_storage(
            &registry,
            &Self::validator_count_key(),
            &ShellHash::from(count_bytes),
        )?;

        Ok(())
    }

    /// Return the validator's canonical voting/proposer weight.
    ///
    /// Missing or zero weights normalize to 1 so legacy genesis files remain
    /// valid and newly added validators have safe default weight.
    pub fn get_validator_weight(&self, validator: &Address) -> Result<u64, StorageError> {
        let registry = validator_registry_addr();
        let raw = self.get_storage(&registry, &Self::validator_weight_key(validator))?;
        if raw == ShellHash::ZERO {
            return Ok(1);
        }
        let weight = Self::hash_to_u64(raw)?;
        Ok(weight.max(1))
    }

    /// Set one validator's canonical weight. A zero input is normalized to 1.
    pub fn set_validator_weight(
        &mut self,
        validator: &Address,
        weight: u64,
    ) -> Result<(), StorageError> {
        if weight > shell_primitives::MAX_VALIDATOR_WEIGHT {
            return Err(StorageError::Codec(format!(
                "validator weight must be between 1 and {}",
                shell_primitives::MAX_VALIDATOR_WEIGHT
            )));
        }
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::validator_weight_key(validator),
            &Self::u64_to_hash(weight.max(1)),
        )
    }

    /// Set validator weights aligned with `validators`; missing weights default to 1.
    pub fn set_validator_weights(
        &mut self,
        validators: &[Address],
        weights: &[u64],
    ) -> Result<(), StorageError> {
        for (idx, validator) in validators.iter().enumerate() {
            self.set_validator_weight(validator, weights.get(idx).copied().unwrap_or(1))?;
        }
        Ok(())
    }

    /// Return true when validator weights are derived from locked SHELL stake.
    pub fn staking_enabled(&self) -> Result<bool, StorageError> {
        let registry = validator_registry_addr();
        let raw = self.get_storage(&registry, &Self::staking_enabled_key())?;
        Ok(raw != ShellHash::ZERO)
    }

    pub fn set_staking_enabled(&mut self, enabled: bool) -> Result<(), StorageError> {
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::staking_enabled_key(),
            &if enabled {
                Self::u64_to_hash(1)
            } else {
                ShellHash::ZERO
            },
        )
    }

    pub fn get_total_supply(&self) -> Result<U256, StorageError> {
        let registry = validator_registry_addr();
        Ok(Self::hash_to_u256(
            self.get_storage(&registry, &Self::total_supply_key())?,
        ))
    }

    pub fn set_total_supply(&mut self, value: U256) -> Result<(), StorageError> {
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::total_supply_key(),
            &Self::u256_to_hash(value),
        )
    }

    pub fn get_total_staked(&self) -> Result<U256, StorageError> {
        let registry = validator_registry_addr();
        Ok(Self::hash_to_u256(
            self.get_storage(&registry, &Self::total_staked_key())?,
        ))
    }

    pub fn set_total_staked(&mut self, value: U256) -> Result<(), StorageError> {
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::total_staked_key(),
            &Self::u256_to_hash(value),
        )
    }

    pub fn get_stake_unit(&self) -> Result<U256, StorageError> {
        let registry = validator_registry_addr();
        Ok(Self::hash_to_u256(
            self.get_storage(&registry, &Self::stake_unit_key())?,
        ))
    }

    pub fn set_stake_unit(&mut self, value: U256) -> Result<(), StorageError> {
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::stake_unit_key(),
            &Self::u256_to_hash(value),
        )
    }

    pub fn get_max_validator_weight(&self) -> Result<u64, StorageError> {
        let registry = validator_registry_addr();
        let raw = self.get_storage(&registry, &Self::max_validator_weight_key())?;
        if raw == ShellHash::ZERO {
            return Ok(u64::MAX);
        }
        Self::hash_to_u64(raw)
    }

    pub fn set_max_validator_weight(&mut self, value: u64) -> Result<(), StorageError> {
        if value == 0 || value > shell_primitives::MAX_VALIDATOR_WEIGHT {
            return Err(StorageError::Codec(format!(
                "max validator weight must be between 1 and {}",
                shell_primitives::MAX_VALIDATOR_WEIGHT
            )));
        }
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::max_validator_weight_key(),
            &Self::u64_to_hash(value),
        )
    }

    pub fn get_validator_stake(&self, validator: &Address) -> Result<U256, StorageError> {
        let registry = validator_registry_addr();
        Ok(Self::hash_to_u256(self.get_storage(
            &registry,
            &Self::validator_stake_key(validator),
        )?))
    }

    pub fn set_validator_stake(
        &mut self,
        validator: &Address,
        stake: U256,
    ) -> Result<(), StorageError> {
        let registry = validator_registry_addr();
        self.set_storage(
            &registry,
            &Self::validator_stake_key(validator),
            &Self::u256_to_hash(stake),
        )
    }

    pub fn derive_validator_weight_from_stake(
        stake: U256,
        stake_unit: U256,
        max_validator_weight: u64,
    ) -> Result<u64, StorageError> {
        if stake_unit == U256::ZERO {
            return Err(StorageError::Codec(
                "stake_unit must be greater than zero".into(),
            ));
        }
        if max_validator_weight == 0 {
            return Err(StorageError::Codec(
                "max_validator_weight must be greater than zero".into(),
            ));
        }
        let raw = stake / stake_unit;
        Ok(raw.min(U256::from(max_validator_weight)).to::<u64>())
    }

    pub fn set_validator_stake_and_weight(
        &mut self,
        validator: &Address,
        stake: U256,
        stake_unit: U256,
        max_validator_weight: u64,
    ) -> Result<u64, StorageError> {
        let weight =
            Self::derive_validator_weight_from_stake(stake, stake_unit, max_validator_weight)?;
        self.set_validator_stake(validator, stake)?;
        self.set_validator_weight(validator, weight.max(1))?;
        Ok(weight.max(1))
    }

    // ── State root ─────────────────────────────────────────────

    /// Compute and return the current state root hash.
    pub fn state_root(&mut self) -> Result<ShellHash, StorageError> {
        let root = self.account_trie.root_hash()?;
        Ok(ShellHash::from(root))
    }

    /// Collect all hashed trie-node keys reachable from the given state root.
    pub fn collect_snapshot_node_hashes(
        store: &S,
        root: ShellHash,
    ) -> Result<HashSet<ShellHash>, StorageError> {
        let mut visited = HashSet::new();
        Self::collect_hashed_node(store, root, &mut visited)?;
        Ok(visited)
    }

    /// Delete all hashed trie nodes reachable from the given state root except
    /// those explicitly protected by `protected_nodes`.
    pub fn delete_state_snapshot(
        store: &S,
        root: ShellHash,
        protected_nodes: &HashSet<ShellHash>,
    ) -> Result<u64, StorageError> {
        let reachable = Self::collect_snapshot_node_hashes(store, root)?;
        let deletable: Vec<ShellHash> = reachable
            .into_iter()
            .filter(|hash| !protected_nodes.contains(hash))
            .collect();

        if deletable.is_empty() {
            return Ok(0);
        }

        let mut batch = WriteBatch::new();
        for hash in &deletable {
            batch.delete(hash.as_bytes().to_vec());
        }
        store.write_batch(batch)?;
        Ok(deletable.len() as u64)
    }

    fn collect_hashed_node(
        store: &S,
        node_hash: ShellHash,
        visited: &mut HashSet<ShellHash>,
    ) -> Result<(), StorageError> {
        if visited.contains(&node_hash) {
            return Ok(());
        }
        let Some(raw_node) = store.get(node_hash.as_bytes())? else {
            return Ok(());
        };
        visited.insert(node_hash);
        Self::collect_hashed_refs_in_raw(store, &raw_node, visited)
    }

    fn collect_hashed_refs_in_raw(
        store: &S,
        raw_node: &[u8],
        visited: &mut HashSet<ShellHash>,
    ) -> Result<(), StorageError> {
        let rlp = Rlp::new(raw_node);
        match rlp
            .prototype()
            .map_err(|e| StorageError::Trie(e.to_string()))?
        {
            Prototype::Data(0) => Ok(()),
            Prototype::List(2) => {
                let key = rlp
                    .at(0)
                    .and_then(|item| item.data())
                    .map_err(|e| StorageError::Trie(e.to_string()))?;
                if Self::compact_path_is_leaf(key) {
                    return Ok(());
                }
                let child_raw = rlp
                    .at(1)
                    .map_err(|e| StorageError::Trie(e.to_string()))?
                    .as_raw()
                    .to_vec();
                Self::collect_hashed_refs_from_item(store, &child_raw, visited)
            }
            Prototype::List(17) => {
                for index in 0..16 {
                    let child_raw = rlp
                        .at(index)
                        .map_err(|e| StorageError::Trie(e.to_string()))?
                        .as_raw()
                        .to_vec();
                    Self::collect_hashed_refs_from_item(store, &child_raw, visited)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn collect_hashed_refs_from_item(
        store: &S,
        raw_item: &[u8],
        visited: &mut HashSet<ShellHash>,
    ) -> Result<(), StorageError> {
        let rlp = Rlp::new(raw_item);
        let prototype = rlp
            .prototype()
            .map_err(|e| StorageError::Trie(e.to_string()))?;
        if rlp.is_data() && matches!(prototype, Prototype::Data(32)) {
            let hash = ShellHash::try_from_slice(
                rlp.data().map_err(|e| StorageError::Trie(e.to_string()))?,
            )
            .map_err(|e| StorageError::Trie(e.to_string()))?;
            return Self::collect_hashed_node(store, hash, visited);
        }
        match prototype {
            Prototype::Data(_) => Ok(()),
            _ => Self::collect_hashed_refs_in_raw(store, raw_item, visited),
        }
    }

    fn compact_path_is_leaf(compact: &[u8]) -> bool {
        compact
            .first()
            .map(|byte| ((byte >> 4) & 0b10) != 0)
            .unwrap_or(false)
    }

    /// Validate the world state by performing a health check (F-123).
    ///
    /// Verifies that the state trie can compute a root hash and that
    /// the validator registry (if populated) is readable and consistent.
    /// Call this after opening a world state from an existing root to
    /// detect DB corruption early.
    pub fn validate(&mut self) -> Result<(), StorageError> {
        // Verify trie can compute root hash without panic.
        let root_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.account_trie.root_hash()
        }))
        .map_err(|_| StorageError::State("state trie integrity check panicked".into()))?;
        let _root = root_result
            .map_err(|e| StorageError::State(format!("state trie integrity check failed: {e}")))?;

        // Verify the validator registry is readable.
        let validators = self
            .get_validators()
            .map_err(|e| StorageError::State(format!("validator registry read failed: {e}")))?;

        // Sanity check: if validators are present, count must be bounded.
        if validators.len() > Self::MAX_VALIDATORS {
            return Err(StorageError::State(format!(
                "validator set size {} exceeds maximum {}",
                validators.len(),
                Self::MAX_VALIDATORS
            )));
        }

        Ok(())
    }

    /// Check whether an account exists in the state.
    pub fn exists(&self, address: &Address) -> Result<bool, StorageError> {
        Ok(self.get_account(address)?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;

    fn test_store() -> Arc<MemoryDb> {
        Arc::new(MemoryDb::new())
    }

    fn test_address(seed: &[u8]) -> Address {
        Address::from_public_key(keccak256(seed).as_bytes(), 0)
    }

    #[test]
    fn empty_state_has_deterministic_root() {
        let store = test_store();
        let mut ws1 = WorldState::new(Arc::clone(&store));

        let store2 = test_store();
        let mut ws2 = WorldState::new(store2);

        assert_eq!(ws1.state_root().unwrap(), ws2.state_root().unwrap());
    }

    #[test]
    fn get_nonexistent_account_returns_none() {
        let store = test_store();
        let ws = WorldState::new(store);
        let addr = test_address(b"nobody");
        assert!(ws.get_account(&addr).unwrap().is_none());
    }

    #[test]
    fn set_and_get_account() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"alice");
        let acct = Account::new_user_account(keccak256(b"alice-pk"), U256::from(1000));

        ws.set_account(&addr, &acct).unwrap();
        let loaded = ws.get_account(&addr).unwrap().unwrap();
        assert_eq!(loaded.balance, U256::from(1000));
        assert_eq!(loaded.nonce, 0);
    }

    #[test]
    fn balance_add_and_sub() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"bob");

        ws.add_balance(&addr, U256::from(500)).unwrap();
        assert_eq!(ws.get_balance(&addr).unwrap(), U256::from(500));

        ws.sub_balance(&addr, U256::from(200)).unwrap();
        assert_eq!(ws.get_balance(&addr).unwrap(), U256::from(300));
    }

    #[test]
    fn sub_balance_insufficient_fails() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"broke");

        ws.add_balance(&addr, U256::from(100)).unwrap();
        let err = ws.sub_balance(&addr, U256::from(200)).unwrap_err();
        assert!(matches!(err, StorageError::State(_)));
    }

    #[test]
    fn sub_balance_exact_amount_zeroes_balance() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"exact");

        ws.add_balance(&addr, U256::from(100)).unwrap();
        ws.sub_balance(&addr, U256::from(100)).unwrap();

        assert_eq!(ws.get_balance(&addr).unwrap(), U256::ZERO);
    }

    #[test]
    fn nonce_increment() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"carol");

        assert_eq!(ws.get_nonce(&addr).unwrap(), 0);
        ws.increment_nonce(&addr).unwrap();
        ws.increment_nonce(&addr).unwrap();
        assert_eq!(ws.get_nonce(&addr).unwrap(), 2);
    }

    #[test]
    fn state_root_changes_with_accounts() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let root_empty = ws.state_root().unwrap();

        let addr = test_address(b"dave");
        ws.add_balance(&addr, U256::from(42)).unwrap();
        let root_with_account = ws.state_root().unwrap();

        assert_ne!(root_empty, root_with_account);
    }

    #[test]
    fn state_root_deterministic() {
        let store1 = test_store();
        let mut ws1 = WorldState::new(store1);
        let store2 = test_store();
        let mut ws2 = WorldState::new(store2);

        let addr = test_address(b"eve");
        ws1.add_balance(&addr, U256::from(100)).unwrap();
        ws2.add_balance(&addr, U256::from(100)).unwrap();

        assert_eq!(ws1.state_root().unwrap(), ws2.state_root().unwrap());
    }

    #[test]
    fn reopen_at_root() {
        let store = test_store();
        let mut ws = WorldState::new(Arc::clone(&store));
        let addr = test_address(b"frank");
        ws.add_balance(&addr, U256::from(777)).unwrap();
        let root = ws.state_root().unwrap();

        let ws2 = WorldState::at_root(store, &root).unwrap();
        assert_eq!(ws2.get_balance(&addr).unwrap(), U256::from(777));
    }

    #[test]
    fn contract_storage_set_and_get() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"contract");

        let slot = keccak256(b"slot-0");
        let value = keccak256(b"value-0");

        ws.set_storage(&addr, &slot, &value).unwrap();
        assert_eq!(ws.get_storage(&addr, &slot).unwrap(), value);
    }

    #[test]
    fn contract_storage_delete() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"contract2");

        let slot = keccak256(b"slot-1");
        let value = keccak256(b"value-1");

        ws.set_storage(&addr, &slot, &value).unwrap();
        ws.set_storage(&addr, &slot, &ShellHash::ZERO).unwrap();
        assert_eq!(ws.get_storage(&addr, &slot).unwrap(), ShellHash::ZERO);
    }

    #[test]
    fn exists_check() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let addr = test_address(b"ghost");

        assert!(!ws.exists(&addr).unwrap());
        ws.add_balance(&addr, U256::from(1)).unwrap();
        assert!(ws.exists(&addr).unwrap());
    }

    // ── Validator registry tests ───────────────────────────────

    #[test]
    fn get_validators_empty() {
        let store = test_store();
        let ws = WorldState::new(store);
        let validators = ws.get_validators().unwrap();
        assert!(validators.is_empty());
    }

    #[test]
    fn set_and_get_validators_roundtrip() {
        let store = test_store();
        let mut ws = WorldState::new(store);

        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let validators = vec![v1, v2, v3];

        ws.set_validators(&validators).unwrap();
        let loaded = ws.get_validators().unwrap();
        assert_eq!(loaded, validators);
    }

    #[test]
    fn set_validators_overwrites_previous() {
        let store = test_store();
        let mut ws = WorldState::new(store);

        let old_set = vec![
            Address::from([0x0A; 20]),
            Address::from([0x0B; 20]),
            Address::from([0x0C; 20]),
        ];
        ws.set_validators(&old_set).unwrap();
        assert_eq!(ws.get_validators().unwrap().len(), 3);

        let new_set = vec![Address::from([0xDD; 20]), Address::from([0xEE; 20])];
        ws.set_validators(&new_set).unwrap();
        let loaded = ws.get_validators().unwrap();
        assert_eq!(loaded, new_set);
    }

    #[test]
    fn set_validators_single() {
        let store = test_store();
        let mut ws = WorldState::new(store);

        let validators = vec![Address::from([0xFF; 20])];
        ws.set_validators(&validators).unwrap();
        assert_eq!(ws.get_validators().unwrap(), validators);
    }

    #[test]
    fn set_validators_persists_across_root_reopen() {
        let store = test_store();
        let mut ws = WorldState::new(Arc::clone(&store));

        let validators = vec![Address::from([0x11; 20]), Address::from([0x22; 20])];
        ws.set_validators(&validators).unwrap();
        let root = ws.state_root().unwrap();

        let ws2 = WorldState::at_root(store, &root).unwrap();
        assert_eq!(ws2.get_validators().unwrap(), validators);
    }

    #[test]
    fn validator_registry_survives_unrelated_account_updates() {
        let store = test_store();
        let mut ws = WorldState::new(Arc::clone(&store));

        let validators = vec![Address::from([0x11; 20])];
        ws.set_validators(&validators).unwrap();
        ws.set_validator_weight(&validators[0], 1).unwrap();
        ws.add_balance(&Address::from([0xAA; 20]), U256::from(1_000))
            .unwrap();
        ws.add_balance(&Address::from([0xBB; 20]), U256::from(2_000))
            .unwrap();
        let root = ws.state_root().unwrap();

        let ws2 = WorldState::at_root(store, &root).unwrap();
        assert_eq!(ws2.get_validators().unwrap(), validators);
        assert_eq!(ws2.get_validator_weight(&validators[0]).unwrap(), 1);
    }

    #[test]
    fn validator_weights_roundtrip_and_default_to_one() {
        let store = test_store();
        let mut ws = WorldState::new(Arc::clone(&store));
        let v1 = Address::from([0x11; 20]);
        let v2 = Address::from([0x22; 20]);

        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 1);
        ws.set_validator_weight(&v1, 3).unwrap();
        ws.set_validator_weight(&v2, 0).unwrap();

        let root = ws.state_root().unwrap();
        let ws2 = WorldState::at_root(store, &root).unwrap();
        assert_eq!(ws2.get_validator_weight(&v1).unwrap(), 3);
        assert_eq!(ws2.get_validator_weight(&v2).unwrap(), 1);
    }

    #[test]
    fn validator_stake_economics_roundtrip_and_derive_weight() {
        let store = test_store();
        let mut ws = WorldState::new(Arc::clone(&store));
        let validator = Address::from([0x33; 20]);
        let stake_unit = U256::from(1_000u64);

        ws.set_staking_enabled(true).unwrap();
        ws.set_total_supply(U256::from(10_000u64)).unwrap();
        ws.set_total_staked(U256::from(0u64)).unwrap();
        ws.set_stake_unit(stake_unit).unwrap();
        ws.set_max_validator_weight(10).unwrap();
        let weight = ws
            .set_validator_stake_and_weight(&validator, U256::from(3_500u64), stake_unit, 10)
            .unwrap();
        ws.set_total_staked(U256::from(3_500u64)).unwrap();

        assert_eq!(weight, 3);
        let root = ws.state_root().unwrap();
        let ws2 = WorldState::at_root(store, &root).unwrap();
        assert!(ws2.staking_enabled().unwrap());
        assert_eq!(ws2.get_total_supply().unwrap(), U256::from(10_000u64));
        assert_eq!(ws2.get_total_staked().unwrap(), U256::from(3_500u64));
        assert_eq!(ws2.get_stake_unit().unwrap(), stake_unit);
        assert_eq!(ws2.get_max_validator_weight().unwrap(), 10);
        assert_eq!(
            ws2.get_validator_stake(&validator).unwrap(),
            U256::from(3_500u64)
        );
        assert_eq!(ws2.get_validator_weight(&validator).unwrap(), 3);
    }

    #[test]
    fn validate_empty_state_ok() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        assert!(ws.validate().is_ok());
    }

    #[test]
    fn validate_with_validators_ok() {
        let store = test_store();
        let mut ws = WorldState::new(store);
        let validators = vec![Address::from([0x01; 20]), Address::from([0x02; 20])];
        ws.set_validators(&validators).unwrap();
        assert!(ws.validate().is_ok());
    }

    #[test]
    fn validate_after_reopen_at_root() {
        let store = test_store();
        let mut ws = WorldState::new(Arc::clone(&store));
        let addr = test_address(b"val-test");
        ws.add_balance(&addr, U256::from(42)).unwrap();
        let root = ws.state_root().unwrap();

        let mut ws2 = WorldState::at_root(store, &root).unwrap();
        assert!(ws2.validate().is_ok());
    }

    #[test]
    fn validate_missing_root_returns_error_instead_of_panicking() {
        let store = test_store();
        let mut ws = WorldState::at_root(store, &ShellHash::from([0xAB; 32])).unwrap();

        assert!(ws.validate().is_err());
    }
}
