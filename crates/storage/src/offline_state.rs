//! Offline state uses ordinary validator-registry storage words, so existing
//! state roots, historical reads and trie snapshot traversal cover every field.
use crate::{validator_registry_addr, KvStore, StorageError, WorldState};
use shell_core::{OfflineCursor, OfflineState, OfflineValidatorState, TimeoutContext};
use shell_primitives::{keccak256, Address, ShellHash};

fn key(name: &[u8], suffix: &[u8]) -> ShellHash {
    keccak256(
        &[
            b"shell:offline-state:v1:".as_slice(),
            name,
            b":".as_slice(),
            suffix,
        ]
        .concat(),
    )
}
fn error(message: &str) -> StorageError {
    StorageError::Codec(message.into())
}
fn numbers(values: [u64; 4]) -> ShellHash {
    let mut bytes = [0; 32];
    for (i, value) in values.into_iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }
    ShellHash::from(bytes)
}
fn decode(word: ShellHash) -> [u64; 4] {
    std::array::from_fn(|i| {
        u64::from_be_bytes(
            word.as_bytes()[i * 8..(i + 1) * 8]
                .try_into()
                .expect("fixed eight-byte word"),
        )
    })
}

impl<S: KvStore + 'static> WorldState<S> {
    fn offline_word(&self, name: &[u8], suffix: &[u8]) -> Result<ShellHash, StorageError> {
        self.get_storage(&validator_registry_addr(), &key(name, suffix))
    }
    fn set_offline_word(
        &mut self,
        name: &[u8],
        suffix: &[u8],
        value: ShellHash,
    ) -> Result<(), StorageError> {
        let slot = key(name, suffix);
        let registry = validator_registry_addr();
        if self.get_storage(&registry, &slot)? != value {
            self.set_storage(&registry, &slot, &value)?;
        }
        Ok(())
    }
    /// Ordered effective authorities used by this root's final proposal. This
    /// records existing economic penalties without substituting a later live set.
    pub fn load_offline_authorities(&self) -> Result<Vec<(Address, u64)>, StorageError> {
        let [count, r1, r2, r3] = decode(self.offline_word(b"set-header", b"")?);
        if count > Self::MAX_VALIDATORS as u64 || r1 != 0 || r2 != 0 || r3 != 0 {
            return Err(error("invalid offline authority header"));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut authorities = Vec::with_capacity(count as usize);
        for i in 0..count {
            let suffix = i.to_be_bytes();
            let address = Address::from(*self.offline_word(b"set-member", &suffix)?.as_bytes());
            let [weight, r1, r2, r3] = decode(self.offline_word(b"set-weight", &suffix)?);
            if r1 != 0 || r2 != 0 || r3 != 0 {
                return Err(error("invalid offline authority weight"));
            }
            authorities.push((address, weight));
        }
        let hash =
            shell_core::timeout_authority_set_hash(&authorities).map_err(StorageError::Codec)?;
        let state = self.load_offline_state()?;
        if !state
            .cursor()
            .is_some_and(|c| c.proposed && c.context.authority_set_hash == hash)
        {
            return Err(error("offline authorities do not match committed proposal"));
        }
        Ok(authorities)
    }
    pub fn save_offline_authorities(
        &mut self,
        authorities: &[(Address, u64)],
    ) -> Result<(), StorageError> {
        if authorities.len() > Self::MAX_VALIDATORS {
            return Err(error("too many offline authorities"));
        }
        let hash =
            shell_core::timeout_authority_set_hash(authorities).map_err(StorageError::Codec)?;
        if !self
            .load_offline_state()?
            .cursor()
            .is_some_and(|c| c.proposed && c.context.authority_set_hash == hash)
        {
            return Err(error(
                "offline authority checkpoint does not bind final proposal",
            ));
        }
        // The previous cursor may now describe the new proposal, so inspect the
        // old list length without revalidating its old hash against that cursor.
        let [previous, r1, r2, r3] = decode(self.offline_word(b"set-header", b"")?);
        if previous > Self::MAX_VALIDATORS as u64 || r1 != 0 || r2 != 0 || r3 != 0 {
            return Err(error("invalid previous offline authority header"));
        }
        let mut next = self.snapshot()?;
        for (i, (address, weight)) in authorities.iter().enumerate() {
            let suffix = (i as u64).to_be_bytes();
            next.set_offline_word(b"set-member", &suffix, ShellHash::from(*address.as_bytes()))?;
            next.set_offline_word(b"set-weight", &suffix, numbers([*weight, 0, 0, 0]))?;
        }
        for i in authorities.len() as u64..previous {
            next.set_offline_word(b"set-member", &i.to_be_bytes(), ShellHash::ZERO)?;
            next.set_offline_word(b"set-weight", &i.to_be_bytes(), ShellHash::ZERO)?;
        }
        next.set_offline_word(
            b"set-header",
            b"",
            numbers([authorities.len() as u64, 0, 0, 0]),
        )?;
        next.state_root()?;
        *self = next;
        Ok(())
    }
    /// No sidecar body, current-state substitution or writeback is needed.
    pub fn load_offline_state(&self) -> Result<OfflineState, StorageError> {
        let [count, flag, r1, r2] = decode(self.offline_word(b"header", b"")?);
        if count > Self::MAX_VALIDATORS as u64 || flag > 2 || r1 != 0 || r2 != 0 {
            return Err(error("invalid offline state header"));
        }
        let mut validators = Vec::with_capacity(count as usize);
        for i in 0..count {
            let address =
                Address::from(*self.offline_word(b"member", &i.to_be_bytes())?.as_bytes());
            let [misses, pending, recovery, r2] =
                decode(self.offline_word(b"validator", address.as_bytes())?);
            if r2 != 0 {
                return Err(error("invalid offline validator state"));
            }
            validators.push(OfflineValidatorState {
                address,
                consecutive_misses: misses,
                suspend_at_epoch: (pending != 0).then_some(pending),
                recover_at_epoch: (recovery != 0).then_some(recovery),
            });
        }
        let slots = [
            b"cursor".as_slice(),
            b"parent".as_slice(),
            b"authorities".as_slice(),
            b"proposer".as_slice(),
            b"opportunity".as_slice(),
        ];
        let mut words = [ShellHash::ZERO; 5];
        for (i, name) in slots.iter().enumerate() {
            words[i] = self.offline_word(name, b"")?;
        }
        let cursor = if flag == 0 {
            if words.iter().any(|word| *word != ShellHash::ZERO) {
                return Err(error("unexpected offline cursor words"));
            }
            None
        } else {
            let [chain_id, block_number, view, epoch] = decode(words[0]);
            Some(OfflineCursor {
                context: TimeoutContext {
                    chain_id,
                    block_number,
                    view,
                    epoch,
                    parent_hash: words[1],
                    authority_set_hash: words[2],
                    proposer: Address::from(*words[3].as_bytes()),
                    opportunity_hash: words[4],
                },
                proposed: flag == 2,
            })
        };
        OfflineState::from_parts(validators, cursor, self.offline_word(b"transcript", b"")?)
            .map_err(StorageError::Codec)
    }
    /// Stage all registry changes in an independent world-state handle. A failed
    /// trie write cannot publish partial counters, roots or balance changes.
    pub fn save_offline_state(&mut self, state: &OfflineState) -> Result<(), StorageError> {
        state.validate().map_err(StorageError::Codec)?;
        if state.validators().len() > Self::MAX_VALIDATORS {
            return Err(error("too many offline validators"));
        }
        let previous = self.load_offline_state()?;
        let mut next = self.snapshot()?;
        for old in previous.validators() {
            if state.validator(&old.address).is_none() {
                next.set_offline_word(b"validator", old.address.as_bytes(), ShellHash::ZERO)?;
            }
        }
        for (i, member) in state.validators().iter().enumerate() {
            next.set_offline_word(
                b"member",
                &(i as u64).to_be_bytes(),
                ShellHash::from(*member.address.as_bytes()),
            )?;
            next.set_offline_word(
                b"validator",
                member.address.as_bytes(),
                numbers([
                    member.consecutive_misses,
                    member.suspend_at_epoch.unwrap_or(0),
                    member.recover_at_epoch.unwrap_or(0),
                    0,
                ]),
            )?;
        }
        for i in state.validators().len()..previous.validators().len() {
            next.set_offline_word(b"member", &(i as u64).to_be_bytes(), ShellHash::ZERO)?;
        }
        let flag = state
            .cursor()
            .map_or(0, |cursor| if cursor.proposed { 2 } else { 1 });
        next.set_offline_word(
            b"header",
            b"",
            numbers([state.validators().len() as u64, flag, 0, 0]),
        )?;
        let mut words = [ShellHash::ZERO; 5];
        if let Some(cursor) = state.cursor() {
            let c = &cursor.context;
            words = [
                numbers([c.chain_id, c.block_number, c.view, c.epoch]),
                c.parent_hash,
                c.authority_set_hash,
                ShellHash::from(*c.proposer.as_bytes()),
                c.opportunity_hash,
            ];
        }
        for (name, word) in [
            b"cursor".as_slice(),
            b"parent".as_slice(),
            b"authorities".as_slice(),
            b"proposer".as_slice(),
            b"opportunity".as_slice(),
        ]
        .iter()
        .zip(words)
        {
            next.set_offline_word(name, b"", word)?;
        }
        next.set_offline_word(b"transcript", b"", state.transcript())?;
        next.state_root()?;
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryDb, WriteBatch};
    use shell_primitives::U256;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    fn context(a: Address) -> TimeoutContext {
        TimeoutContext {
            chain_id: 1337,
            block_number: 1,
            view: 0,
            parent_hash: ShellHash::from([1; 32]),
            epoch: 0,
            authority_set_hash: ShellHash::from([2; 32]),
            proposer: a,
            opportunity_hash: ShellHash::from([3; 32]),
        }
    }
    #[test]
    fn offline_state_root_history_and_reopen_keep_balances_and_counters_separate() {
        let db = Arc::new(MemoryDb::new());
        let mut ws = WorldState::new(Arc::clone(&db));
        let a = Address::from([1; 32]);
        let b = Address::from([2; 32]);
        ws.add_balance(&a, U256::from(123)).unwrap();
        ws.set_validator_stake(&a, U256::from(50)).unwrap();
        let mut state = OfflineState::default();
        state.sync_membership(&[a, b]).unwrap();
        ws.save_offline_state(&state).unwrap();
        let old = ws.state_root().unwrap();
        state
            .record_verified_timeout(&context(a), ShellHash::from([4; 32]))
            .unwrap();
        ws.save_offline_state(&state).unwrap();
        let current = ws.state_root().unwrap();
        assert_ne!(old, current);
        assert_eq!(ws.get_balance(&a).unwrap(), U256::from(123));
        assert_eq!(ws.get_validator_stake(&a).unwrap(), U256::from(50));
        drop(ws);
        let mut reopened = WorldState::at_root(Arc::clone(&db), &current).unwrap();
        assert_eq!(
            reopened
                .load_offline_state()
                .unwrap()
                .validator(&a)
                .unwrap()
                .consecutive_misses,
            1
        );
        let historic = WorldState::at_root(Arc::clone(&db), &old).unwrap();
        assert_eq!(
            historic
                .load_offline_state()
                .unwrap()
                .validator(&a)
                .unwrap()
                .consecutive_misses,
            0
        );
        assert_eq!(reopened.state_root().unwrap(), current);
        WorldState::validate_snapshot_nodes(db.as_ref(), current).unwrap();
        assert_eq!(reopened.load_offline_state().unwrap(), state);
        // An unknown counter value in committed registry state is rejected, not reset.
        reopened
            .set_offline_word(b"validator", a.as_bytes(), numbers([101, 0, 0, 0]))
            .unwrap();
        assert!(reopened.load_offline_state().is_err());
    }
    #[derive(Default)]
    struct FailTrie {
        inner: MemoryDb,
        remaining: AtomicUsize,
        writes: AtomicUsize,
    }
    impl FailTrie {
        fn check(&self) -> Result<(), StorageError> {
            if self.remaining.load(Ordering::SeqCst) > 0 {
                self.writes.fetch_add(1, Ordering::SeqCst);
                if self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                    return Err(StorageError::Database("injected trie failure".into()));
                }
            }
            Ok(())
        }
    }
    impl KvStore for FailTrie {
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(k)
        }
        fn put(&self, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
            self.check()?;
            self.inner.put(k, v)
        }
        fn delete(&self, k: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(k)
        }
        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }
        fn write_batch(&self, b: WriteBatch) -> Result<(), StorageError> {
            self.check()?;
            self.inner.write_batch(b)
        }
        fn scan_prefix(&self, p: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(p)
        }
    }
    #[test]
    fn offline_state_failed_root_publication_preserves_original_state() {
        let db = Arc::new(FailTrie::default());
        let mut ws = WorldState::new(Arc::clone(&db));
        let a = Address::from([1; 32]);
        let mut state = OfflineState::default();
        state.sync_membership(&[a]).unwrap();
        ws.save_offline_state(&state).unwrap();
        let root = ws.state_root().unwrap();
        state
            .record_verified_timeout(&context(a), ShellHash::from([4; 32]))
            .unwrap();
        db.remaining.store(2, Ordering::SeqCst);
        assert!(ws.save_offline_state(&state).is_err());
        assert_eq!(db.writes.load(Ordering::SeqCst), 2);
        assert_eq!(ws.state_root().unwrap(), root);
        assert_eq!(
            ws.load_offline_state()
                .unwrap()
                .validator(&a)
                .unwrap()
                .consecutive_misses,
            0
        );
        ws.save_offline_state(&state).unwrap();
        assert_eq!(
            ws.load_offline_state()
                .unwrap()
                .validator(&a)
                .unwrap()
                .consecutive_misses,
            1
        );
    }
    #[test]
    fn offline_authorities_preserve_order_weights_history_and_snapshot_nodes() {
        let db = Arc::new(MemoryDb::new());
        let mut ws = WorldState::new(db.clone());
        let a = Address::from([1; 32]);
        let b = Address::from([2; 32]);
        let original = vec![(b, 3), (a, 1)];
        let mut ledger = OfflineState::default();
        ledger.sync_membership(&[a, b]).unwrap();
        let mut c = context(b);
        c.authority_set_hash = shell_core::timeout_authority_set_hash(&original).unwrap();
        ledger.record_verified_proposal(&c).unwrap();
        ws.save_offline_state(&ledger).unwrap();
        ws.save_offline_authorities(&original).unwrap();
        let first = ws.state_root().unwrap();
        assert_eq!(ws.load_offline_authorities().unwrap(), original);
        assert!(ws.save_offline_authorities(&[(a, 1), (b, 3)]).is_err());
        assert_eq!(ws.state_root().unwrap(), first);
        c.block_number = 2;
        c.parent_hash = first;
        c.proposer = a;
        c.authority_set_hash = shell_core::timeout_authority_set_hash(&[(a, 1)]).unwrap();
        ledger.record_verified_proposal(&c).unwrap();
        ledger.sync_membership(&[a]).unwrap();
        ws.save_offline_state(&ledger).unwrap();
        ws.save_offline_authorities(&[(a, 1)]).unwrap();
        let second = ws.state_root().unwrap();
        assert_ne!(first, second);
        let old = WorldState::at_root(db.clone(), &first).unwrap();
        assert_eq!(old.load_offline_authorities().unwrap(), original);
        let mut current = WorldState::at_root(db.clone(), &second).unwrap();
        assert_eq!(current.load_offline_authorities().unwrap(), vec![(a, 1)]);
        WorldState::validate_snapshot_nodes(db.as_ref(), second).unwrap();
        current
            .set_offline_word(b"set-weight", &0u64.to_be_bytes(), numbers([2, 0, 0, 0]))
            .unwrap();
        assert!(current.load_offline_authorities().is_err());
        current
            .set_offline_word(
                b"set-header",
                b"",
                numbers([WorldState::<MemoryDb>::MAX_VALIDATORS as u64 + 1, 0, 0, 0]),
            )
            .unwrap();
        assert!(current.load_offline_authorities().is_err());
    }
    #[test]
    fn offline_authority_checkpoint_failed_write_keeps_original_root() {
        let db = Arc::new(FailTrie::default());
        let mut ws = WorldState::new(db.clone());
        let a = Address::from([1; 32]);
        let set = vec![(a, 3)];
        let mut c = context(a);
        c.authority_set_hash = shell_core::timeout_authority_set_hash(&set).unwrap();
        let mut ledger = OfflineState::default();
        ledger.sync_membership(&[a]).unwrap();
        ledger.record_verified_proposal(&c).unwrap();
        ws.save_offline_state(&ledger).unwrap();
        let before = ws.state_root().unwrap();
        db.remaining.store(2, Ordering::SeqCst);
        assert!(ws.save_offline_authorities(&set).is_err());
        assert_eq!(ws.state_root().unwrap(), before);
        assert!(ws.load_offline_authorities().unwrap().is_empty());
        ws.save_offline_authorities(&set).unwrap();
        assert_eq!(ws.load_offline_authorities().unwrap(), set);
    }
}
