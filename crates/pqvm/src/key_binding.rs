use shell_crypto::{SignatureType, ALLOWED_ALGORITHMS};
use shell_primitives::{blake3_hash, Address, ShellHash};
use shell_storage::{ChainStore, KvStore, StorageError, WorldState};

pub(crate) fn enabled<S: KvStore>(
    store: &ChainStore<S>,
    height: u64,
) -> Result<bool, StorageError> {
    Ok(store
        .get_chain_config()?
        .and_then(|c| c.registered_key_algorithm_height)
        .is_some_and(|activation| height >= activation))
}

pub(crate) fn algorithm_hash(pubkey: &[u8], algorithm: SignatureType) -> ShellHash {
    ShellHash::from(*Address::from_public_key(pubkey, algorithm.as_u8()).as_bytes())
}

pub(crate) fn bound_algorithm<S: KvStore>(
    world: &WorldState<S>,
    store: &ChainStore<S>,
    address: &Address,
    pubkey: &[u8],
    height: u64,
) -> Result<Option<SignatureType>, StorageError> {
    if !enabled(store, height)? || store.get_pubkey(address)?.as_deref() != Some(pubkey) {
        return Ok(None);
    }
    let Some(account) = world.get_account(address)? else {
        return Ok(None);
    };
    Ok(ALLOWED_ALGORITHMS
        .iter()
        .copied()
        .find(|algorithm| account.pq_pubkey_hash == algorithm_hash(pubkey, *algorithm)))
}

pub(crate) fn key_matches<S: KvStore>(
    world: &WorldState<S>,
    store: &ChainStore<S>,
    address: &Address,
    pubkey: &[u8],
    height: u64,
) -> Result<bool, StorageError> {
    let Some(account) = world.get_account(address)? else {
        return Ok(false);
    };
    Ok(account.pq_pubkey_hash == blake3_hash(pubkey)
        || bound_algorithm(world, store, address, pubkey, height)?.is_some())
}
