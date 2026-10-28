//! CLI command implementations.

pub mod account;
mod backup;
#[cfg(unix)]
mod database_lock;
mod export_state;
mod genesis;
mod import_state;
mod init;
mod key;
pub mod pqhd;
mod removedb;
mod rpc;
pub mod run;
pub mod tx;
mod version;
pub mod wallet;

pub use backup::{create_backup, restore_backup};
pub use export_state::export_state;
pub use genesis::{
    genesis_add_alloc, genesis_set_economics, genesis_set_validator_stake, genesis_validate_supply,
};
pub use import_state::import_state;
pub use init::init;
pub use key::{key_generate, key_inspect, key_migrate};
pub use removedb::removedb;
pub use run::run;
pub use version::version;

/// A supplied genesis defines the network identity; an explicit selection must agree.
pub(crate) fn validate_genesis_chain_id(
    requested: Option<u64>,
    genesis_chain_id: u64,
) -> Result<(), String> {
    if let Some(requested) = requested {
        if requested != genesis_chain_id {
            return Err(format!(
                "requested chain ID {requested} does not match genesis chain ID {genesis_chain_id}"
            ));
        }
    }
    Ok(())
}
