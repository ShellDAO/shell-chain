use shell_primitives::{Root, StateKey, StateWitness};

use crate::errors::StateError;
use crate::transition::StatePatch;

pub trait StateAccumulator {
    fn get_witness_for_accesses(
        &self,
        accesses: &[StateKey],
    ) -> Result<alloc::vec::Vec<StateWitness>, StateError>;

    fn apply_transition(&mut self, patch: &StatePatch) -> Result<Root, StateError>;

    fn state_root(&self) -> Root;
}
