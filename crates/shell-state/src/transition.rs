use shell_primitives::{MockProgressiveByteList, MockProgressiveList, Root, StateKey};

use crate::errors::StateError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePatch {
    pub accesses: MockProgressiveList<StateKey>,
    pub new_values: MockProgressiveList<MockProgressiveByteList>,
}

impl StatePatch {
    pub fn validate_shape(&self) -> Result<(), StateError> {
        if self.accesses.len() != self.new_values.len() {
            return Err(StateError::TransitionShapeMismatch {
                accesses: self.accesses.len(),
                new_values: self.new_values.len(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateTransitionOutcome {
    pub post_state_root: Root,
}

pub trait StateTransitionApplier {
    fn apply_transition(
        &self,
        pre_state_root: &Root,
        patch: &StatePatch,
    ) -> Result<StateTransitionOutcome, StateError>;
}
