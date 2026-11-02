//! Deterministic state transitions for certified assigned misses. Runtime callers
//! authenticate certificates/proposals/governance and enforce activation first.
use crate::TimeoutContext;
use serde::{Deserialize, Serialize};
use shell_primitives::{keccak256, Address, ShellHash};

pub const OFFLINE_ASSIGNED_MISS_THRESHOLD: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineValidatorState {
    pub address: Address,
    pub consecutive_misses: u64,
    pub suspend_at_epoch: Option<u64>,
    #[serde(default)]
    pub recover_at_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineCursor {
    pub context: TimeoutContext,
    pub proposed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineState {
    validators: Vec<OfflineValidatorState>,
    cursor: Option<OfflineCursor>,
    /// Commits every accepted certificate's bytes, including its genuine signatures.
    transcript: ShellHash,
}

impl OfflineState {
    pub fn cursor(&self) -> Option<&OfflineCursor> {
        self.cursor.as_ref()
    }
    pub fn from_parts(
        validators: Vec<OfflineValidatorState>,
        cursor: Option<OfflineCursor>,
        transcript: ShellHash,
    ) -> Result<Self, String> {
        let state = Self {
            validators,
            cursor,
            transcript,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn validators(&self) -> &[OfflineValidatorState] {
        &self.validators
    }
    pub fn transcript(&self) -> ShellHash {
        self.transcript
    }
    pub fn validator(&self, address: &Address) -> Option<&OfflineValidatorState> {
        self.validators.iter().find(|v| v.address == *address)
    }
    pub fn is_suspended(&self, address: &Address, epoch: u64) -> bool {
        self.validator(address).is_some_and(|v| {
            v.suspend_at_epoch.is_some_and(|at| epoch >= at)
                && v.recover_at_epoch.is_none_or(|at| epoch < at)
        })
    }

    /// Called after authenticated membership updates. Leaving removes old history;
    /// a subsequently rejoining validator starts with a fresh consecutive counter.
    pub fn sync_membership(&mut self, members: &[Address]) -> Result<(), String> {
        let mut ordered = members.to_vec();
        ordered.sort_by_key(|address| *address.as_bytes());
        if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("duplicate offline-state member".into());
        }
        self.validators = ordered
            .into_iter()
            .map(|address| {
                self.validator(&address)
                    .cloned()
                    .unwrap_or(OfflineValidatorState {
                        address,
                        consecutive_misses: 0,
                        suspend_at_epoch: None,
                        recover_at_epoch: None,
                    })
            })
            .collect();
        Ok(())
    }

    fn check_slot(&self, context: &TimeoutContext) -> Result<(), String> {
        if context.block_number == 0 || context.parent_hash == ShellHash::ZERO {
            return Err("offline opportunity at genesis".into());
        }
        match &self.cursor {
            None if context.view == 0 => Ok(()),
            Some(last)
                if last.proposed
                    && last.context.block_number.checked_add(1) == Some(context.block_number)
                    && context.view == 0
                    && context.epoch >= last.context.epoch =>
            {
                Ok(())
            }
            Some(last)
                if !last.proposed
                    && context.block_number == last.context.block_number
                    && context.parent_hash == last.context.parent_hash
                    && context.epoch == last.context.epoch
                    && context.authority_set_hash == last.context.authority_set_hash
                    && last.context.view.checked_add(1) == Some(context.view) =>
            {
                Ok(())
            }
            _ => Err("replayed, missing or out-of-order offline opportunity".into()),
        }
    }

    fn record(&mut self, context: &TimeoutContext, digest: ShellHash, proposed: bool) {
        let mut bytes = b"shell:offline-transcript:v1".to_vec();
        bytes.extend_from_slice(self.transcript.as_bytes());
        bytes.push(u8::from(proposed));
        bytes.extend_from_slice(&context.signing_message(&Address::ZERO));
        bytes.extend_from_slice(digest.as_bytes());
        self.transcript = keccak256(&bytes);
        self.cursor = Some(OfflineCursor {
            context: context.clone(),
            proposed,
        });
    }

    /// Trusted consensus entry: the caller has verified the full certificate and
    /// canonical opportunity. All refusals precede mutation. No economic state exists here.
    pub fn record_verified_timeout(
        &mut self,
        context: &TimeoutContext,
        proof_hash: ShellHash,
    ) -> Result<(), String> {
        self.check_slot(context)?;
        if proof_hash == ShellHash::ZERO
            || context.opportunity_hash == ShellHash::ZERO
            || context.view == u64::MAX
        {
            return Err("timeout requires an admitted opportunity and proof commitment".into());
        }
        let current = self
            .validator(&context.proposer)
            .ok_or("unknown assigned validator")?;
        if self.is_suspended(&context.proposer, context.epoch) {
            return Err("assigned validator already suspended".into());
        }
        let misses = current
            .consecutive_misses
            .saturating_add(1)
            .min(OFFLINE_ASSIGNED_MISS_THRESHOLD);
        let pending =
            if misses == OFFLINE_ASSIGNED_MISS_THRESHOLD && current.suspend_at_epoch.is_none() {
                Some(
                    context
                        .epoch
                        .checked_add(1)
                        .ok_or("suspension epoch overflow")?,
                )
            } else {
                current.suspend_at_epoch
            };
        let entry = self
            .validators
            .iter_mut()
            .find(|v| v.address == context.proposer)
            .expect("member checked");
        entry.consecutive_misses = misses;
        entry.suspend_at_epoch = pending;
        self.record(context, proof_hash, false);
        Ok(())
    }

    /// Called only for an authenticated, correctly assigned canonical proposal.
    /// A reset does not cancel a suspension already triggered at the threshold.
    pub fn record_verified_proposal(&mut self, context: &TimeoutContext) -> Result<(), String> {
        self.check_slot(context)?;
        if self.is_suspended(&context.proposer, context.epoch) {
            return Err("proposal by suspended validator".into());
        }
        let entry = self
            .validators
            .iter_mut()
            .find(|v| v.address == context.proposer)
            .ok_or("unknown proposal validator")?;
        entry.consecutive_misses = 0;
        self.record(context, ShellHash::ZERO, true);
        Ok(())
    }

    /// Called only after authenticated weighted governance has approved recovery.
    /// The current epoch remains suspended; the next common epoch clears it.
    pub fn schedule_recovery_authorized(
        &mut self,
        address: &Address,
        epoch: u64,
    ) -> Result<(), String> {
        if !self.is_suspended(address, epoch) {
            return Err("validator is not suspended".into());
        }
        let at = epoch.checked_add(1).ok_or("recovery epoch overflow")?;
        let entry = self
            .validators
            .iter_mut()
            .find(|v| v.address == *address)
            .ok_or("unknown recovery validator")?;
        if entry.recover_at_epoch.is_some() {
            return Err("recovery already scheduled".into());
        }
        entry.recover_at_epoch = Some(at);
        Ok(())
    }

    /// Canonical block prefix, before accounting for this epoch's opportunities.
    pub fn activate_recoveries(&mut self, epoch: u64) {
        for entry in &mut self.validators {
            if entry.recover_at_epoch.is_some_and(|at| epoch >= at) {
                entry.consecutive_misses = 0;
                entry.suspend_at_epoch = None;
                entry.recover_at_epoch = None;
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.validators.iter().any(|v| {
            v.consecutive_misses > OFFLINE_ASSIGNED_MISS_THRESHOLD
                || v.suspend_at_epoch == Some(0)
                || v.recover_at_epoch
                    .is_some_and(|at| v.suspend_at_epoch.is_none_or(|suspended| at <= suspended))
                || (v.consecutive_misses == OFFLINE_ASSIGNED_MISS_THRESHOLD
                    && v.suspend_at_epoch.is_none())
        }) || self
            .validators
            .windows(2)
            .any(|pair| pair[0].address.as_bytes() >= pair[1].address.as_bytes())
            || self
                .cursor
                .as_ref()
                .is_some_and(|c| c.context.block_number == 0)
        {
            return Err("invalid persisted offline state".into());
        }
        Ok(())
    }
    pub fn to_state_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, String> {
        let state: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        state.validate()?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_success_resets_counter_and_invalid_slot_keeps_state() {
        let a = Address::from([1; 32]);
        let mut state = OfflineState::default();
        state.sync_membership(&[a]).unwrap();
        let mut context = TimeoutContext {
            chain_id: 1337,
            block_number: 7,
            view: 0,
            parent_hash: ShellHash::from([1; 32]),
            epoch: 0,
            authority_set_hash: ShellHash::from([2; 32]),
            proposer: a,
            opportunity_hash: ShellHash::from([3; 32]),
        };
        state
            .record_verified_timeout(&context, ShellHash::from([4; 32]))
            .unwrap();
        let snapshot = state.clone();
        assert!(state
            .record_verified_timeout(&context, ShellHash::from([5; 32]))
            .is_err());
        assert_eq!(state, snapshot);
        context.view = 1;
        state.record_verified_proposal(&context).unwrap();
        assert_eq!(state.validator(&a).unwrap().consecutive_misses, 0);
        context.block_number = 8;
        context.view = 0;
        state
            .record_verified_timeout(&context, ShellHash::from([6; 32]))
            .unwrap();
        assert_eq!(state.validator(&a).unwrap().consecutive_misses, 1);
        let snapshot = state.clone();
        context.view = 2;
        assert!(state.record_verified_proposal(&context).is_err());
        assert_eq!(state, snapshot);
        state.sync_membership(&[]).unwrap();
        state.sync_membership(&[a]).unwrap();
        assert_eq!(state.validator(&a).unwrap().consecutive_misses, 0);
    }
}
