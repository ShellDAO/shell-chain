use super::*;

/// Canonical-chain transition classifier used before block import mutates
/// storage or state. This keeps fork, gap, stale, and finalized-conflict
/// decisions in one place instead of scattering them across importer branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockImportTransition {
    DuplicateOrStale,
    SameHeightFork,
    NextHeightFork,
    CanonicalNext,
    Gap { incoming: u64, expected: u64 },
}

pub(crate) struct ChainStateMachine;

impl ChainStateMachine {
    pub(crate) fn next_block_number(parent_number: u64) -> Result<u64, NodeError> {
        parent_number
            .checked_add(1)
            .ok_or_else(|| NodeError::Startup("block number overflows u64".into()))
    }

    pub(crate) fn classify_import(
        head_number: u64,
        head_hash: ShellHash,
        incoming_number: u64,
        incoming_hash: ShellHash,
        incoming_parent: ShellHash,
        finalized_number: u64,
        canonical_hash_at_incoming: Option<ShellHash>,
    ) -> Result<BlockImportTransition, NodeError> {
        if finalized_number > 0
            && incoming_number <= finalized_number
            && canonical_hash_at_incoming != Some(incoming_hash)
        {
            return Err(NodeError::ConflictsWithFinalized {
                incoming: incoming_number,
                fin_number: finalized_number,
            });
        }

        if incoming_number == head_number && incoming_hash != head_hash {
            return Ok(BlockImportTransition::SameHeightFork);
        }
        if incoming_number <= head_number {
            return Ok(BlockImportTransition::DuplicateOrStale);
        }
        let expected = Self::next_block_number(head_number)?;
        if incoming_number == expected && incoming_parent != head_hash {
            return Ok(BlockImportTransition::NextHeightFork);
        }
        if incoming_number > expected {
            return Ok(BlockImportTransition::Gap {
                incoming: incoming_number,
                expected,
            });
        }

        Ok(BlockImportTransition::CanonicalNext)
    }

    pub(crate) fn ensure_production_parent(
        head_number: u64,
        head_hash: ShellHash,
        next_number: u64,
        canonical_next_exists: bool,
        finalized_number: u64,
        finalized_hash: ShellHash,
    ) -> Result<(), NodeError> {
        if canonical_next_exists {
            debug!(
                next_number,
                "canonical block already exists, skipping production"
            );
            return Err(NodeError::NotProposer);
        }

        if finalized_number == 0 {
            return Ok(());
        }
        if head_number < finalized_number {
            warn!(
                head_number,
                finalized_number, "head is below finalized number, refusing to produce block"
            );
            return Err(NodeError::ConflictsWithFinalized {
                incoming: head_number,
                fin_number: finalized_number,
            });
        }
        if head_number == finalized_number && head_hash != finalized_hash {
            warn!(
                head_number,
                %head_hash,
                %finalized_hash,
                "head hash diverges from finalized hash, refusing to produce block"
            );
            return Err(NodeError::ConflictsWithFinalized {
                incoming: head_number,
                fin_number: finalized_number,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> ShellHash {
        ShellHash::from_slice(&[byte; 32])
    }

    #[test]
    fn next_block_number_rejects_height_overflow() {
        assert_eq!(ChainStateMachine::next_block_number(41).unwrap(), 42);
        let err = ChainStateMachine::next_block_number(u64::MAX).unwrap_err();
        assert!(matches!(err, NodeError::Startup(message) if message.contains("overflows u64")));
    }

    #[test]
    fn classifies_canonical_next_block() {
        assert_eq!(
            ChainStateMachine::classify_import(7, h(1), 8, h(2), h(1), 0, None).unwrap(),
            BlockImportTransition::CanonicalNext
        );
    }

    #[test]
    fn classifies_side_forks_without_mutating_canonical_head() {
        assert_eq!(
            ChainStateMachine::classify_import(7, h(1), 7, h(2), h(0), 0, Some(h(1))).unwrap(),
            BlockImportTransition::SameHeightFork
        );
        assert_eq!(
            ChainStateMachine::classify_import(7, h(1), 8, h(3), h(9), 0, None).unwrap(),
            BlockImportTransition::NextHeightFork
        );
    }

    #[test]
    fn classifies_stale_and_gap_blocks() {
        assert_eq!(
            ChainStateMachine::classify_import(7, h(1), 6, h(2), h(0), 0, Some(h(2))).unwrap(),
            BlockImportTransition::DuplicateOrStale
        );
        assert_eq!(
            ChainStateMachine::classify_import(7, h(1), 10, h(2), h(0), 0, None).unwrap(),
            BlockImportTransition::Gap {
                incoming: 10,
                expected: 8
            }
        );
    }

    #[test]
    fn rejects_conflicts_at_finalized_height() {
        let err =
            ChainStateMachine::classify_import(7, h(1), 5, h(2), h(0), 5, Some(h(3))).unwrap_err();

        assert!(matches!(
            err,
            NodeError::ConflictsWithFinalized {
                incoming: 5,
                fin_number: 5
            }
        ));
    }

    #[test]
    fn rejects_finalized_import_when_canonical_mapping_is_missing() {
        let err = ChainStateMachine::classify_import(7, h(1), 5, h(2), h(0), 5, None).unwrap_err();

        assert!(matches!(
            err,
            NodeError::ConflictsWithFinalized {
                incoming: 5,
                fin_number: 5
            }
        ));
    }

    #[test]
    fn production_parent_rejects_duplicate_next_block() {
        let err = ChainStateMachine::ensure_production_parent(7, h(1), 8, true, 0, ShellHash::ZERO)
            .unwrap_err();

        assert!(matches!(err, NodeError::NotProposer));
    }
}
