pub mod challenge;
mod engine;
mod error;
mod finality;
mod fork_choice;
pub mod peer_scoring;
mod poa;
pub mod prover_registry;
pub mod rate_limiter;
pub mod slashing;
pub mod validator;
pub mod view_change;
pub mod window;
pub mod wpoa;
pub mod wpoa_state;

pub use challenge::{ChallengeReason, ChallengeResponse, ProofChallenge};
pub use engine::{ConsensusEngine, EngineType};
pub use error::ConsensusError;
pub use finality::{Attestation, FinalityState};
pub use fork_choice::{BlockScore, ForkChoice};
pub use peer_scoring::{PeerEvent, PeerId as ScoringPeerId, PeerScorer, PeerScoringConfig};
pub use poa::{PoaConfig, PoaEngine};
pub use prover_registry::{ProverRecord, ProverRegistry, ProverRegistryConfig, RegistryError};
pub use rate_limiter::{ProofRateLimiter, RateLimiterConfig};
pub use slashing::{
    detect_double_sign, detect_offline, EquivocationProof, SlashEvidence, SlashRecord, SlashType,
    SlashingConfig,
};
pub use validator::{ValidatorInfo, ValidatorSet, ValidatorSetConfig, ValidatorStatus};

fn round_robin_index(block_number: u64, count: usize) -> Option<usize> {
    if count == 0 {
        return None;
    }
    let count = u64::try_from(count).expect("validator count fits in u64");
    Some(usize::try_from(block_number % count).expect("proposer index fits in usize"))
}
pub use view_change::{ViewChangeMessage, ViewChangeState, VIEW_CHANGE_TIMEOUT_MS};
pub use window::{ProofWindowManager, WindowConfig, WindowError, WindowState};
pub use wpoa::{WPoaConfig, WPoaEngine};
pub use wpoa_state::{WPoaEvent, WPoaRound};
