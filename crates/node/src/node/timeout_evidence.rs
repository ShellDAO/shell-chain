use super::*;
use shell_consensus::TimeoutCertificate;

/// One bounded local observation, separate from canonical state and penalties.
const LATEST_TIMEOUT_CERTIFICATE: &[u8] = b"meta:latest_timeout_certificate_v1";

impl<S: KvStore + 'static> Node<S> {
    /// Return the last durably observed timeout proof. Callers must verify it
    /// against the applicable canonical roster before using it as evidence.
    pub fn latest_timeout_certificate(&self) -> Result<Option<TimeoutCertificate>, NodeError> {
        self.chain_store
            .store()
            .get(LATEST_TIMEOUT_CERTIFICATE)?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| {
                    NodeError::Startup(format!("invalid stored timeout certificate: {error}"))
                })
            })
            .transpose()
    }

    /// Activated transitions retain the verified complete sequence before
    /// changing view. Legacy observations remain diagnostic and best effort.
    pub(crate) fn apply_observed_view_change(&self, msg: ViewChangeMessage) -> bool {
        let strict = match self.offline_accounting_active(msg.block_number) {
            Ok(active) => active,
            Err(error) => {
                warn!(%error, "cannot determine timeout activation");
                return false;
            }
        };
        let expected_block = match self
            .chain_store
            .get_head_block()
            .map_err(NodeError::from)
            .and_then(|head| {
                ChainStateMachine::next_block_number(head.map_or(0, |block| block.number()))
            }) {
            Ok(height) => height,
            Err(error) => {
                warn!(%error, "cannot check timeout height");
                return false;
            }
        };
        let highest_qc = match self.timeout_vote_qc(expected_block) {
            Ok(qc) => qc,
            Err(error) => {
                warn!(%error, "cannot check certified timeout parent");
                return false;
            }
        };
        if strict
            && (msg.block_number != expected_block
                || msg.chain_id != self.config.chain_id
                || msg.highest_qc_hash != highest_qc)
        {
            return false;
        }
        let public_keys = self.known_authorities.read().clone();
        let (advanced, before, weights, votes) = {
            let mut consensus = self.consensus.write();
            consensus.set_strict_timeout_quorum(strict);
            let weights = consensus.validator_weights();
            let total_weight = weights.values().copied().sum();
            let before = consensus.current_view();
            let advanced = if strict {
                consensus.handle_view_change_with_commit(msg, total_weight, &mut |votes| {
                    let certificate = TimeoutCertificate {
                        votes: votes.to_vec(),
                    };
                    if !certificate.verify(
                        self.config.chain_id,
                        expected_block,
                        before,
                        highest_qc,
                        &weights,
                        &public_keys,
                        &MultiVerifier,
                    ) {
                        return false;
                    }
                    match self.retain_pending_timeout(&certificate) {
                        Ok(()) => true,
                        Err(error) => {
                            warn!(%error, "cannot advance view without retained timeout evidence");
                            false
                        }
                    }
                })
            } else {
                consensus.handle_view_change_message(msg, total_weight)
            };
            let votes = if consensus.engine_type() == EngineType::WPoA
                && consensus.current_view() > before
            {
                Some(consensus.last_view_change_votes())
            } else {
                None
            };
            (advanced, before, weights, votes)
        };
        if let Some(votes) = votes {
            let mut certificate = TimeoutCertificate { votes };
            certificate
                .votes
                .sort_by(|left, right| left.validator.as_bytes().cmp(right.validator.as_bytes()));
            if certificate.verify(
                self.config.chain_id,
                expected_block,
                before,
                highest_qc,
                &weights,
                &public_keys,
                &MultiVerifier,
            ) {
                let result = serde_json::to_vec(&certificate)
                    .map_err(|error| NodeError::Startup(error.to_string()))
                    .and_then(|bytes| {
                        self.chain_store
                            .store()
                            .put(LATEST_TIMEOUT_CERTIFICATE, &bytes)
                            .map_err(NodeError::from)
                    });
                if let Err(error) = result {
                    warn!(%error, "failed to persist diagnostic timeout observation");
                }
            }
        }
        advanced
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use shell_consensus::{PoaConfig, WPoaConfig, WPoaEngine};
    use shell_crypto::DilithiumSigner;
    use shell_mempool::MempoolConfig;
    use shell_storage::MemoryDb;

    pub(in crate::node) fn node<S: KvStore + 'static>(
        store: Arc<S>,
        keys: &[DilithiumSigner],
        weights: Vec<u64>,
    ) -> Node<S> {
        let addresses = keys
            .iter()
            .map(|key| Address::from_public_key(key.public_key(), key.sig_type().as_u8()))
            .collect::<Vec<_>>();
        let instance = Node::new(
            NodeConfig::dev(addresses[0]),
            store.clone(),
            Arc::new(ChainStore::new(store.clone())),
            Arc::new(RwLock::new(WorldState::new(store))),
            Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            })),
            Arc::new(RwLock::new(WPoaEngine::new(
                WPoaConfig::with_weights(PoaConfig::new(addresses, 1), weights),
                Arc::new(MultiVerifier),
            ))),
        );
        for key in keys {
            instance.register_authority_pubkey(
                Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                key.public_key().to_vec(),
            );
        }
        instance
    }

    fn vote(key: &dyn Signer, view: u64) -> ViewChangeMessage {
        let payload = ViewChangeMessage::signing_message(1337, 1, view, &ShellHash::ZERO);
        ViewChangeMessage::new(
            1337,
            1,
            view,
            ShellHash::ZERO,
            Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
            key.sign(&payload).unwrap().data,
        )
    }

    #[test]
    fn timeout_certificate_genuine_votes_persist_from_both_live_ingress_paths() {
        for local in [false, true] {
            let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
            let instance = node(Arc::new(MemoryDb::new()), &keys, vec![3, 1]);
            assert!(!instance
                .handle_wpoa_view_change(vote(&keys[1], 0), &MultiVerifier)
                .unwrap());
            assert!(instance.latest_timeout_certificate().unwrap().is_none());
            let signed = vote(&keys[0], 0);
            if local {
                assert!(instance.apply_observed_view_change(signed.clone()));
            } else {
                assert!(instance
                    .handle_wpoa_view_change(signed.clone(), &MultiVerifier)
                    .unwrap());
            }
            assert_eq!(instance.consensus.read().current_view(), 1);
            let certificate = instance.latest_timeout_certificate().unwrap().unwrap();
            assert_eq!(certificate.votes.len(), 2);
            let weights = instance.consensus.read().validator_weights();
            let keys = instance.known_authorities.read();
            assert!(certificate.verify(
                1337,
                1,
                0,
                ShellHash::ZERO,
                &weights,
                &keys,
                &MultiVerifier
            ));
            assert!(!certificate.verify(
                1338,
                1,
                0,
                ShellHash::ZERO,
                &weights,
                &keys,
                &MultiVerifier
            ));
            assert!(!certificate.verify(
                1337,
                2,
                0,
                ShellHash::ZERO,
                &weights,
                &keys,
                &MultiVerifier
            ));
            assert!(!certificate.verify(
                1337,
                1,
                1,
                ShellHash::ZERO,
                &weights,
                &keys,
                &MultiVerifier
            ));
            assert!(!certificate.verify(
                1337,
                1,
                0,
                ShellHash::from([1; 32]),
                &weights,
                &keys,
                &MultiVerifier
            ));
            let mut duplicate = certificate.clone();
            duplicate.votes[1] = duplicate.votes[0].clone();
            assert!(!duplicate.verify(
                1337,
                1,
                0,
                ShellHash::ZERO,
                &weights,
                &keys,
                &MultiVerifier
            ));
            let mut tampered = certificate.clone();
            tampered.votes[0].signature[0] ^= 1;
            assert!(!tampered.verify(1337, 1, 0, ShellHash::ZERO, &weights, &keys, &MultiVerifier));
            let mut wrong_key = keys.clone();
            wrong_key.insert(
                signed.validator,
                keys.values()
                    .find(|key| **key != keys[&signed.validator])
                    .unwrap()
                    .clone(),
            );
            assert!(!certificate.verify(
                1337,
                1,
                0,
                ShellHash::ZERO,
                &weights,
                &wrong_key,
                &MultiVerifier
            ));
            drop(keys);
            let before = instance.store.scan_prefix(b"").unwrap();
            assert!(!instance
                .handle_wpoa_view_change(signed, &MultiVerifier)
                .unwrap());
            assert_eq!(instance.store.scan_prefix(b"").unwrap(), before);
            assert_eq!(instance.chain_store.get_head_hash().unwrap(), None);
            assert_eq!(instance.finality.read().last_finalized_number(), 0);
        }
    }

    #[test]
    fn timeout_certificate_exact_two_thirds_and_mixed_context_are_not_certified() {
        let keys = [DilithiumSigner::generate(), DilithiumSigner::generate()];
        let instance = node(Arc::new(MemoryDb::new()), &keys, vec![2, 1]);
        // Preserve the legacy engine's ceil(2T/3) transition; do not upgrade the
        // protocol silently. This is insufficient for a strict certificate.
        assert!(instance
            .handle_wpoa_view_change(vote(&keys[0], 0), &MultiVerifier)
            .unwrap());
        assert_eq!(instance.consensus.read().current_view(), 1);
        assert!(instance.latest_timeout_certificate().unwrap().is_none());
        let mixed = node(Arc::new(MemoryDb::new()), &keys, vec![3, 1]);
        let mut different = vote(&keys[1], 0);
        different.highest_qc_hash = ShellHash::from([7; 32]);
        different.signature = keys[1].sign(&different.own_signing_message()).unwrap().data;
        assert!(!mixed
            .handle_wpoa_view_change(different, &MultiVerifier)
            .unwrap());
        assert!(mixed
            .handle_wpoa_view_change(vote(&keys[0], 0), &MultiVerifier)
            .unwrap());
        assert!(mixed.latest_timeout_certificate().unwrap().is_none());
    }

    #[test]
    fn timeout_certificate_write_failure_does_not_change_legacy_transition() {
        let keys = [DilithiumSigner::generate()];
        let store = Arc::new(super::super::tests::FailingBatchDb::new());
        let instance = node(store.clone(), &keys, vec![1]);
        let weights = instance.consensus.read().validator_weights();
        store.fail_next_put();
        assert!(instance
            .handle_wpoa_view_change(vote(&keys[0], 0), &MultiVerifier)
            .unwrap());
        assert_eq!(instance.consensus.read().current_view(), 1);
        assert!(instance.latest_timeout_certificate().unwrap().is_none());
        assert_eq!(instance.consensus.read().validator_weights(), weights);
        assert_eq!(instance.chain_store.get_head_hash().unwrap(), None);
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn timeout_certificate_survives_physical_process_reopen() {
        const DIRECTORY: &str = "SHELL_TEST_TIMEOUT_CERTIFICATE_DIRECTORY";
        if let Some(directory) = std::env::var_os(DIRECTORY) {
            let directory = std::path::PathBuf::from(directory);
            let keys = [DilithiumSigner::generate()];
            let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
            let instance = node(Arc::new(stores.state), &keys, vec![1]);
            assert!(instance
                .handle_wpoa_view_change(vote(&keys[0], 0), &MultiVerifier)
                .unwrap());
            let certificate = instance.latest_timeout_certificate().unwrap().unwrap();
            let fixture = serde_json::json!({"certificate":certificate,"weights":instance.consensus.read().validator_weights(),"public_keys":*instance.known_authorities.read()});
            std::fs::write(
                directory.join("fixture.json"),
                serde_json::to_vec(&fixture).unwrap(),
            )
            .unwrap();
            // A fresh parent process must recover from the actual WAL, not a live
            // database handle or an in-memory clone. No application state restored.
            std::process::exit(0);
        }
        let directory = std::env::temp_dir().join(format!(
            "shell-timeout-certificate-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "node::timeout_evidence::tests::timeout_certificate_survives_physical_process_reopen", "--nocapture"])
            .env(DIRECTORY, &directory).status().unwrap();
        assert!(status.success());
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("fixture.json")).unwrap())
                .unwrap();
        let expected: TimeoutCertificate =
            serde_json::from_value(fixture["certificate"].clone()).unwrap();
        let weights = serde_json::from_value(fixture["weights"].clone()).unwrap();
        let public_keys = serde_json::from_value(fixture["public_keys"].clone()).unwrap();
        let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
        let keys = [DilithiumSigner::generate()];
        let instance = node(Arc::new(stores.state), &keys, vec![1]);
        let restored = instance.latest_timeout_certificate().unwrap().unwrap();
        assert_eq!(restored, expected);
        assert!(restored.verify(
            1337,
            1,
            0,
            ShellHash::ZERO,
            &weights,
            &public_keys,
            &MultiVerifier
        ));
        assert_eq!(
            instance.consensus.read().current_view(),
            0,
            "observation must not restore a legacy consensus view or penalties"
        );
        assert_eq!(instance.chain_store.get_head_hash().unwrap(), None);
        println!("Retained timeout proof: {}", directory.display());
    }
}
