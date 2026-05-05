use super::*;

const SYSTEM_EXTRA_PREFIX: &[u8] = b"shell:system-extra:v1:";
const BASE_STARK_MINT_WEI: u128 = 100_000_000_000_000_000_000;
const ESTIMATED_DILITHIUM3_SIG_BYTES: u64 = 3_309;
const ESTIMATED_REFERENCE_WITNESS_RLP_OVERHEAD_BYTES: u64 = 8;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SystemExtraEnvelope {
    stark_proofs: Vec<ProofAmendment>,
}

impl<S: KvStore + 'static> Node<S> {
    #[cfg(test)]
    pub(crate) fn encode_system_extra(stark_proofs: &[ProofAmendment]) -> Result<Bytes, NodeError> {
        if stark_proofs.is_empty() {
            return Ok(Bytes::default());
        }
        let envelope = SystemExtraEnvelope {
            stark_proofs: stark_proofs.to_vec(),
        };
        let mut bytes = SYSTEM_EXTRA_PREFIX.to_vec();
        bytes.extend(
            serde_json::to_vec(&envelope)
                .map_err(|e| NodeError::Startup(format!("encode system extra: {e}")))?,
        );
        Ok(Bytes::from(bytes))
    }

    pub(crate) fn decode_system_extra(
        extra_data: &Bytes,
    ) -> Result<Vec<ProofAmendment>, NodeError> {
        if extra_data.is_empty() {
            return Ok(vec![]);
        }
        let bytes = extra_data.as_ref();
        if !bytes.starts_with(SYSTEM_EXTRA_PREFIX) {
            return Ok(vec![]);
        }
        let payload = &bytes[SYSTEM_EXTRA_PREFIX.len()..];
        let envelope: SystemExtraEnvelope = serde_json::from_slice(payload)
            .map_err(|e| NodeError::Startup(format!("decode system extra: {e}")))?;
        Ok(envelope.stark_proofs)
    }

    pub(crate) fn stark_reward_value(
        &self,
        _reward_block_number: u64,
        amendment: &ProofAmendment,
    ) -> Result<U256, NodeError> {
        if !amendment.has_valid_embedded_compression() {
            return Err(NodeError::Startup(
                "STARK reward claim does not satisfy strict compression threshold".into(),
            ));
        }
        if amendment.layer == 1 && amendment.proof.n_sigs < MIN_L1_STARK_TXS {
            return Err(NodeError::Startup(format!(
                "STARK L1 reward claim covers {} tx entries; minimum is {MIN_L1_STARK_TXS}",
                amendment.proof.n_sigs
            )));
        }

        let covered_hashes = amendment.covered_hashes();
        let source_count = covered_hashes.len().max(1);
        let mut mint = U256::from(BASE_STARK_MINT_WEI);
        for _ in 0..amendment.layer {
            mint /= U256::from(2u8);
        }
        mint = mint.saturating_mul(U256::from(source_count));

        let mut gas_share = U256::ZERO;
        if amendment.layer == 1 {
            let mut total_effective_fees = U256::ZERO;
            for source_hash in covered_hashes {
                let Some(source_block) = self.chain_store.get_block_by_hash(&source_hash)? else {
                    return Err(NodeError::Startup(format!(
                        "STARK reward source block not found: {source_hash}"
                    )));
                };
                let receipts = self
                    .chain_store
                    .get_receipts(&source_hash)?
                    .unwrap_or_default();
                for (idx, tx) in source_block.transactions.iter().enumerate() {
                    let gas_used = receipts.get(idx).map(|r| r.gas_used).unwrap_or(0);
                    let price = effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        source_block.header.base_fee_per_gas,
                    );
                    total_effective_fees = total_effective_fees
                        .saturating_add(U256::from(gas_used).saturating_mul(U256::from(price)));
                }
            }
            gas_share = total_effective_fees / U256::from(2u8);
        }

        Ok(mint.saturating_add(gas_share))
    }

    pub(crate) fn build_stark_reward_tx(
        &self,
        block_number: u64,
        tx_index: u32,
        amendment: &ProofAmendment,
    ) -> Result<SystemTransaction, NodeError> {
        let original_size = amendment
            .original_size
            .ok_or_else(|| NodeError::Startup("STARK reward claim missing original_size".into()))?;
        let compressed_size = amendment
            .compressed_size
            .unwrap_or(amendment.size_bytes() as u64);
        Ok(SystemTransaction::stark_reward(
            shell_core::StarkRewardParams {
                chain_id: self.config.chain_id,
                block_number,
                tx_index,
                recipient: amendment.prover,
                value: self.stark_reward_value(block_number, amendment)?,
                source_hash: amendment.block_hash,
                layer: amendment.layer,
                original_size,
                compressed_size,
                proof_payload: Bytes::from(amendment.to_json().map_err(|e| {
                    NodeError::Startup(format!("serialize STARK reward proof payload: {e}"))
                })?),
            },
        ))
    }

    pub(crate) fn stark_source_original_size(
        &self,
        source_hash: &ShellHash,
        source_block: &Block,
        entry_count: usize,
    ) -> Result<Option<u64>, NodeError> {
        if entry_count == 0 {
            return Ok(Some(0));
        }
        if let Some(size) = self.witness_store.bundle_size(source_hash)? {
            return Ok(Some(size));
        }

        // If a full node pruned the raw witness before the prover caught up, the
        // exact bytes are gone. Use a conservative reference-witness estimate so
        // the ordered STARK frontier can still advance instead of wedging forever.
        Ok(Some(
            source_block.transactions.len() as u64
                * (ESTIMATED_DILITHIUM3_SIG_BYTES + ESTIMATED_REFERENCE_WITNESS_RLP_OVERHEAD_BYTES),
        ))
    }

    pub(crate) fn validate_stark_amendment_ordering(
        &self,
        amendment: &ProofAmendment,
    ) -> Result<(), NodeError> {
        self.validate_stark_amendment_ordering_with_overlay(amendment, &HashMap::new())
            .inspect_err(|_| self.metrics.stark_settlements_rejected.inc())
    }

    pub(crate) fn validate_stark_settlement_sequence(
        &self,
        amendments: &[ProofAmendment],
    ) -> Result<(), NodeError> {
        let mut overlay = HashMap::new();
        for amendment in amendments {
            self.validate_stark_amendment_ordering_with_overlay(amendment, &overlay)
                .inspect_err(|_| self.metrics.stark_settlements_rejected.inc())?;
            for source in amendment.covered_hashes() {
                overlay.insert(source, amendment.layer);
            }
        }
        Ok(())
    }

    pub(crate) fn store_stark_artifacts(
        &self,
        amendment: &ProofAmendment,
        settlement_tx_hash: Option<ShellHash>,
    ) -> Result<usize, NodeError> {
        let artifacts = amendment
            .storage_artifacts_with_settlement(settlement_tx_hash)
            .map_err(|e| {
                NodeError::Startup(format!(
                    "serialize STARK proof artifacts for block #{}: {e}",
                    amendment.block_number
                ))
            })?;
        let mut stored = 0usize;
        for (source_hash, artifact) in artifacts {
            self.amendment_store
                .put_amendment(&source_hash, &artifact)?;
            stored += 1;
        }
        Ok(stored)
    }

    fn validate_stark_amendment_ordering_with_overlay(
        &self,
        amendment: &ProofAmendment,
        overlay_layers: &HashMap<ShellHash, u32>,
    ) -> Result<(), NodeError> {
        if amendment.layer == 0 {
            return Err(NodeError::Startup(
                "STARK amendment layer must be at least 1".into(),
            ));
        }

        if !amendment.has_valid_embedded_compression() {
            return Err(NodeError::Startup(
                "STARK amendment does not satisfy strict embedded compression threshold".into(),
            ));
        }

        if amendment.layer == 1 && amendment.proof.n_sigs < MIN_L1_STARK_TXS {
            return Err(NodeError::Startup(format!(
                "STARK L1 amendment covers {} tx entries; minimum is {MIN_L1_STARK_TXS}",
                amendment.proof.n_sigs
            )));
        }

        let covered = amendment.covered_hashes();
        if covered.is_empty() {
            return Err(NodeError::Startup(
                "STARK amendment covers no canonical sources".into(),
            ));
        }
        if covered.last() != Some(&amendment.block_hash) {
            return Err(NodeError::Startup(format!(
                "STARK amendment final source hash must match proof target {}",
                amendment.block_hash
            )));
        }

        let start_block = amendment.range_start_block().ok_or_else(|| {
            NodeError::Startup(format!(
                "STARK amendment range ending at #{} is shorter than its source count {}",
                amendment.block_number,
                covered.len()
            ))
        })?;
        let expected_end = start_block
            .checked_add(covered.len() as u64)
            .and_then(|end_plus_one| end_plus_one.checked_sub(1))
            .ok_or_else(|| NodeError::Startup("STARK amendment range overflows u64".into()))?;
        if expected_end != amendment.block_number {
            return Err(NodeError::Startup(format!(
                "STARK amendment range #{}..=#{expected_end} does not end at declared block #{}",
                start_block, amendment.block_number
            )));
        }

        for (offset, source_hash) in covered.iter().enumerate() {
            let number = start_block.saturating_add(offset as u64);
            let canonical_hash = self
                .chain_store
                .get_block_hash_by_number(number)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "STARK amendment references missing canonical block #{number}"
                    ))
                })?;
            if canonical_hash != *source_hash {
                return Err(NodeError::Startup(format!(
                    "STARK amendment source #{number} is not canonical: expected {canonical_hash}, got {source_hash}"
                )));
            }

            if !self.is_stark_compression_source(source_hash, overlay_layers)? {
                return Err(NodeError::Startup(format!(
                    "STARK amendment source #{number} has no compressible witness/proof payload"
                )));
            }

            let current_layer =
                self.compression_layer_for_source(source_hash, overlay_layers, Some(amendment))?;
            if current_layer >= amendment.layer {
                return Err(NodeError::Startup(format!(
                    "STARK amendment overlaps block #{number} already compressed at layer {current_layer}"
                )));
            }
            if amendment.layer > 1 && current_layer + 1 != amendment.layer {
                return Err(NodeError::Startup(format!(
                    "STARK L{} amendment requires block #{number} to be compressed at L{}, found L{}",
                    amendment.layer,
                    amendment.layer - 1,
                    current_layer
                )));
            }
        }

        let expected_start =
            self.first_canonical_block_below_layer(amendment.layer, overlay_layers, amendment)?;
        if start_block != expected_start {
            return Err(NodeError::Startup(format!(
                "STARK L{} amendment must start at frontier #{expected_start}, got #{start_block}",
                amendment.layer
            )));
        }

        Ok(())
    }

    fn first_canonical_block_below_layer(
        &self,
        layer: u32,
        overlay_layers: &HashMap<ShellHash, u32>,
        subject: &ProofAmendment,
    ) -> Result<u64, NodeError> {
        let head = self
            .chain_store
            .get_head_block()?
            .map(|block| block.number())
            .unwrap_or(0);
        for number in 0..=head {
            let Some(hash) = self.chain_store.get_block_hash_by_number(number)? else {
                continue;
            };
            if !self.is_stark_compression_source(&hash, overlay_layers)? {
                continue;
            }
            if self.compression_layer_for_source(&hash, overlay_layers, Some(subject))? < layer {
                return Ok(number);
            }
        }
        Ok(head.saturating_add(1))
    }

    fn compression_layer_for_source(
        &self,
        source_hash: &ShellHash,
        overlay_layers: &HashMap<ShellHash, u32>,
        subject: Option<&ProofAmendment>,
    ) -> Result<u32, NodeError> {
        if let Some(layer) = overlay_layers.get(source_hash) {
            return Ok(*layer);
        }
        // Check layers 1, 2, 3 from highest to lowest for the given source_hash.
        // The in-memory set is always authoritative; the index is the durable backup.
        let settled_layer = {
            let lock = self.settled_stark_sources.lock();
            (1u32..=3)
                .rev()
                .find(|&l| lock.contains(&(l, *source_hash)))
                .unwrap_or(0)
        };
        if settled_layer > 0 {
            return Ok(settled_layer);
        }
        let _ = subject;
        Ok(0)
    }

    pub(crate) fn is_stark_compression_source(
        &self,
        source_hash: &ShellHash,
        overlay_layers: &HashMap<ShellHash, u32>,
    ) -> Result<bool, NodeError> {
        if overlay_layers.contains_key(source_hash) {
            return Ok(true);
        }
        if self.amendment_store.get_amendment(source_hash)?.is_some() {
            return Ok(true);
        }
        if self.witness_store.has_bundle(source_hash)? {
            return Ok(true);
        }
        Ok(self.chain_store.get_header_by_hash(source_hash)?.is_some())
    }
}
