//! Independent bound SLH sender and proposer Native controls.
use super::*;
use shell_crypto::{SphincsSigner, Verifier};

pub(crate) fn prepare(out: &Path) -> Result<(), Error> {
    ensure(
        !out.exists(),
        "both-SLH output exists; refusing replacement",
    )?;
    let sender = SphincsSigner::generate();
    let proposer = SphincsSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    ensure(
        sender.public_key().len() == 64
            && proposer.public_key().len() == 64
            && Address::from_public_key(sender.public_key(), sender.sig_type().as_u8())
                != authority,
        "independent SLH actor profile differs",
    )?;
    std::fs::create_dir(out)?;
    let native = dilithium::genesis(&out.join("native/db"), &sender, &proposer, false)?;
    let receiver = dilithium::genesis(&out.join("receiver/db"), &sender, &proposer, false)?;
    let mut node = fixture::node(
        Arc::new(native.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    node.config.canonical_proof_production = false;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    let other = SphincsSigner::generate();
    let mut intake_refusals = Vec::new();
    let mut import_refusals = Vec::new();
    for nonce in 0..3 {
        let signed = dilithium::signed(&sender, nonce)?;
        ensure(
            signed.signature.data.len() == 49_856
                && MultiVerifier.verify(
                    sender.public_key(),
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                )?,
            "genuine SLH sender signature refused",
        )?;
        if nonce == 0 {
            for case in ["message", "signature-byte", "wrong-owner", "nonce"] {
                let mut bad = signed.clone();
                match case {
                    "message" => bad.tx.value = U256::from(2),
                    "signature-byte" => bad.signature.data[0] ^= 1,
                    "wrong-owner" => {
                        bad.signature = other.sign(signed.sender_signing_hash().as_bytes())?
                    }
                    _ => bad.tx.nonce = 1,
                }
                let before = digest(&native.state)?;
                let error = node
                    .handle_incoming_tx(bad.clone(), &MultiVerifier)
                    .err()
                    .ok_or("invalid SLH sender accepted")?
                    .to_string();
                ensure(
                    before == digest(&native.state)?,
                    "sender refusal wrote Native state",
                )?;
                write(&out.join(format!("sender-{case}.json")), &bad)?;
                intake_refusals.push(json!({"case":case,"error":error,"native_unchanged":true}));
            }
        }
        node.handle_incoming_tx(signed.clone(), &MultiVerifier)?;
        let block = node.produce_block(&proposer, 100)?;
        ensure(
            block.number() == nonce + 1
                && block.transactions == vec![signed.clone()]
                && block
                    .proposer_seal
                    .as_ref()
                    .is_some_and(|s| s.sig_type == proposer.sig_type() && s.data.len() == 49_856),
            "both-SLH Native block profile differs",
        )?;
        if nonce == 0 {
            for case in ["seal-byte", "selected-authority", "header-message"] {
                let mut bad = block.clone();
                match case {
                    "seal-byte" => bad.proposer_seal.as_mut().ok_or("seal absent")?.data[0] ^= 1,
                    "selected-authority" => bad.header.proposer = Address::from([0x44; 32]),
                    _ => bad.header.timestamp += 1,
                }
                let before = digest(&receiver.state)?;
                let error = peer
                    .import_block(bad, &MultiVerifier)
                    .err()
                    .ok_or("invalid SLH proposer imported")?
                    .to_string();
                ensure(
                    before == digest(&receiver.state)?,
                    "seal refusal wrote Native state",
                )?;
                import_refusals.push(json!({"case":case,"error":error,"native_unchanged":true}));
            }
        }
        peer.import_block(block.clone(), &MultiVerifier)?;
        slh_proposer::finalize(&node, &proposer, &block)?;
        slh_proposer::finalize(&peer, &proposer, &block)?;
        let control = dilithium::control(&node, &block)?;
        ensure(
            dilithium::control(&peer, &block)? == control,
            "independent both-SLH controls differ",
        )?;
        let (checkpoint, header, transaction, result) = match nonce {
            0 => (
                "provider",
                "candidate.json",
                "signed-first.json",
                "control.json",
            ),
            1 => (
                "native-later",
                "later.json",
                "later-signed.json",
                "later-control.json",
            ),
            _ => (
                "native-third",
                "advance.json",
                "advance-signed.json",
                "advance-control.json",
            ),
        };
        std::fs::create_dir(out.join(checkpoint))?;
        native.create_checkpoint(out.join(checkpoint).join("db"))?;
        write(&out.join(header), &block)?;
        write(&out.join(transaction), &signed)?;
        write(&out.join(result), &control)?;
        if nonce == 0 {
            write(
                &out.join("context.json"),
                &fixture::Context {
                    version: 1,
                    authority,
                    authority_key: proposer.public_key().to_vec(),
                    genesis_root: node
                        .chain_store
                        .get_header_by_hash(&block.header.parent_hash)?
                        .ok_or("genesis absent")?
                        .state_root,
                    block: block.hash(),
                    tip: block.hash(),
                },
            )?;
        }
    }
    write(&out.join("native-intake-refusals.json"), &intake_refusals)?;
    write(&out.join("native-refusals.json"), &import_refusals)?;
    drop(other);
    drop(sender);
    drop(proposer);
    write(
        &out.join("prepared.json"),
        &json!({
            "independent_new_native_cohort":true,
            "bound_SLH_sender":true,"SLH_proposer":true,
            "key_bytes":64,"signature_bytes":49856,
            "all_three_genuine_headers_and_quorum_controls_frozen":true,
            "independent_native_import_receipts_accounts_root_and_finality":true,
            "private_keys_memory_only_dropped":true,
            "original_old_unsigned_successor_recreated":false
        }),
    )
}
