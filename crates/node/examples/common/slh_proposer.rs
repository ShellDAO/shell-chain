//! Genuine SLH proposer controls and complete canonical seal acceptance.
use super::*;
use shell_crypto::{
    CryptoError, DilithiumVerifier, MlDsaSigner, PQSignature, SignatureType, SphincsSigner,
    Verifier,
};
use std::path::PathBuf;

fn finalize(node: &Node<RocksDbStore>, signer: &dyn Signer, block: &Block) -> Result<(), Error> {
    let authority = block.header.proposer;
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        block.number(),
        0,
        node.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), authority);
    *node.wpoa_round.lock() = Some(round);
    node.handle_wpoa_vote(
        authority,
        block.hash(),
        block.number(),
        signer.sign(block.hash().as_bytes())?,
    )
    .ok_or("SLH proposer Native quorum absent")?;
    ensure(
        node.finality.read().last_finalized_number() == block.number(),
        "SLH Native finality absent",
    )
}
pub(crate) fn prepare(out: &Path) -> Result<(), Error> {
    ensure(
        !out.exists(),
        "SLH proposer output exists; refusing replacement",
    )?;
    let sender = MlDsaSigner::generate();
    let proposer = SphincsSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
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
    let first = dilithium::signed(&sender, 0)?;
    node.handle_incoming_tx(first.clone(), &MultiVerifier)?;
    let block = node.produce_block(&proposer, 100)?;
    ensure(
        block.transactions == vec![first.clone()]
            && block.proposer_seal.as_ref().is_some_and(|s| {
                s.sig_type == shell_crypto::SignatureType::SphincsSha2256f && s.data.len() == 49856
            })
            && proposer.public_key().len() == 64,
        "Native proposer/primary sender profile differs",
    )?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    let before = digest(&receiver.state)?;
    let mut refusals = Vec::new();
    for case in ["seal-byte", "selected-authority", "header-message"] {
        let mut bad = block.clone();
        match case {
            "seal-byte" => bad.proposer_seal.as_mut().ok_or("seal absent")?.data[0] ^= 1,
            "selected-authority" => bad.header.proposer = Address::from([0x44; 32]),
            _ => bad.header.timestamp += 1,
        }
        let error = peer
            .import_block(bad, &MultiVerifier)
            .err()
            .ok_or("invalid SLH proposer imported")?
            .to_string();
        ensure(
            before == digest(&receiver.state)?,
            "SLH proposer refusal wrote Native state",
        )?;
        refusals.push(json!({"case":case,"error":error,"native_unchanged":true}));
    }
    write(&out.join("native-refusals.json"), &refusals)?;
    peer.import_block(block.clone(), &MultiVerifier)?;
    finalize(&node, &proposer, &block)?;
    finalize(&peer, &proposer, &block)?;
    let control = dilithium::control(&node, &block)?;
    ensure(
        dilithium::control(&peer, &block)? == control,
        "SLH proposer Native controls differ",
    )?;
    std::fs::create_dir(out.join("provider"))?;
    native.create_checkpoint(out.join("provider/db"))?;
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
    write(&out.join("signed-first.json"), &first)?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("control.json"), &control)?;
    let next = dilithium::signed(&sender, 1)?;
    node.handle_incoming_tx(next.clone(), &MultiVerifier)?;
    let later = node.produce_block(&proposer, 100)?;
    ensure(
        later.number() == 2
            && later.header.state_root != block.header.state_root
            && later.transactions == vec![next.clone()],
        "SLH proposer later state did not change",
    )?;
    peer.import_block(later.clone(), &MultiVerifier)?;
    finalize(&node, &proposer, &later)?;
    finalize(&peer, &proposer, &later)?;
    ensure(
        dilithium::control(&node, &later)? == dilithium::control(&peer, &later)?,
        "later Native controls differ",
    )?;
    std::fs::create_dir(out.join("native-later"))?;
    native.create_checkpoint(out.join("native-later/db"))?;
    write(&out.join("later.json"), &later)?;
    write(&out.join("later-signed.json"), &next)?;
    write(
        &out.join("later-control.json"),
        &dilithium::control(&node, &later)?,
    )?;
    drop(sender);
    drop(proposer);
    write(
        &out.join("prepared.json"),
        &json!({"independent_new_native_control":true,"primary_MLDSA_sender":true,"SLH_proposer_key_bytes":64,"SLH_seal_bytes":49856,"first_native_import_and_finality":true,"later_native_state_changed":true,"private_keys_memory_only_dropped":true}),
    )
}
struct PublicRetainedSender {
    key: Vec<u8>,
    kind: SignatureType,
    calls: AtomicUsize,
}
impl Signer for PublicRetainedSender {
    fn public_key(&self) -> &[u8] {
        &self.key
    }
    fn sig_type(&self) -> SignatureType {
        self.kind
    }
    fn sign(&self, _: &[u8]) -> Result<PQSignature, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CryptoError::SigningFailed(
            "public-only retained sender".into(),
        ))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RetainedKind {
    Primary,
    Sdk,
    Raw,
}
impl RetainedKind {
    fn signature_type(self) -> SignatureType {
        match self {
            Self::Primary => SignatureType::MlDsa65,
            Self::Sdk | Self::Raw => SignatureType::Dilithium3,
        }
    }
}
pub(crate) fn prepare_raw_bound(original: &Path, out: &Path) -> Result<(), Error> {
    prepare_retained(original, out, RetainedKind::Raw, false, 1)
}
pub(crate) fn prepare_raw_first_use(original: &Path, out: &Path) -> Result<(), Error> {
    prepare_retained(original, out, RetainedKind::Raw, true, 1)
}
pub(crate) fn reuse_raw_reference(original: &Path, out: &Path) -> Result<(), Error> {
    ensure(
        !out.exists(),
        "Reference output exists; refusing replacement",
    )?;
    let c: fixture::Context = read(&original.join("context.json"))?;
    let prepared: Value = read(&original.join("prepared.json"))?;
    let first: Block = read(&original.join("candidate.json"))?;
    let target: Block = read(&original.join("later.json"))?;
    let later: Block = read(&original.join("advance.json"))?;
    ensure(
        prepared["funded_zero_commitment_raw_sender"] == true
            && prepared["all_three_genuine_headers_and_quorum_controls_frozen"] == true
            && c.block == first.hash()
            && c.tip == first.hash()
            && first.number() == 1
            && target.number() == 2
            && later.number() == 3
            && target.header.parent_hash == first.hash()
            && later.header.parent_hash == target.hash()
            && target.header.state_root != first.header.state_root
            && later.header.state_root != target.header.state_root
            && first.transactions.len() == 1
            && target.transactions.len() == 1
            && later.transactions.len() == 1,
        "retained funded raw first/Reference/third controls required",
    )?;
    let key = first.transactions[0]
        .pubkey_mode
        .pubkey_bytes()
        .ok_or("retained raw Embedded public key absent")?;
    let sender = PublicRetainedSender {
        key: key.to_vec(),
        kind: SignatureType::Dilithium3,
        calls: AtomicUsize::new(0),
    };
    let proposer = PublicRetainedSender {
        key: c.authority_key.clone(),
        kind: SignatureType::SphincsSha2256f,
        calls: AtomicUsize::new(0),
    };
    ensure(
        key.len() == 1952
            && c.authority_key.len() == 64
            && Address::from_public_key(&c.authority_key, proposer.kind.as_u8()) == c.authority
            && [&first, &target, &later]
                .into_iter()
                .enumerate()
                .all(|(nonce, block)| {
                    let signed = &block.transactions[0];
                    signed.from == Address::from_public_key(key, sender.kind.as_u8())
                        && signed.tx.nonce == nonce as u64
                        && signed.signature.sig_type == sender.kind
                        && signed.pubkey_mode.is_embedded() == (nonce == 0)
                        && block.header.proposer == c.authority
                        && DilithiumVerifier.verify_legacy_transcript(
                            key,
                            signed.sender_signing_hash().as_bytes(),
                            &signed.signature,
                        )
                        && !DilithiumVerifier.verify_sdk_transcript(
                            key,
                            signed.sender_signing_hash().as_bytes(),
                            &signed.signature,
                        )
                }),
        "retained raw identities, signature domain or public proposer differ",
    )?;
    let source = RocksDbStore::open_all(original.join("native-third/db"), None)?;
    let before = digest(&source.state)?;
    let chain = ChainStore::new(Arc::new(source.state.clone()));
    ensure(
        chain.get_head_hash()? == Some(later.hash())
            && chain.get_pubkey(&c.authority)?.as_deref() == Some(c.authority_key.as_slice()),
        "retained ordinary third checkpoint differs",
    )?;
    for prefix in [
        b"production/".as_slice(),
        b"local/canonical-production/v1/".as_slice(),
        shell_storage::CANONICAL_PROOF_CACHE_PREFIX,
    ] {
        ensure(
            source.state.scan_prefix(prefix)?.is_empty(),
            "retained ordinary control contains mathematical job or availability rows",
        )?;
    }
    std::fs::create_dir(out)?;
    let native = dilithium::genesis(&out.join("native/db"), &sender, &proposer, true)?;
    let receiver = dilithium::genesis(&out.join("receiver/db"), &sender, &proposer, true)?;
    let node = fixture::node(
        Arc::new(native.state.clone()),
        c.authority,
        &c.authority_key,
    )?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        c.authority,
        &c.authority_key,
    )?;
    ensure(
        node.chain_store.get_chain_config()? == chain.get_chain_config()?
            && node.chain_store.get_head_hash()? == Some(first.header.parent_hash)
            && node.world_state.write().state_root()? == c.genesis_root
            && node
                .chain_store
                .get_pubkey(&first.transactions[0].from)?
                .is_none(),
        "replayed funded genesis differs from retained control",
    )?;
    for (block, name) in [
        (&first, "control.json"),
        (&target, "later-control.json"),
        (&later, "advance-control.json"),
    ] {
        ensure(
            chain.get_block_by_hash(&block.hash())?.as_ref() == Some(block),
            "retained signed header differs from canonical checkpoint",
        )?;
        let certificate = chain
            .get_commit_certificate(&block.hash())?
            .ok_or("retained genuine quorum certificate absent")?;
        let expected: Value = read(&original.join(name))?;
        for control in [&node, &peer] {
            control.import_block(block.clone(), &MultiVerifier)?;
            ensure(
                control.fast_finalize_with_certificate(block.number(), block.hash(), &certificate)
                    && control.finality.read().last_finalized_number() == block.number()
                    && control
                        .chain_store
                        .get_commit_certificate(&block.hash())?
                        .as_ref()
                        == Some(&certificate),
                "retained quorum did not authenticate replayed Native finality",
            )?;
            let mut observed = dilithium::control(control, block)?;
            if let Some(flag) = expected.get("first_use_parent_unregistered") {
                observed["first_use_parent_unregistered"] = flag.clone();
            }
            ensure(
                observed == expected,
                "replayed frozen Native control differs",
            )?;
        }
        let checkpoint = match block.number() {
            1 => "native-parent/db",
            2 => "provider/db",
            _ => "native-later/db",
        };
        let path = out.join(checkpoint);
        std::fs::create_dir_all(path.parent().ok_or("checkpoint parent absent")?)?;
        native.create_checkpoint(path)?;
    }
    let mut control: Value = read(&original.join("later-control.json"))?;
    control["first_use_parent_unregistered"] = json!(false);
    write(
        &out.join("parent-control.json"),
        &read::<Value>(&original.join("control.json"))?,
    )?;
    write(&out.join("retained-embedded.json"), &first.transactions[0])?;
    write(
        &out.join("original-signed-first.json"),
        &first.transactions[0],
    )?;
    write(&out.join("signed-first.json"), &target.transactions[0])?;
    write(&out.join("later-signed.json"), &later.transactions[0])?;
    write(&out.join("candidate.json"), &target)?;
    write(&out.join("control.json"), &control)?;
    write(&out.join("later.json"), &later)?;
    write(
        &out.join("later-control.json"),
        &read::<Value>(&original.join("advance-control.json"))?,
    )?;
    write(
        &out.join("context.json"),
        &fixture::Context {
            block: target.hash(),
            tip: target.hash(),
            ..c
        },
    )?;
    ensure(
        before == digest(&source.state)?
            && sender.calls.load(Ordering::SeqCst) == 0
            && proposer.calls.load(Ordering::SeqCst) == 0,
        "retained Native input changed or public-only actor attempted signing",
    )?;
    write(
        &out.join("prepared.json"),
        &json!({"funded_zero_commitment_raw_sender":true,"reference_target":true,"target_height":2,"parent_height":1,"later_height":3,"retained_headers_and_quorums_reused":true,"all_three_genuine_sender_signatures_unchanged":true,"new_keys":false,"new_signing":false,"new_headers_or_quorums":false,"completed_math_donor_opened":false,"original_native_unchanged":true,"genuine_parent1_and_target2_quorums_persisted":true,"independent_native_replays_match_frozen_controls":true}),
    )
}
pub(crate) fn prepare_first_use(original: &Path, out: &Path) -> Result<(), Error> {
    prepare_retained(original, out, RetainedKind::Primary, true, 1)
}
pub(crate) fn prepare_sdk_bound(original: &Path, out: &Path) -> Result<(), Error> {
    prepare_retained(original, out, RetainedKind::Sdk, false, 1)
}
pub(crate) fn prepare_sdk_first_use(original: &Path, out: &Path) -> Result<(), Error> {
    prepare_retained(original, out, RetainedKind::Sdk, true, 1)
}
pub(crate) fn prepare_sdk_reference(original: &Path, out: &Path) -> Result<(), Error> {
    prepare_retained(original, out, RetainedKind::Sdk, true, 2)
}
fn prepare_retained(
    original: &Path,
    out: &Path,
    profile: RetainedKind,
    first_use: bool,
    target_number: u64,
) -> Result<(), Error> {
    let kind = profile.signature_type();
    ensure(
        !out.exists(),
        "retained-sender proposer output exists; refusing replacement",
    )?;
    let old_context: fixture::Context = read(&original.join("context.json"))?;
    let old_block: Block = read(&original.join("candidate.json"))?;
    let (reference, next, original_db): (SignedTransaction, SignedTransaction, PathBuf) =
        if profile == RetainedKind::Primary {
            (
                read(&original.join("signed-first.json"))?,
                read(&original.join("later-signed.json"))?,
                original.join("provider/db"),
            )
        } else {
            let first: Block = read(&original.join("candidate.json"))?;
            let later: Block = read(&original.join("successor.json"))?;
            ensure(
                first.transactions.len() == 1 && later.transactions.len() == 1,
                "retained Native tag-zero transaction count differs",
            )?;
            (
                first.transactions[0].clone(),
                later.transactions[0].clone(),
                original.join("network-dilithium/provider/db"),
            )
        };
    let old = RocksDbStore::open_all(original_db, None)?;
    let old_before = digest(&old.state)?;
    let old_chain = ChainStore::new(Arc::new(old.state.clone()));
    ensure(
        old_context.block == old_block.hash()
            && old_chain.get_block_hash_by_number(old_block.number())? == Some(old_block.hash()),
        "retained sender control is not canonical",
    )?;
    let current_tip = old_chain
        .get_head_hash()?
        .ok_or("retained sender current tip absent")?;
    let old_parent = old_chain.canonical_parent_view(current_tip, old_block.header.parent_hash)?;
    let registered = old_parent.registered_key(&reference.from)?;
    let key = registered
        .clone()
        .or_else(|| {
            first_use
                .then(|| reference.pubkey_mode.pubkey_bytes().map(<[u8]>::to_vec))
                .flatten()
        })
        .ok_or("retained sender parent or first-use Embedded key absent")?;
    ensure(
        key.len() == 1952
            && reference.signature.sig_type == kind
            && next.signature.sig_type == kind
            && next.from == reference.from
            && reference.tx.nonce == 0
            && next.tx.nonce == 1
            && Address::from_public_key(&key, kind.as_u8()) == reference.from
            && if profile == RetainedKind::Primary {
                MultiVerifier.verify(
                    &key,
                    reference.sender_signing_hash().as_bytes(),
                    &reference.signature,
                )? && MultiVerifier.verify(
                    &key,
                    next.sender_signing_hash().as_bytes(),
                    &next.signature,
                )?
            } else if profile == RetainedKind::Raw {
                ensure(
                    registered.is_none() == first_use
                        && (!first_use
                            || reference.pubkey_mode.pubkey_bytes() == Some(key.as_slice()))
                        && old_parent
                            .world_state()?
                            .get_account(&reference.from)?
                            .is_some_and(|a| {
                                a.validation_code_hash.is_none()
                                    && (a.pq_pubkey_hash == ShellHash::ZERO) == first_use
                            }),
                    "raw retained parent commitment or Embedded provenance differs",
                )?;
                [&reference, &next].into_iter().all(|signed| {
                    DilithiumVerifier.verify_legacy_transcript(
                        &key,
                        signed.sender_signing_hash().as_bytes(),
                        &signed.signature,
                    ) && !DilithiumVerifier.verify_sdk_transcript(
                        &key,
                        signed.sender_signing_hash().as_bytes(),
                        &signed.signature,
                    )
                })
            } else {
                let public: Value = read(&original.join("sdk-public.json"))?;
                ensure(
                    public["package"] == "shell-sdk"
                        && public["version"] == "0.14.0-rc.3"
                        && public["signature_type"] == "Dilithium3"
                        && public["private_keys_persisted"] == false
                        && serde_json::from_value::<Vec<u8>>(public["public_key"].clone())? == key,
                    "retained public SDK provenance differs",
                )?;
                if first_use {
                    ensure(
                        public["unbound_sender"] == true
                            && registered.is_none()
                            && reference.pubkey_mode.pubkey_bytes() == Some(key.as_slice())
                            && old_parent
                                .world_state()?
                                .get_account(&reference.from)?
                                .is_some_and(|a| {
                                    a.validation_code_hash.is_none()
                                        && a.pq_pubkey_hash == ShellHash::ZERO
                                }),
                        "retained SDK first-use parent or Embedded provenance differs",
                    )?;
                }
                [&reference, &next].into_iter().all(|signed| {
                    !DilithiumVerifier.verify_legacy_transcript(
                        &key,
                        signed.sender_signing_hash().as_bytes(),
                        &signed.signature,
                    ) && DilithiumVerifier.verify_sdk_transcript(
                        &key,
                        signed.sender_signing_hash().as_bytes(),
                        &signed.signature,
                    )
                })
            },
        "retained genuine sender first/later signatures differ",
    )?;
    let advance = if target_number == 2 {
        ensure(
            profile == RetainedKind::Sdk && first_use,
            "unsupported retained target",
        )?;
        let block: Block = read(&original.join("advance.json"))?;
        ensure(
            block.transactions.len() == 1,
            "retained SDK advance transaction count differs",
        )?;
        let signed = block.transactions[0].clone();
        ensure(
            !next.pubkey_mode.is_embedded()
                && !signed.pubkey_mode.is_embedded()
                && signed.from == reference.from
                && signed.tx.nonce == 2
                && signed.signature.sig_type == kind
                && !DilithiumVerifier.verify_legacy_transcript(
                    &key,
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                )
                && DilithiumVerifier.verify_sdk_transcript(
                    &key,
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                ),
            "retained genuine SDK Reference advance differs",
        )?;
        Some(signed)
    } else {
        ensure(target_number == 1, "unsupported retained target")?;
        None
    };
    let third = if profile == RetainedKind::Raw && first_use {
        let block: Block = read(&original.join("advance.json"))?;
        ensure(
            block.transactions.len() == 1,
            "raw third transaction count differs",
        )?;
        let signed = block.transactions[0].clone();
        ensure(
            target_number == 1
                && !next.pubkey_mode.is_embedded()
                && !signed.pubkey_mode.is_embedded()
                && signed.from == reference.from
                && signed.tx.nonce == 2
                && signed.signature.sig_type == kind
                && DilithiumVerifier.verify_legacy_transcript(
                    &key,
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                )
                && !DilithiumVerifier.verify_sdk_transcript(
                    &key,
                    signed.sender_signing_hash().as_bytes(),
                    &signed.signature,
                ),
            "retained genuine raw Reference third input differs",
        )?;
        Some(signed)
    } else {
        None
    };
    let sender = PublicRetainedSender {
        key,
        kind,
        calls: AtomicUsize::new(0),
    };
    let proposer = SphincsSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    std::fs::create_dir(out)?;
    let native = dilithium::genesis(&out.join("native/db"), &sender, &proposer, first_use)?;
    let receiver = dilithium::genesis(&out.join("receiver/db"), &sender, &proposer, first_use)?;
    let mut node = fixture::node(
        Arc::new(native.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    ensure(
        node.chain_store.get_pubkey(&reference.from)?.is_none() == first_use
            && node
                .world_state
                .read()
                .get_account(&reference.from)?
                .is_some_and(|a| (a.pq_pubkey_hash == ShellHash::ZERO) == first_use),
        "retained sender parent profile differs",
    )?;
    let mut first = reference.clone();
    if first_use {
        first.pubkey_mode = shell_core::PubkeyMode::Embedded(sender.key.clone());
    }
    ensure(
        first.tx == reference.tx
            && first.signature == reference.signature
            && first.sender_signing_hash() == reference.sender_signing_hash()
            && first.uncached_hash() == reference.uncached_hash(),
        "retained signed sender identity changed",
    )?;
    ensure(
        kind != SignatureType::Dilithium3 || !first_use || first == reference,
        "original Native tag-zero first-use Embedded input changed",
    )?;
    let mut refused = Vec::new();
    for case in [
        if first_use {
            "reference-without-key"
        } else {
            "changed-signature"
        },
        "wrong-derived-address",
        "changed-message",
        "wrong-embedded-key",
    ] {
        let mut bad = first.clone();
        match case {
            "reference-without-key" => bad.pubkey_mode = shell_core::PubkeyMode::Reference,
            "changed-signature" => bad.signature.data[0] ^= 1,
            "wrong-derived-address" => bad.from = Address::from([0x12; 32]),
            "changed-message" => bad.tx.value = U256::from(2),
            _ => {
                let mut key = sender.key.clone();
                key[0] ^= 1;
                bad.pubkey_mode = shell_core::PubkeyMode::Embedded(key);
            }
        }
        let before = digest(node.store.as_ref())?;
        let error = node
            .handle_incoming_tx(bad, &MultiVerifier)
            .err()
            .ok_or("invalid retained sender input accepted")?
            .to_string();
        ensure(
            before == digest(node.store.as_ref())?
                && node.chain_store.get_pubkey(&first.from)?.is_none() == first_use,
            "refusal wrote Native state or registration",
        )?;
        refused.push(
            json!({"case":case,"error":error,"native_unchanged":true,"key_registered":!first_use}),
        );
    }
    write(&out.join("native-refusals.json"), &refused)?;
    node.handle_incoming_tx(first.clone(), &MultiVerifier)?;
    ensure(
        node.chain_store.get_pubkey(&first.from)?.is_none() == first_use,
        "mempool changed historical sender registration",
    )?;
    let mut block = node.produce_block(&proposer, 100)?;
    ensure(
        block.transactions == vec![first.clone()]
            && node.chain_store.get_pubkey(&first.from)?.as_deref() == Some(sender.public_key()),
        "first-use commit or key registration failed",
    )?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    peer.import_block(block.clone(), &MultiVerifier)?;
    finalize(&node, &proposer, &block)?;
    finalize(&peer, &proposer, &block)?;
    let mut control = dilithium::control(&node, &block)?;
    ensure(
        dilithium::control(&peer, &block)? == control,
        "independent first-use Native controls differ",
    )?;
    if target_number == 2 {
        // Keep an independently imported, finalized parent before either control advances.
        std::fs::create_dir(out.join("native-parent"))?;
        receiver.create_checkpoint(out.join("native-parent/db"))?;
        write(&out.join("retained-embedded.json"), &first)?;
        write(&out.join("parent-control.json"), &control)?;
        node.handle_incoming_tx(next.clone(), &MultiVerifier)?;
        let target = node.produce_block(&proposer, 100)?;
        ensure(
            target.number() == 2 && target.transactions == vec![next.clone()],
            "Reference target differs",
        )?;
        peer.import_block(target.clone(), &MultiVerifier)?;
        finalize(&node, &proposer, &target)?;
        finalize(&peer, &proposer, &target)?;
        control = dilithium::control(&node, &target)?;
        ensure(
            control == dilithium::control(&peer, &target)?,
            "Reference Native controls differ",
        )?;
        block = target;
        first = next.clone();
    }
    control["first_use_parent_unregistered"] = json!(first_use && target_number == 1);
    std::fs::create_dir(out.join("provider"))?;
    native.create_checkpoint(out.join("provider/db"))?;
    write(
        &out.join("context.json"),
        &fixture::Context {
            version: 1,
            authority,
            authority_key: proposer.public_key().to_vec(),
            genesis_root: node
                .chain_store
                .get_header_by_hash(
                    &node
                        .chain_store
                        .get_chain_config()?
                        .ok_or("chain config absent")?
                        .genesis_hash,
                )?
                .ok_or("genesis absent")?
                .state_root,
            block: block.hash(),
            tip: block.hash(),
        },
    )?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("signed-first.json"), &first)?;
    write(&out.join("original-signed-first.json"), &reference)?;
    write(&out.join("control.json"), &control)?;
    let later_signed = advance.as_ref().unwrap_or(&next);
    node.handle_incoming_tx(later_signed.clone(), &MultiVerifier)?;
    let later = node.produce_block(&proposer, 100)?;
    ensure(
        later.number() == target_number + 1
            && later.transactions == vec![later_signed.clone()]
            && later.header.state_root != block.header.state_root,
        "genuine later sender state did not change",
    )?;
    peer.import_block(later.clone(), &MultiVerifier)?;
    finalize(&node, &proposer, &later)?;
    finalize(&peer, &proposer, &later)?;
    ensure(
        dilithium::control(&node, &later)? == dilithium::control(&peer, &later)?,
        "later Native controls differ",
    )?;
    std::fs::create_dir(out.join("native-later"))?;
    native.create_checkpoint(out.join("native-later/db"))?;
    write(&out.join("later.json"), &later)?;
    write(&out.join("later-signed.json"), later_signed)?;
    write(
        &out.join("later-control.json"),
        &dilithium::control(&node, &later)?,
    )?;
    if let Some(signed) = &third {
        node.handle_incoming_tx(signed.clone(), &MultiVerifier)?;
        let advance = node.produce_block(&proposer, 100)?;
        ensure(
            advance.number() == 3
                && advance.transactions == vec![signed.clone()]
                && advance.header.state_root != later.header.state_root,
            "genuine raw third state differs",
        )?;
        peer.import_block(advance.clone(), &MultiVerifier)?;
        finalize(&node, &proposer, &advance)?;
        finalize(&peer, &proposer, &advance)?;
        ensure(
            dilithium::control(&node, &advance)? == dilithium::control(&peer, &advance)?,
            "raw third Native controls differ",
        )?;
        std::fs::create_dir(out.join("native-third"))?;
        native.create_checkpoint(out.join("native-third/db"))?;
        write(&out.join("advance.json"), &advance)?;
        write(&out.join("advance-signed.json"), signed)?;
        write(
            &out.join("advance-control.json"),
            &dilithium::control(&node, &advance)?,
        )?;
    }
    ensure(
        sender.calls.load(Ordering::SeqCst) == 0 && old_before == digest(&old.state)?,
        "sender signing or original Native mutation",
    )?;
    drop(proposer);
    write(
        &out.join("prepared.json"),
        &json!({"funded_zero_commitment_primary_sender":first_use && kind==SignatureType::MlDsa65,"funded_zero_commitment_sdk_sender":first_use && profile==RetainedKind::Sdk,"funded_zero_commitment_raw_sender":first_use && profile==RetainedKind::Raw,"native_bound_raw_sender":profile==RetainedKind::Raw && !first_use,"native_bound_sdk_sender":profile==RetainedKind::Sdk && !first_use,"same_retained_first_and_later_signatures":true,"first_reference_to_embedded_identity_unchanged":first_use && kind==SignatureType::MlDsa65,"sdk_embedded_input_unchanged":first_use && profile==RetainedKind::Sdk,"raw_embedded_input_unchanged":first_use && profile==RetainedKind::Raw,"retained_signed_identity_unchanged":true,"target_height":target_number,"later_height":later.number(),"third_height":third.as_ref().map(|_|3),"all_three_genuine_headers_and_quorum_controls_frozen":third.is_some(),"reference_target":target_number==2,"native_first_use_and_registration":first_use,"native_bound_sdk_first_and_later":profile==RetainedKind::Sdk && !first_use,"native_later_state_changed":true,"new_sender_signing":false,"new_proposer_keys_memory_only_dropped":true,"original_native_unchanged":true}),
    )
}
pub(crate) fn capture(out: &Path) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let db = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&db.state)?;
    let source = shell_stark_prover::canonical_producer::CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(db.state.clone())),
        c.tip,
        c.block,
    )?;
    let value: Value = serde_json::from_slice(source.identity())?;
    ensure(
        before == digest(&db.state)?,
        "proposer capture wrote Native state",
    )?;
    if !matches!(value["version"].as_u64(), Some(8..=13))
        || value["proposer_key"]
            .as_array()
            .is_none_or(|v| v.len() != 64)
    {
        if !out.join("sender-only-source.json").exists() {
            write(&out.join("sender-only-source.json"), &value)?;
        }
        return Err("SLH proposer seal absent from captured source; Native fallback cannot qualify full proposer proof".into());
    }
    let path = out.join("source.json");
    if path.exists() {
        ensure(
            read::<Value>(&path)? == value,
            "retained proposer source differs; refusing replacement",
        )
    } else {
        write(&path, &value)
    }
}

pub(crate) fn prove(out: &Path, pause: bool) -> Result<(), Error> {
    use shell_stark_prover::{
        canonical_producer::CanonicalProductionSource,
        production_store::{ProductionError, ProductionStore},
    };
    let c: fixture::Context = read(&out.join("context.json"))?;
    let native = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&native.state)?;
    let source = CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(native.state.clone())),
        c.tip,
        c.block,
    )?;
    ensure(source.has_slh_proposer(), "full SLH proposer source absent")?;
    std::fs::create_dir_all(out.join("proof"))?;
    let mut kv = RocksDbStore::open_all(out.join("proof/db"), None)?.state;
    let mut job = ProductionStore::open_slh(
        &mut kv,
        source.identity(),
        if pause {
            std::num::NonZeroUsize::new(1)
        } else {
            None
        },
    )?;
    let result = source.produce(&mut job);
    write(
        &out.join(if pause {
            "proof-paused.json"
        } else {
            "proof-progress.json"
        }),
        &job.progress(),
    )?;
    drop(job);
    if pause {
        ensure(
            matches!(result, Err(ProductionError::Paused)),
            "proposer proof did not durably pause",
        )?;
        return Ok(());
    }
    let proof = result?;
    source.verify(&proof)?;
    let payload =
        shell_stark_prover::compact_canonical::encode_payload(&proof, 256 * 1024 * 1024, true)?;
    let decoded = shell_stark_prover::compact_canonical::decode_payload(&payload)?;
    source.verify(&decoded)?;
    let path = out.join("proof.cbor");
    if path.exists() {
        ensure(
            std::fs::read(&path)? == payload,
            "immutable SLH proposer graph differs",
        )?;
    } else {
        std::fs::write(&path, &payload)?;
    }
    let manifest = shell_storage::CanonicalProofManifest {
        version: 1,
        chain_id: 10,
        genesis_hash: source.genesis_hash(),
        block_hash: c.block,
        total_bytes: payload.len() as u64,
        payload_hash: blake3_hash(&payload),
    };
    write(&out.join("manifest.json"), &manifest)?;
    ensure(
        before == digest(&native.state)?,
        "proving changed Native source",
    )?;
    write(
        &out.join("proof-complete.json"),
        &json!({"source_version":serde_json::from_slice::<Value>(source.identity())?["version"],"batch_version":proof.version,"frame_version":proof.version+1,"proposer_full17_layers":true,"source_native_unchanged":true,"new_signing":false,"proof_bytes":payload.len()}),
    )
}
pub(crate) fn verify(out: &Path, refuse: bool) -> Result<(), Error> {
    use shell_stark_prover::canonical_producer::CanonicalProductionSource;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let payload = std::fs::read(out.join("proof.cbor"))?;
    let proof = shell_stark_prover::compact_canonical::decode_payload(&payload)?;
    let original = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let original_before = digest(&original.state)?;
    let source = CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(original.state.clone())),
        c.tip,
        c.block,
    )?;
    source.verify(&proof)?;
    let expected_parent_key = ChainStore::new(Arc::new(original.state.clone()))
        .canonical_parent_view(c.tip, block.header.parent_hash)?
        .registered_key(&block.transactions[0].from)?;
    let certificate = ChainStore::new(Arc::new(original.state.clone()))
        .get_commit_certificate(&c.block)?
        .ok_or("original SLH certificate absent")?;
    ensure(
        original_before == digest(&original.state)?,
        "proposer verification changed Native input",
    )?;
    // Parent reconstruction takes its own exclusive source handle.
    drop(original);
    let directory = if refuse {
        "refused-control"
    } else {
        "verified-control"
    };
    if !out.join(directory).exists() {
        if block.number() == 1 {
            super::prepare_from(out, directory, &out.join("provider/db"))?;
        } else {
            let source = RocksDbStore::open_all(out.join("provider/db"), None)?;
            fixture::restore_parent(out, &out.join(directory).join("receiver/db"), &source.state)?;
        }
    }
    let fresh =
        Arc::new(RocksDbStore::open_all(out.join(directory).join("receiver/db"), None)?.state);
    let mut node = fixture::node(fresh.clone(), c.authority, &c.authority_key)?;
    if refuse {
        ensure(
            node.chain_store.get_head_hash()? == Some(block.header.parent_hash),
            "negative proposer receiver not at sealed parent",
        )?;
        let before = digest(fresh.as_ref())?;
        if block.number() == 2 {
            let mut native_refusals = Vec::new();
            for case in [
                "changed-signature",
                "wrong-derived-address",
                "changed-message",
                "wrong-embedded-key",
            ] {
                let mut bad = block.transactions[0].clone();
                match case {
                    "changed-signature" => bad.signature.data[0] ^= 1,
                    "wrong-derived-address" => bad.from = Address::from([0x12; 32]),
                    "changed-message" => bad.tx.value += U256::from(1),
                    _ => {
                        let mut key = expected_parent_key
                            .clone()
                            .ok_or("Reference parent key absent")?;
                        key[0] ^= 1;
                        bad.pubkey_mode = shell_core::PubkeyMode::Embedded(key);
                    }
                }
                let error = node
                    .handle_incoming_tx(bad, &MultiVerifier)
                    .err()
                    .ok_or("invalid Native Reference input accepted")?
                    .to_string();
                ensure(
                    before == digest(fresh.as_ref())?
                        && node.chain_store.get_pubkey(&block.transactions[0].from)?
                            == expected_parent_key,
                    "Native Reference refusal changed parent state or registration",
                )?;
                native_refusals.push(json!({"case":case,"error":error,"native_unchanged":true,"parent_key_unchanged":true}));
            }
            write(
                &out.join("native-reference-refusals.json"),
                &native_refusals,
            )?;
        }
        let mut results = Vec::new();
        let mut cases = vec![
            "missing-proposer",
            "wrong-profile",
            "missing-layer",
            "changed-signature",
            "foreign-header-certificate",
        ];
        if source.has_unbound_senders() {
            cases.extend(["bound-account-profile", "missing-address-certificate"]);
        }
        if matches!(proof.version, 6 | 7) {
            cases.extend([
                "sdk-as-raw-account",
                "sdk-as-primary-account",
                "sdk-as-raw-transaction",
                "sdk-as-primary-transaction",
                "sdk-as-raw-challenge",
            ]);
        }
        if matches!(proof.version, 7 | 9) {
            cases.push("wrong-address-tag");
        }
        if matches!(proof.version, 8 | 9) {
            cases.extend([
                "raw-as-sdk-account",
                "raw-as-primary-account",
                if proof.version == 9 {
                    "raw-as-bound-account"
                } else {
                    "raw-as-unbound-account"
                },
                "raw-as-sdk-transaction",
                "raw-as-primary-transaction",
                "raw-as-sdk-signature",
                "raw-as-sdk-challenge",
                "raw-as-sdk-profile",
            ]);
        }
        for case in cases {
            let mut bad = proof.clone();
            match case {
                "missing-proposer" => bad.slh_proposer = None,
                "raw-as-sdk-account" => {
                    bad.transactions[0].signature.version = if proof.version == 9 { 6 } else { 5 }
                }
                "raw-as-primary-account" => {
                    bad.transactions[0].signature.version = if proof.version == 9 { 2 } else { 1 }
                }
                "raw-as-bound-account" => bad.transactions[0].signature.version = 3,
                "raw-as-unbound-account" => bad.transactions[0].signature.version = 4,
                "raw-as-sdk-transaction" => bad.transactions[0].signature.transaction.version = 3,
                "raw-as-primary-transaction" => {
                    bad.transactions[0].signature.transaction.version = 1
                }
                "raw-as-sdk-signature" => {
                    bad.transactions[0].signature.transaction.signature.version = 1
                }
                "raw-as-sdk-challenge" => {
                    bad.transactions[0]
                        .signature
                        .transaction
                        .signature
                        .equation
                        .challenge
                        .version = 1
                }
                "raw-as-sdk-profile" => bad.version = if proof.version == 9 { 7 } else { 6 },
                "sdk-as-raw-account" => {
                    bad.transactions[0].signature.version = if proof.version == 7 { 4 } else { 3 }
                }
                "sdk-as-primary-account" => {
                    bad.transactions[0].signature.version = if proof.version == 7 { 2 } else { 1 }
                }
                "sdk-as-raw-transaction" => bad.transactions[0].signature.transaction.version = 2,
                "sdk-as-primary-transaction" => {
                    bad.transactions[0].signature.transaction.version = 1
                }
                "sdk-as-raw-challenge" => {
                    bad.transactions[0]
                        .signature
                        .transaction
                        .signature
                        .equation
                        .challenge
                        .version = 2
                }
                "wrong-profile" => bad.version = 2,
                "bound-account-profile" => {
                    bad.version = match proof.version {
                        9 => 8,
                        7 => 6,
                        _ => 4,
                    }
                }
                "missing-address-certificate" => bad.transactions[0].signature.tagged_key = None,
                "wrong-address-tag" => {
                    bad.transactions[0]
                        .signature
                        .tagged_key
                        .as_mut()
                        .ok_or("address certificate absent")?
                        .message[0] ^= 1
                }
                "missing-layer" => {
                    bad.slh_proposer.as_mut().ok_or("SLH absent")?.layers.pop();
                }
                "changed-signature" => {
                    bad.slh_proposer
                        .as_mut()
                        .ok_or("SLH absent")?
                        .fors
                        .inputs
                        .signature[0] ^= 1
                }
                _ => {
                    let valid = &bad.transactions[0].signature.transaction_id;
                    bad.slh_proposer
                        .as_mut()
                        .ok_or("SLH absent")?
                        .header
                        .canonical = valid.clone();
                }
            }
            let error = node
                .import_block_with_canonical_proof(block.header.parent_hash, block.clone(), &bad)
                .err()
                .ok_or("invalid SLH proposer graph imported")?
                .to_string();
            ensure(
                before == digest(fresh.as_ref())?,
                "proposer graph refusal wrote Native state",
            )?;
            results.push(json!({"case":case,"error":error,"native_unchanged":true}));
        }
        return write(&out.join("refused.json"), &results);
    }
    let control: Value = read(&out.join("control.json"))?;
    if node.chain_store.get_head_hash()? == Some(block.header.parent_hash) {
        let imported = node.import_block_with_canonical_proof(
            block.header.parent_hash,
            block.clone(),
            &proof,
        )?;
        ensure(
            imported.proved_proposer_signature
                && imported.proved_sender_signatures == 1
                && serde_json::to_value(&imported.receipts)? == control["receipts"]
                && accounts(fresh.clone(), &block)? == control["accounts"],
            "full SLH proposer import differs from Native",
        )?;
        ensure(
            node.fast_finalize_with_certificate(block.number(), c.block, &certificate),
            "proof-backed SLH proposer child did not finalize",
        )?;
        write(
            &out.join("proof-import.json"),
            &json!({"actual_import":imported,"finalized_height":block.number(),"native_controls_match":true}),
        )?;
    }
    let mut later: Block = read(&out.join("later.json"))?;
    if node.chain_store.get_head_hash()? == Some(c.block) {
        node.import_block(later.clone(), &MultiVerifier)?;
    }
    let ordinary_path = if proof.version == 9 && block.number() == 1 {
        let advance: Block = read(&out.join("advance.json"))?;
        ensure(
            advance.number() == 3
                && advance.header.parent_hash == later.hash()
                && advance.header.state_root != later.header.state_root,
            "retained raw third header differs",
        )?;
        if node.chain_store.get_head_hash()? == Some(later.hash()) {
            node.import_block(advance.clone(), &MultiVerifier)?;
        }
        later = advance;
        out.join("native-third/db")
    } else {
        out.join("native-later/db")
    };
    ensure(
        node.chain_store.get_head_hash()? == Some(later.hash())
            && node.world_state.write().state_root()? == later.header.state_root
            && later.header.state_root != block.header.state_root,
        "proposer history did not advance",
    )?;
    let before = digest(fresh.as_ref())?;
    let replay = node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    let ordinary = Arc::new(RocksDbStore::open_all(ordinary_path, None)?.state);
    let ordinary_before = digest(ordinary.as_ref())?;
    let ordinary_node = fixture::node(ordinary.clone(), c.authority, &c.authority_key)?;
    let second =
        ordinary_node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    ensure(
        replay.proved_proposer_signature
            && second.proved_proposer_signature
            && replay.state_root == block.header.state_root
            && second.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && serde_json::to_value(&second.receipts)? == control["receipts"]
            && before == digest(fresh.as_ref())?
            && ordinary_before == digest(ordinary.as_ref())?,
        "SLH proposer historical replay differs or writes back",
    )?;
    let parent_sender_key = node
        .chain_store
        .canonical_parent_view(later.hash(), block.header.parent_hash)?
        .registered_key(&block.transactions[0].from)?;
    let parent_sender_absent = parent_sender_key.is_none();
    ensure(
        parent_sender_key == expected_parent_key
            && node
                .chain_store
                .get_pubkey(&block.transactions[0].from)?
                .is_some(),
        "current registration replaced sealed parent authority",
    )?;
    write(
        &out.join("verified.json"),
        &json!({"full_SLH_proposer_AIR":true,"actual_proof_import":true,"changed_current_height":later.number(),"proof_target_height":block.number(),"sealed_parent_sender_key_absent":parent_sender_absent,"current_sender_key_present":true,"read_only_historical_replay":replay,"ordinary_Native_history_matches":true,"both_Native_databases_unchanged":true,"new_signing":false}),
    )
}

pub(crate) fn publish(out: &Path) -> Result<(), Error> {
    use shell_storage::{CanonicalProofUploadState, CanonicalProofUploadStore};
    let published = out.join("published");
    ensure(
        !published.exists(),
        "published output exists; refusing replacement",
    )?;
    let original = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&original.state)?;
    let manifest: CanonicalProofManifest = read(&out.join("manifest.json"))?;
    let payload = std::fs::read(out.join("proof.cbor"))?;
    ensure(
        payload.len() as u64 == manifest.total_bytes
            && blake3_hash(&payload) == manifest.payload_hash,
        "completed proposer frame/manifest mismatch",
    )?;
    std::fs::create_dir(&published)?;
    std::fs::create_dir(published.join("provider"))?;
    original.create_checkpoint(published.join("provider/db"))?;
    let db = RocksDbStore::open_all(published.join("provider/db"), None)?;
    let store = CanonicalProofUploadStore::new(Arc::new(db.state));
    let id = store.begin(manifest.clone())?.proof_id;
    for (index, chunk) in payload
        .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
        .enumerate()
    {
        store.append(&id, index as u32, chunk)?;
    }
    let status = store.status(&id)?;
    ensure(
        status.state == CanonicalProofUploadState::Ready
            && status.result.is_none()
            && store.payload(&id)? == payload
            && before == digest(&original.state)?,
        "proposer proof publication differs or changed Native input",
    )?;
    std::fs::write(published.join("proof.cbor"), &payload)?;
    write(&published.join("manifest.json"), &manifest)?;
    write(
        &published.join("published.json"),
        &json!({"availability_only":true,"outer_hash_checked":true,"native_original_unchanged":true,"payload_bytes":payload.len(),"new_math":0,"new_signing":false}),
    )
}
