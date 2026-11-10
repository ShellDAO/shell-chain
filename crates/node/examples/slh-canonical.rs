//! Reuse genuine retained signatures/certificates through actual canonical production.
#[path = "common/slh_automatic.rs"]
mod automatic;
#[allow(dead_code)]
#[path = "common/canonical_proof_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/support/certificate_io.rs"]
mod io;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_source.rs"]
mod source;
use io::{decode, read, write};
use serde::Serialize;
use serde_json::{json, Value};
use shell_crypto::Verifier;
use shell_primitives::{blake3_hash, ShellHash};
use shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof;
use shell_stark_prover::{
    blake3_hash::{Blake3HashProof, CompressionProof},
    canonical_producer::CanonicalProductionSource,
    compact_canonical::{decode_payload, encode_component, encode_payload},
    production_store::{ProductionError, ProductionStore},
    slh_fors::SlhForsProof,
    slh_xmss::SlhXmssProof,
};
use shell_storage::{ChainStore, KvStore, RocksDbStore};
use source::Error;
use std::{
    cell::RefCell,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
};
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn immutable(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if path.exists() {
        ensure(
            read(path, 256 * 1024 * 1024)? == bytes,
            "retained artifact differs; refusing replacement",
        )
    } else {
        write(path, bytes)
    }
}
fn digest(db: &impl KvStore) -> Result<ShellHash, Error> {
    Ok(blake3_hash(&serde_json::to_vec(&db.scan_all()?)?))
}
fn component<T: Serialize>(value: &T) -> Result<Option<Vec<u8>>, String> {
    encode_component(value).map(Some)
}
struct Retained {
    signature: PathBuf,
    body: PathBuf,
    fors: RefCell<Option<SlhForsProof>>,
    layer: RefCell<Option<(usize, SlhXmssProof)>>,
}
impl Retained {
    fn reuse(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let load = |p: &Path, max| read(p, max).map_err(|e| e.to_string());
        if let Some(at) = name.strip_prefix("sender-0-fors-") {
            let at = at.parse::<usize>().map_err(|e| e.to_string())?;
            if self.fors.borrow().is_none() {
                *self.fors.borrow_mut() = Some(
                    decode(&load(&self.signature.join("fors.cbor"), 128 * 1024 * 1024)?)
                        .map_err(|e| e.to_string())?,
                );
            }
            return component(
                self.fors
                    .borrow()
                    .as_ref()
                    .ok_or("retained FORS absent")?
                    .hashes
                    .get(at)
                    .ok_or("retained FORS step absent")?,
            );
        }
        if name == "sender-0-seed-prefix" || name.starts_with("sender-0-layer-") {
            let (layer, part, ordinal) = if name == "sender-0-seed-prefix" {
                (0, "prefix", 0)
            } else {
                let parts = name
                    .strip_prefix("sender-0-layer-")
                    .ok_or("invalid layer name")?
                    .split('-')
                    .collect::<Vec<_>>();
                if parts.len() != 3 {
                    return Err("invalid layer component".into());
                }
                (
                    parts[0].parse::<usize>().map_err(|e| e.to_string())?,
                    parts[1],
                    parts[2].parse::<usize>().map_err(|e| e.to_string())?,
                )
            };
            if self
                .layer
                .borrow()
                .as_ref()
                .is_none_or(|(at, _)| *at != layer)
            {
                let proof = decode(&load(
                    &self.signature.join(format!("layer-{layer:02}/xmss.cbor")),
                    64 * 1024 * 1024,
                )?)
                .map_err(|e| e.to_string())?;
                *self.layer.borrow_mut() = Some((layer, proof));
            }
            let saved = self.layer.borrow();
            let proof = &saved.as_ref().ok_or("retained layer absent")?.1;
            return match part {
                "prefix" => component(&proof.prefix),
                "chain" => component(
                    proof
                        .chains
                        .get(ordinal.checked_sub(1).ok_or("invalid chain ordinal")?)
                        .ok_or("retained chain absent")?,
                ),
                "hash" if ordinal == 0 => component(&proof.wots_public_key),
                "hash" => component(
                    proof
                        .authentication
                        .get(ordinal - 1)
                        .ok_or("retained authentication absent")?,
                ),
                _ => Err("invalid retained layer component".into()),
            };
        }
        if let Some(at) = name.strip_prefix("sender-0-body-group-") {
            let at = at.parse::<usize>().map_err(|e| e.to_string())?;
            let mut group = Vec::<CompressionProof>::new();
            for ordinal in at * 16..at * 16 + 16 {
                let path = self.body.join(format!("leaf-{ordinal:04}.cbor"));
                if !path.exists() {
                    break;
                }
                group.push(decode(&load(&path, 2 * 1024 * 1024)?).map_err(|e| e.to_string())?);
            }
            if group.is_empty() {
                return Err("retained body group absent".into());
            }
            return component(&group);
        }
        let path = match name {
            "sender-0-signing-hash" => Some(self.body.join("signing.cbor")),
            "sender-0-id" => Some(self.body.join("identity.cbor")),
            _ => name
                .strip_prefix("sender-0-body-")
                .and_then(|v| v.parse::<usize>().ok())
                .map(|at| self.body.join(format!("hash-{at:03}.cbor"))),
        };
        if let Some(path) = path {
            return component(
                &decode::<Blake3HashProof>(&load(&path, 8 * 1024 * 1024)?)
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(None)
    }
}
fn peer_import(
    native: &(impl KvStore + 'static),
    chain: &ChainStore<RocksDbStore>,
    context: &fixture::Context,
    block: &shell_core::Block,
    proof: &CanonicalSignatureBatchProof,
    out: &Path,
    control: &Value,
) -> Result<Value, Error> {
    let path = out.join("peer-genesis/db");
    let existing = path.join("CURRENT").exists();
    if !existing {
        std::fs::create_dir_all(out.join("peer-genesis"))?;
    }
    if let Ok(metadata) = path.symlink_metadata() {
        ensure(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "receiver database must be a real directory",
        )?;
    }
    let peer = Arc::new(RocksDbStore::open_all(&path, None)?.state);
    let peer_chain = ChainStore::new(peer.clone());
    let parent = chain
        .get_block_by_hash(&block.header.parent_hash)?
        .ok_or("original parent unavailable")?;
    ensure(
        parent.number() == 0,
        "reconstruction requires the original genesis parent",
    )?;
    if !existing {
        ensure(peer.scan_all()?.is_empty(), "new peer store is not empty")?;
        // A separate test receiver begins at the original authenticated genesis.
        // Only content-addressed trie nodes and independently selected parent
        // registrations are copied; no executed child, receipts or success flag.
        shell_storage::WorldState::validate_snapshot_nodes(native, parent.header.state_root)?;
        for hash in shell_storage::WorldState::collect_snapshot_node_hashes(
            native,
            parent.header.state_root,
        )? {
            let node = native
                .get(hash.as_bytes())?
                .ok_or("reachable genesis trie node absent")?;
            ensure(
                shell_primitives::keccak256(&node) == hash,
                "genesis trie node hash mismatch",
            )?;
            peer.put(hash.as_bytes(), &node)?;
        }
        ensure(
            peer.get(block.header.state_root.as_bytes())?.is_none(),
            "child state root preloaded in fresh receiver",
        )?;
        let config = chain
            .get_chain_config()?
            .ok_or("original configuration unavailable")?;
        peer_chain.commit_genesis_block(&parent, &config)?;
        let view = chain.canonical_parent_view(context.tip, parent.hash())?;
        for address in [block.transactions[0].from, context.authority] {
            peer_chain.put_pubkey(
                &address,
                &view
                    .registered_key(&address)?
                    .ok_or("original parent registry missing")?,
            )?;
        }
        peer.flush()?;
    }
    let mut node = fixture::node(peer.clone(), context.authority, &context.authority_key)?;
    let imported = if peer_chain.get_head_hash()? == Some(parent.hash()) {
        let before = digest(peer.as_ref())?;
        ensure(
            node.import_block_with_canonical_proof(ShellHash::ZERO, block.clone(), proof)
                .is_err(),
            "wrong expected parent accepted",
        )?;
        ensure(
            before == digest(peer.as_ref())?,
            "wrong-parent proof import wrote state",
        )?;
        Some(node.import_block_with_canonical_proof(parent.hash(), block.clone(), proof)?)
    } else {
        ensure(
            peer_chain.get_head_hash()? == Some(block.hash()),
            "retained receiver has unexpected head",
        )?;
        None
    };
    ensure(
        peer_chain
            .get_receipts(&block.hash())?
            .is_some_and(|v| serde_json::to_value(v).is_ok_and(|v| v == control["receipts"])),
        "receiver persisted receipts differ from original control",
    )?;
    let before = digest(peer.as_ref())?;
    let replay =
        node.replay_canonical_transactions_with_proof(block.hash(), block.hash(), proof)?;
    ensure(
        before == digest(peer.as_ref())?,
        "receiver cold replay wrote state",
    )?;
    ensure(
        serde_json::to_value(replay.state_root)? == control["state_root"],
        "receiver persisted state differs from original control",
    )?;
    // The opaque verifier can never authorize a changed signature, even though
    // the canonical transaction ID excludes its signature witness.
    let view = peer_chain.canonical_parent_view(block.hash(), parent.hash())?;
    let verified =
        shell_stark_prover::canonical_batch::verify_canonical_signature_batch(&view, block, proof)?;
    let key = view
        .registered_key(&block.transactions[0].from)?
        .ok_or("receiver sender absent")?;
    let mut altered = block.transactions[0].signature.clone();
    altered.data[0] ^= 1;
    ensure(
        !verified.verify(
            &key,
            block.transactions[0].sender_signing_hash().as_bytes(),
            &altered,
        )?,
        "proved verifier accepted a changed signature",
    )?;
    let world = shell_storage::WorldState::at_root(peer.clone(), &block.header.state_root)?;
    let mut accounts = Vec::new();
    for expected in control["accounts"]
        .as_array()
        .ok_or("original account controls absent")?
    {
        let address: shell_primitives::Address =
            serde_json::from_value(expected["address"].clone())?;
        accounts.push(json!({"address":address,"nonce":world.get_nonce(&address)?,"balance":world.get_balance(&address)?}));
    }
    ensure(
        Value::Array(accounts.clone()) == control["accounts"],
        "receiver balances/nonces differ from original control",
    )?;
    peer.flush()?;
    Ok(
        json!({"fresh_import":imported,"cold_replay":replay,"persisted_receipts_match_original":true,"read_only_cold_replay":true,"changed_signature_rejected":true,"parent_reconstruction_from_original_genesis":true,"genesis_reachable_nodes_only":true,"child_state_root_not_preloaded":true,"accounts":accounts,"network_transport":false}),
    )
}

fn main() -> Result<(), Error> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 4 && args[0].starts_with("automatic-") {
        return automatic::run(
            &args[0],
            Path::new(&args[1]),
            Path::new(&args[2]),
            Path::new(&args[3]),
        );
    }
    ensure(matches!(args.len(),5|6) || (args.len()==3 && args[0]=="capture"),"usage: slh-canonical capture native-output proof-output; pause|prove|resume|verify|refusals native-output proof-output signature-cache body-cache [prior-job-output]")?;
    let mode = &args[0];
    let native = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    ensure(
        matches!(
            mode.as_str(),
            "capture" | "pause" | "prove" | "resume" | "verify" | "refusals"
        ),
        "unsupported canonical SLH mode",
    )?;
    ensure(
        native.join("provider/db/CURRENT").is_file(),
        "retained initialized Native provider required",
    )?;
    let output_path = if out.exists() {
        ensure(
            out.is_dir() && !out.symlink_metadata()?.file_type().is_symlink(),
            "proof output must be a real directory",
        )?;
        out.canonicalize()?
    } else {
        out.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?
            .join(out.file_name().ok_or("missing output name")?)
    };
    let mut retained_paths = vec![native];
    if mode != "capture" {
        retained_paths.extend([Path::new(&args[3]), Path::new(&args[4])]);
        if args.len() == 6 {
            retained_paths.push(Path::new(&args[5]));
        }
    }
    for input in retained_paths {
        let input = input.canonicalize()?;
        ensure(
            !output_path.starts_with(&input) && !input.starts_with(&output_path),
            "proof output overlaps retained inputs",
        )?;
    }
    if !out.exists() {
        std::fs::create_dir(out)?;
    }
    for entry in std::fs::read_dir(out)? {
        let entry = entry?;
        ensure(
            !entry.file_type()?.is_symlink()
                && matches!(
                    entry.file_name().to_str(),
                    Some(
                        "source.json"
                            | "proof.cbor"
                            | "db"
                            | "peer"
                            | "peer-genesis"
                            | "manifest.json"
                            | "block.json"
                    )
                ),
            "proof output contains unowned or linked artifacts",
        )?;
    }
    let context: fixture::Context =
        serde_json::from_slice(&read(&native.join("context.json"), 1_048_576)?)?;
    let stores = RocksDbStore::open_all(native.join("provider/db"), None)?;
    let store = Arc::new(stores.state);
    let chain = ChainStore::new(store.clone());
    let before = digest(store.as_ref())?;
    let captured = CanonicalProductionSource::capture(&chain, context.tip, context.block)?;
    ensure(
        captured.has_slh_senders(),
        "explicit canonical SLH source required",
    )?;
    let original: shell_core::SignedTransaction =
        serde_json::from_slice(&read(&native.join("signed-first.json"), 1_048_576)?)?;
    ensure(
        captured.block().transactions == vec![original],
        "retained canonical source differs from original signed input",
    )?;
    let cli_artifact = out.join("manifest.json").exists() || out.join("block.json").exists();
    if cli_artifact {
        ensure(
            matches!(mode.as_str(), "verify" | "refusals"),
            "CLI artifact outputs are verification only; resume with the CLI",
        )?;
        let manifest: shell_storage::CanonicalProofManifest =
            serde_json::from_slice(&read(&out.join("manifest.json"), 65_536)?)?;
        manifest.validate()?;
        let block: shell_core::Block =
            serde_json::from_slice(&read(&out.join("block.json"), 2 * 1024 * 1024)?)?;
        let bytes = read(&out.join("proof.cbor"), 256 * 1024 * 1024)?;
        ensure(
            block == *captured.block()
                && manifest.chain_id == captured.chain_id()
                && manifest.genesis_hash == captured.genesis_hash()
                && manifest.block_hash == context.block
                && manifest.total_bytes == bytes.len() as u64
                && manifest.payload_hash == blake3_hash(&bytes),
            "CLI artifact manifest/block/source mismatch",
        )?;
    } else {
        immutable(&out.join("source.json"), captured.identity())?;
    }
    let identity = if cli_artifact {
        captured.identity().to_vec()
    } else {
        read(&out.join("source.json"), 4 * 1024 * 1024)?
    };
    let restored = CanonicalProductionSource::restore(&chain, &identity)?;
    if mode == "capture" {
        ensure(
            before == digest(store.as_ref())?,
            "source capture wrote Native state",
        )?;
        println!(
            "{}",
            json!({"captured":true,"source_format":6,"all_native_KV_unchanged":true,"native_digest":before,"new_signing":false,"full_proof_admitted":false})
        );
        return Ok(());
    }
    if mode == "prove" {
        ensure(!out.join("proof.cbor").exists(), "proof exists; use resume")?;
    }
    let (mut proof, progress) = if mode == "verify" || mode == "refusals" {
        (
            decode_payload(&read(&out.join("proof.cbor"), 256 * 1024 * 1024)?)?,
            None,
        )
    } else {
        let retained = Retained {
            signature: args[3].clone().into(),
            body: args[4].clone().into(),
            fors: RefCell::new(None),
            layer: RefCell::new(None),
        };
        let prior = if args.len() == 6 {
            let path = Path::new(&args[5]).join("db");
            ensure(
                path.join("CURRENT").is_file(),
                "initialized prior job required",
            )?;
            let mut db = RocksDbStore::open_all(path, None)?.state;
            let index: Value = serde_json::from_slice(
                &db.get(b"production/index")?
                    .ok_or("prior job index absent")?,
            )?;
            let check = if index["version"] == 4 {
                ProductionStore::open_slh(&mut db, restored.identity(), None)?
            } else {
                ProductionStore::open_compact(&mut db, restored.identity(), None)?
            };
            drop(check);
            Some(db)
        } else {
            None
        };
        let prior_before = prior.as_ref().map(digest).transpose()?;
        let reuse = |name: &str| {
            let imported = retained.reuse(name)?;
            if imported.is_some() {
                return Ok(imported);
            }
            prior
                .as_ref()
                .map(|db| {
                    db.get(format!("production/component/{name}").as_bytes())
                        .map_err(|e| e.to_string())
                })
                .transpose()
                .map(Option::flatten)
        };
        let mut job_db = RocksDbStore::open_all(out.join("db"), None)?.state;
        let mut job = ProductionStore::open_slh(
            &mut job_db,
            restored.identity(),
            if mode == "pause" {
                NonZeroUsize::new(1)
            } else {
                None
            },
        )?
        .with_reuse(&reuse);
        let produced = restored.produce(&mut job);
        ensure(
            prior.as_ref().map(digest).transpose()? == prior_before,
            "prior job changed during retained component import",
        )?;
        let progress = serde_json::to_value(job.progress())?;
        if matches!(produced, Err(ProductionError::Paused)) {
            ensure(
                mode == "pause" && before == digest(store.as_ref())?,
                "unexpected production pause or native write",
            )?;
            println!(
                "{}",
                json!({"paused":true,"progress":progress,"all_native_KV_unchanged":true})
            );
            return Ok(());
        }
        let proof = produced?;
        restored.recheck_canonical(&chain)?;
        let bytes = encode_payload(&proof, 256 * 1024 * 1024, true)?;
        immutable(&out.join("proof.cbor"), &bytes)?;
        (proof, Some(progress))
    };
    restored.verify(&proof)?;
    let node = fixture::node(store.clone(), context.authority, &context.authority_key)?;
    let replay =
        node.replay_canonical_transactions_with_proof(context.tip, context.block, &proof)?;
    let control: Value = serde_json::from_slice(&read(&native.join("control.json"), 1_048_576)?)?;
    ensure(
        replay.proved_sender_signatures == 1
            && replay.proved_proposer_signature
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && serde_json::to_value(replay.state_root)? == control["state_root"],
        "canonical AIR replay differs from original Native control",
    )?;
    ensure(
        before == digest(store.as_ref())?,
        "canonical production/replay wrote Native state",
    )?;
    if mode == "refusals" {
        let mut cases = Vec::new();
        for kind in 0..9 {
            let mut source: Value = serde_json::from_slice(restored.identity())?;
            let name = match kind {
                0..=4 => {
                    source["version"] = json!(kind + 1);
                    format!("old-source-format-{}", kind + 1)
                }
                5 => {
                    source["senders"][0]["key"][0] = json!(
                        source["senders"][0]["key"][0]
                            .as_u64()
                            .ok_or("key byte absent")?
                            ^ 1
                    );
                    "changed-parent-key".into()
                }
                6 => {
                    source["config"]["chain_id"] = json!(11);
                    "wrong-chain".into()
                }
                7 => {
                    source["proposer_key"][0] = json!(
                        source["proposer_key"][0]
                            .as_u64()
                            .ok_or("proposer byte absent")?
                            ^ 1
                    );
                    "changed-proposer-key".into()
                }
                _ => {
                    source["proposer_sdk_fips"] = json!(2);
                    "unknown-proposer-SDK-marker".into()
                }
            };
            ensure(
                CanonicalProductionSource::restore(&chain, &serde_json::to_vec(&source)?).is_err(),
                &format!("accepted {name}"),
            )?;
            cases.push(name);
        }
        for kind in 0..6 {
            let name = match kind {
                0 => {
                    proof.version = 2;
                    "old-proof-profile"
                }
                1 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .public_key_hash
                        .output[0] ^= 1;
                    "changed-key-hash"
                }
                2 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .envelope
                        .body
                        .root
                        .output[0] ^= 1;
                    "wrong-body-header-root"
                }
                3 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .manifest
                        .inputs
                        .message[0] ^= 1;
                    "wrong-signing-message"
                }
                4 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .fors
                        .inputs
                        .signature[0] ^= 1;
                    "changed-signature-witness"
                }
                _ => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .manifest
                        .layers = 16;
                    "missing-hypertree-layer"
                }
            };
            ensure(
                node.replay_canonical_transactions_with_proof(context.tip, context.block, &proof)
                    .is_err(),
                &format!("Native replay accepted {name}"),
            )?;
            match kind {
                0 => proof.version = 3,
                1 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .public_key_hash
                        .output[0] ^= 1
                }
                2 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .envelope
                        .body
                        .root
                        .output[0] ^= 1
                }
                3 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .manifest
                        .inputs
                        .message[0] ^= 1
                }
                4 => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .fors
                        .inputs
                        .signature[0] ^= 1
                }
                _ => {
                    proof
                        .slh_transactions
                        .as_mut()
                        .ok_or("sender proof absent")?[0]
                        .manifest
                        .layers = 17
                }
            }
            cases.push(name.to_string());
        }
        ensure(
            before == digest(store.as_ref())?,
            "canonical refusal changed original Native state",
        )?;
        println!(
            "{}",
            json!({"refusals":cases,"all_native_KV_unchanged":true,"retained_artifacts_not_written":true})
        );
        return Ok(());
    }
    let peer = if cli_artifact {
        Value::Null
    } else {
        peer_import(
            store.as_ref(),
            &chain,
            &context,
            restored.block(),
            &proof,
            out,
            &control,
        )?
    };
    ensure(
        before == digest(store.as_ref())?,
        "independent receiver changed original Native source",
    )?;
    println!(
        "{}",
        json!({"canonical_source_format":6,"canonical_proof_version":3,"native_replay":replay,"all_native_KV_unchanged":true,"progress":progress,"new_signing":false,"ordinary_successor2_recovered":false,"peer_import":peer})
    );
    Ok(())
}
