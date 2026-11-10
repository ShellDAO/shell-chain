//! Genuine locked Dilithium3 roles and retained native controls.
use super::*;
use shell_crypto::{DilithiumSigner, MlDsaSigner, Verifier};
use shell_storage::RocksDbStores;

fn genesis(
    path: &Path,
    sender: &dyn Signer,
    proposer: &dyn Signer,
    unbound: bool,
) -> Result<RocksDbStores, Error> {
    let stores = RocksDbStore::open_all(path, None)?;
    let db = Arc::new(stores.state.clone());
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    let mut world = WorldState::new(db.clone());
    world.set_account(
        &address,
        &Account::new_user_account(
            if unbound {
                ShellHash::ZERO
            } else {
                blake3_hash(sender.public_key())
            },
            U256::from(1_000_000),
        ),
    )?;
    let block = Block {
        header: BlockHeader {
            state_root: world.state_root()?,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: 1,
            proposer: authority,
            ..Default::default()
        },
        transactions: vec![],
        system_transactions: vec![],
        proposer_seal: None,
    };
    let chain = ChainStore::new(db);
    if !unbound {
        chain.put_pubkey(&address, sender.public_key())?;
    }
    chain.put_pubkey(&authority, proposer.public_key())?;
    let config: ChainConfig = serde_json::from_value(
        json!({"chain_id":10,"genesis_hash":block.hash(),"fee_accounting_activation_height":1,"native_address_context_height":1,"block_commitment_height":1}),
    )?;
    chain.commit_genesis_block(&block, &config)?;
    stores.state.flush()?;
    Ok(stores)
}
fn signed(sender: &dyn Signer, nonce: u64) -> Result<SignedTransaction, Error> {
    let tx = Transaction {
        chain_id: 10,
        nonce,
        to: Some(Address::from([0x11; 32])),
        value: U256::from(1),
        data: Default::default(),
        gas_limit: 21_000,
        max_fee_per_gas: 2,
        max_priority_fee_per_gas: 1,
        tx_type: 0,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    Ok(SignedTransaction::new(
        Address::from_public_key(sender.public_key(), sender.sig_type().as_u8()),
        tx.clone(),
        sender.sign(tx.signing_hash(sender.sig_type().as_u8()).as_bytes())?,
    ))
}
fn control(node: &Node<RocksDbStore>, block: &Block) -> Result<Value, Error> {
    let receipts = node
        .chain_store
        .get_receipts(&block.hash())?
        .ok_or("legacy receipts absent")?;
    ensure(
        receipts.len() == 2
            && receipts[0].gas_used == 21_000
            && receipts[0].status == 1
            && receipts[1].gas_used == 0,
        "legacy native receipt mismatch",
    )?;
    Ok(
        json!({"head":block.hash(),"height":block.number(),"state_root":block.header.state_root,"receipts":receipts,"accounts":accounts(node.store.clone(),block)?}),
    )
}
pub(crate) fn prepare(
    out: &Path,
    legacy_sender: bool,
    legacy_proposer: bool,
    unbound: bool,
) -> Result<(), Error> {
    prepare_profile(out, legacy_sender, legacy_proposer, unbound, false, false)
}
pub(crate) fn prepare_sdk(out: &Path) -> Result<(), Error> {
    prepare_profile(out, true, false, false, true, false)
}
struct SdkPublicKey(Vec<u8>);
impl Signer for SdkPublicKey {
    fn sign(&self, _: &[u8]) -> Result<shell_crypto::PQSignature, shell_crypto::CryptoError> {
        Err(shell_crypto::CryptoError::SigningFailed(
            "only the retained public SDK inputs may sign this fixture".into(),
        ))
    }
    fn public_key(&self) -> &[u8] {
        &self.0
    }
    fn sig_type(&self) -> shell_crypto::SignatureType {
        shell_crypto::SignatureType::Dilithium3
    }
}
fn sdk_rpc(
    node: &Node<RocksDbStore>,
    out: &Path,
    mode: &str,
    argument: &str,
) -> Result<Value, Error> {
    tokio::runtime::Runtime::new()?.block_on(async {
        let (events, _) = tokio::sync::broadcast::channel(16);
        let finalized = node.finality.read().last_finalized_number();
        let server = shell_rpc::start_rpc_server(
            shell_rpc::RpcConfig {
                listen_addr: "127.0.0.1:0".parse()?,
                ws_addr: None,
                rate_limit_per_sec: None,
                ..Default::default()
            },
            node.chain_store.clone(),
            node.world_state.clone(),
            node.tx_pool.clone(),
            10,
            None,
            events,
            None,
            None,
            Arc::new(parking_lot::RwLock::new(finalized)),
            node.finality.clone(),
            Arc::new(AtomicUsize::new(0)),
            None,
            None,
            Some(node.witness_store.clone()),
            None,
            Some(node.consensus.clone()),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        let output = std::process::Command::new("node")
            .args([
                "tests/e2e/sdk-dilithium-inputs.mjs",
                mode,
                &format!("{}.client", out.display()),
                &out.join("sdk-public.json").to_string_lossy(),
                argument,
                &format!("http://{}", server.http_addr),
            ])
            .output();
        let stopped = server.http_handle.stop();
        server.http_handle.stopped().await;
        stopped?;
        let output = output?;
        ensure(
            output.status.success(),
            &format!(
                "public SDK RPC failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )?;
        Ok(serde_json::from_slice::<Value>(&output.stdout)?)
    })
}
pub(crate) fn prepare_sdk_unbound(out: &Path) -> Result<(), Error> {
    prepare_profile(out, true, false, true, true, false)
}
pub(crate) fn prepare_sdk_proposer(out: &Path) -> Result<(), Error> {
    prepare_profile(out, false, true, false, false, true)
}
pub(crate) fn prepare_raw_sdk_proposer(out: &Path) -> Result<(), Error> {
    prepare_profile(out, true, true, false, false, true)
}
pub(crate) fn prepare_sdk_both(out: &Path) -> Result<(), Error> {
    prepare_profile(out, true, true, false, true, true)
}
pub(crate) fn prepare_sdk_raw_proposer(out: &Path) -> Result<(), Error> {
    prepare_profile(out, true, true, false, true, false)
}
pub(crate) fn prepare_sdk_both_unbound(out: &Path) -> Result<(), Error> {
    prepare_profile(out, true, true, true, true, true)
}
struct SdkProposerClient {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::io::BufReader<std::process::ChildStdout>,
}
impl SdkProposerClient {
    fn receive(&mut self) -> Result<Value, Error> {
        use std::io::BufRead;
        let mut line = String::new();
        ensure(
            self.output.read_line(&mut line)? > 0,
            "SDK signer process closed its public response",
        )?;
        Ok(serde_json::from_str(&line)?)
    }
    fn exchange(&mut self, request: &Value) -> Result<Value, Error> {
        use std::io::Write;
        writeln!(self.input, "{request}")?;
        self.input.flush()?;
        self.receive()
    }
}
// Only public inputs cross this channel; all SDK secret bytes stay in its
// disposable process. Native block production invokes the actual public signer.
struct SdkProposer {
    key: Vec<u8>,
    client: std::sync::Mutex<SdkProposerClient>,
}
impl SdkProposer {
    fn start(out: &Path) -> Result<Self, Error> {
        let mut child = std::process::Command::new("node")
            .args([
                "tests/e2e/sdk-dilithium-inputs.mjs",
                "proposer",
                &format!("{}.client", out.display()),
                &out.join("sdk-proposer-public.json").to_string_lossy(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or("SDK signer input absent")?;
        let output =
            std::io::BufReader::new(child.stdout.take().ok_or("SDK signer output absent")?);
        let mut client = SdkProposerClient {
            child,
            input,
            output,
        };
        let ready = client.receive()?;
        let key: Vec<u8> = serde_json::from_value(ready["public_key"].clone())?;
        ensure(
            ready["kind"] == "ready"
                && ready["version"] == "0.14.0-rc.3"
                && ready["private_keys_persisted"] == false
                && key.len() == 1952
                && ready["address"] == serde_json::to_value(Address::from_public_key(&key, 0))?,
            "SDK proposer public profile mismatch",
        )?;
        Ok(Self {
            key,
            client: std::sync::Mutex::new(client),
        })
    }
}
impl Signer for SdkProposer {
    fn sign(&self, message: &[u8]) -> Result<shell_crypto::PQSignature, shell_crypto::CryptoError> {
        let error = |e: String| shell_crypto::CryptoError::SigningFailed(e);
        let mut client = self.client.lock().map_err(|e| error(e.to_string()))?;
        let value = client
            .exchange(&json!({"message":message}))
            .map_err(|e| error(e.to_string()))?;
        if value["kind"] != "signature" || value["actual_public_signer"] != true {
            return Err(error("SDK signature response mismatch".into()));
        }
        let sig: shell_crypto::PQSignature =
            serde_json::from_value(value["signature"].clone()).map_err(|e| error(e.to_string()))?;
        if sig.sig_type != shell_crypto::SignatureType::Dilithium3 || sig.data.len() != 3309 {
            return Err(error("SDK signature shape mismatch".into()));
        }
        Ok(sig)
    }
    fn public_key(&self) -> &[u8] {
        &self.key
    }
    fn sig_type(&self) -> shell_crypto::SignatureType {
        shell_crypto::SignatureType::Dilithium3
    }
}
impl Drop for SdkProposer {
    fn drop(&mut self) {
        if let Ok(client) = self.client.get_mut() {
            let _ = client.exchange(&json!({"stop":true}));
            let _ = client.child.wait();
        }
    }
}
fn prepare_profile(
    out: &Path,
    legacy_sender: bool,
    legacy_proposer: bool,
    unbound: bool,
    sdk: bool,
    sdk_proposer: bool,
) -> Result<(), Error> {
    if out.exists() {
        ensure(
            std::fs::read_dir(out)?.all(|e| {
                e.is_ok_and(|e| {
                    e.file_name() == "commands" || sdk && e.file_name() == "sdk-public.json"
                })
            }),
            "legacy output exists; refusing key replacement",
        )?;
    } else {
        std::fs::create_dir(out)?;
    }
    ensure(
        legacy_sender || legacy_proposer,
        "a genuine Dilithium role is required",
    )?;
    let sender: Box<dyn Signer> = if sdk {
        let data: Value = read(&out.join("sdk-public.json"))?;
        ensure(
            data["version"] == "0.14.0-rc.3"
                && data["signature_type"] == "Dilithium3"
                && data["private_keys_persisted"] == false,
            "SDK input profile mismatch",
        )?;
        Box::new(SdkPublicKey(serde_json::from_value(
            data["public_key"].clone(),
        )?))
    } else if legacy_sender {
        Box::new(DilithiumSigner::generate())
    } else {
        Box::new(MlDsaSigner::generate())
    };
    let proposer: Box<dyn Signer> = if sdk_proposer {
        Box::new(SdkProposer::start(out)?)
    } else if legacy_proposer {
        Box::new(DilithiumSigner::generate())
    } else {
        Box::new(MlDsaSigner::generate())
    };
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    ensure(
        address != authority && address != Address::from([0x11; 32]),
        "legacy actor collision",
    )?;
    let stores = genesis(
        &out.join("native-original/db"),
        sender.as_ref(),
        proposer.as_ref(),
        unbound,
    )?;
    let receiver = genesis(
        &out.join("network-dilithium/receiver/db"),
        sender.as_ref(),
        proposer.as_ref(),
        unbound,
    )?;
    let receiver_genesis = ChainStore::new(Arc::new(receiver.state.clone()))
        .get_head_hash()?
        .ok_or("legacy receiver genesis absent")?;
    let genesis_rows = receiver.state.scan_all()?;
    drop(receiver);
    let mut node = fixture::node(
        Arc::new(stores.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    // This ordinary Native proposer control precedes public source collection.
    // Avoid creating a sender-only job whose immutable inputs would be replaced.
    node.config.canonical_proof_production = !legacy_proposer && !unbound && !sdk;
    if unbound {
        let mut cases = Vec::new();
        for name in [
            "reference-before-registration",
            "wrong-derived-address",
            "tampered-signature",
        ] {
            if sdk {
                let mode = match name {
                    "reference-before-registration" => "refuse-reference",
                    "wrong-derived-address" => "refuse-address",
                    _ => "refuse",
                };
                let before = digest(node.store.as_ref())?;
                let result = sdk_rpc(&node, out, mode, "0")?;
                ensure(
                    result["rejected"] == true
                        && before == digest(node.store.as_ref())?
                        && node.chain_store.get_pubkey(&address)?.is_none(),
                    "SDK unbound refusal wrote state or registered key",
                )?;
                cases.push(json!({"case":name,"result":result,"all_kv_unchanged":true,"key_registered":false}));
                continue;
            }
            let mut rejected = signed(sender.as_ref(), 0)?;
            if name != "reference-before-registration" {
                rejected.pubkey_mode =
                    shell_core::PubkeyMode::Embedded(sender.public_key().to_vec());
            }
            if name == "wrong-derived-address" {
                rejected.from = Address::from([0x11; 32]);
            }
            if name == "tampered-signature" {
                rejected.tx.value = U256::from(2);
            }
            let before = digest(node.store.as_ref())?;
            let error = node
                .handle_incoming_tx(rejected, &MultiVerifier)
                .err()
                .ok_or("invalid unbound legacy transaction accepted")?
                .to_string();
            ensure(
                before == digest(node.store.as_ref())?
                    && node.chain_store.get_pubkey(&address)?.is_none(),
                "unbound refusal wrote state or registered key",
            )?;
            cases.push(
                json!({"case":name,"error":error,"all_kv_unchanged":true,"key_registered":false}),
            );
        }
        write(
            &out.join("first-use-native-refusals.json"),
            &json!({"cases":cases,"real_signatures":true,"private_keys_persisted":false}),
        )?;
    }
    if sdk {
        let submitted = sdk_rpc(&node, out, "send", "0")?;
        write(&out.join("sdk-rpc-submitted-1.json"), &submitted)?;
    } else {
        let mut tx = signed(sender.as_ref(), 0)?;
        if unbound {
            tx.pubkey_mode = shell_core::PubkeyMode::Embedded(sender.public_key().to_vec());
        }
        ensure(
            MultiVerifier.verify(
                sender.public_key(),
                tx.sender_signing_hash().as_bytes(),
                &tx.signature,
            )?,
            "genuine legacy crypto refused",
        )?;
        node.handle_incoming_tx(tx, &MultiVerifier)?;
        if unbound {
            ensure(
                node.chain_store.get_pubkey(&address)?.is_none(),
                "mempool prematurely registered key",
            )?;
        }
    }
    let block = node.produce_block(proposer.as_ref(), 100)?;
    if sdk {
        let submitted: Value = read(&out.join("sdk-rpc-submitted-1.json"))?;
        ensure(
            block.transactions.len() == 1
                && serde_json::to_value(block.transactions[0].hash())? == submitted["hash"]
                && block.transactions[0].signature.sig_type
                    == shell_crypto::SignatureType::Dilithium3,
            "SDK RPC input did not execute",
        )?;
        write(
            &out.join("sdk-rpc-receipt-1.json"),
            &sdk_rpc(
                &node,
                out,
                "receipt",
                submitted["hash"].as_str().ok_or("SDK hash absent")?,
            )?,
        )?;
    }
    if unbound {
        let parent = node
            .chain_store
            .canonical_parent_view(block.hash(), block.header.parent_hash)?;
        ensure(
            parent.registered_key(&address)?.is_none()
                && parent
                    .world_state()?
                    .get_account(&address)?
                    .is_some_and(|a| a.pq_pubkey_hash == ShellHash::ZERO)
                && node.chain_store.get_pubkey(&address)?.as_deref() == Some(sender.public_key()),
            "Native unbound registration differs",
        )?;
        write(
            &out.join("first-use-registration.json"),
            &json!({"parent_key_absent":true,"parent_account_commitment_zero":true,"native_key_registered":true,"sender":address,"public_key":sender.public_key()}),
        )?;
    }
    let vote = proposer.sign(block.hash().as_bytes())?;
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        block.number(),
        0,
        node.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), authority);
    *node.wpoa_round.lock() = Some(round);
    node.handle_wpoa_vote(authority, block.hash(), block.number(), vote.clone())
        .ok_or("legacy quorum absent")?;
    ensure(
        node.finality.read().last_finalized_number() == 1,
        "legacy native finality absent",
    )?;
    let context = fixture::Context {
        version: 1,
        authority,
        authority_key: proposer.public_key().to_vec(),
        genesis_root: node
            .chain_store
            .get_header_by_hash(&receiver_genesis)?
            .ok_or("legacy genesis header absent")?
            .state_root,
        block: block.hash(),
        tip: block.hash(),
    };
    ensure(
        block.header.parent_hash == receiver_genesis,
        "legacy independent genesis differs",
    )?;
    write(&out.join("context.json"), &context)?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("quorum-vote.json"), &vote)?;
    write(&out.join("control.json"), &control(&node, &block)?)?;
    let failed = Arc::new(shell_storage::MemoryDb::new());
    for (k, v) in genesis_rows {
        failed.put(&k, &v)?;
    }
    let failed_node = fixture::node(failed.clone(), authority, proposer.public_key())?;
    let mut bad = block.clone();
    bad.header.state_root = ShellHash::ZERO;
    bad.proposer_seal = Some(proposer.sign(bad.hash().as_bytes())?);
    let before = failed.scan_all()?;
    let error = failed_node
        .import_block(bad, &MultiVerifier)
        .err()
        .ok_or("legacy wrong root accepted")?
        .to_string();
    ensure(
        error.contains("state root mismatch")
            && error.contains(&format!("{:?}", block.header.state_root))
            && before == failed.scan_all()?
            && (!unbound || failed_node.chain_store.get_pubkey(&address)?.is_none()),
        "legacy wrong-root refusal leaked writes or preceded execution",
    )?;
    write(
        &out.join("native-rollback.json"),
        &json!({"native_crypto_control_not_proof_admission":true,"all_kv_unchanged":true,"unbound_registration_rolled_back":unbound,"error":error}),
    )?;
    stores.state.flush()?;
    std::fs::create_dir(out.join("network-dilithium/provider"))?;
    stores.create_checkpoint(out.join("network-dilithium/provider/db"))?;
    node.config.canonical_proof_production = false;
    if sdk {
        write(
            &out.join("sdk-rpc-submitted-2.json"),
            &sdk_rpc(&node, out, "send", "1")?,
        )?;
    } else {
        node.handle_incoming_tx(signed(sender.as_ref(), 1)?, &MultiVerifier)?;
    }
    let successor = node.produce_block(proposer.as_ref(), 100)?;
    if sdk {
        let submitted: Value = read(&out.join("sdk-rpc-submitted-2.json"))?;
        ensure(
            successor.transactions.len() == 1
                && serde_json::to_value(successor.transactions[0].hash())? == submitted["hash"],
            "retained SDK successor did not execute",
        )?;
        write(
            &out.join("sdk-rpc-receipt-2.json"),
            &sdk_rpc(
                &node,
                out,
                "receipt",
                submitted["hash"]
                    .as_str()
                    .ok_or("SDK successor hash absent")?,
            )?,
        )?;
    }
    write(&out.join("successor.json"), &successor)?;
    write(
        &out.join("later-control.json"),
        &control(&node, &successor)?,
    )?;
    if unbound {
        if sdk {
            write(
                &out.join("sdk-rpc-submitted-3.json"),
                &sdk_rpc(&node, out, "send", "2")?,
            )?;
        } else {
            node.handle_incoming_tx(signed(sender.as_ref(), 2)?, &MultiVerifier)?;
        }
        let third = node.produce_block(proposer.as_ref(), 100)?;
        if sdk {
            let submitted: Value = read(&out.join("sdk-rpc-submitted-3.json"))?;
            ensure(
                third.transactions.len() == 1
                    && serde_json::to_value(third.transactions[0].hash())? == submitted["hash"],
                "retained SDK advance did not execute",
            )?;
            write(
                &out.join("sdk-rpc-receipt-3.json"),
                &sdk_rpc(
                    &node,
                    out,
                    "receipt",
                    submitted["hash"]
                        .as_str()
                        .ok_or("SDK advance hash absent")?,
                )?,
            )?;
        }
        write(&out.join("advance.json"), &third)?;
        write(&out.join("advance-control.json"), &control(&node, &third)?)?;
    }
    write(
        &out.join("actors.json"),
        &json!({"sender":address,"sender_key":sender.public_key(),"sender_algorithm":sender.sig_type(),"proposer_algorithm":proposer.sig_type(),"private_keys_persisted":false,"unbound_sender":unbound,"native_sdk_fips_sender":sdk,"native_sdk_fips_proposer":sdk_proposer,"profile":if !sdk && sdk_proposer && legacy_sender {"native-raw-sender-sdk-proposer"} else if sdk && legacy_proposer && !sdk_proposer {"native-sdk-sender-raw-proposer"} else if sdk && sdk_proposer && unbound {"native-sdk-fips-both-unbound"} else if sdk && sdk_proposer {"native-sdk-fips-both"} else if sdk_proposer {"native-sdk-fips-proposer"} else if sdk && unbound {"native-sdk-fips-unbound"} else if sdk {"native-sdk-fips-bound"} else if unbound {"legacy-unbound"} else if legacy_sender && legacy_proposer {"legacy-both"} else if legacy_proposer {"legacy-proposer"} else {"legacy-sender"},"initial_automatic_capture_disabled_native_control":legacy_proposer || unbound || sdk,"native_transcript":"locked pqcrypto-dilithium0.5.0 raw roles; FIPS only where explicitly selected"}),
    )?;
    node.store.flush()?;
    drop(node);
    drop(stores);
    drop(sender);
    drop(proposer);
    probe(out, false)
}
pub(crate) fn sdk_intake_refusal(out: &Path) -> Result<(), Error> {
    let context: fixture::Context = read(&out.join("context.json"))?;
    let stores = RocksDbStore::open_all(out.join("network-dilithium/receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    ensure(
        node.chain_store
            .get_head_block()?
            .ok_or("SDK genesis absent")?
            .number()
            == 0,
        "SDK intake control requires original genesis",
    )?;
    let before = digest(node.store.as_ref())?;
    let result = sdk_rpc(&node, out, "refuse", "0")?;
    ensure(
        result["rejected"] == true && before == digest(node.store.as_ref())?,
        "SDK tamper refusal wrote state",
    )?;
    write(
        &out.join("sdk-native-tamper-refused.json"),
        &json!({"actual_public_provider_rpc":true,"all_kv_unchanged":true,"original_signed_input_unchanged":true,"result":result,"native_crypto_control_not_proof_admission":true}),
    )?;
    Ok(())
}
pub(crate) fn probe(out: &Path, recovered: bool) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network-dilithium/provider/db"), None)?;
    let chain = ChainStore::new(Arc::new(stores.state.clone()));
    let context: fixture::Context = read(&out.join("context.json"))?;
    let before = digest(&stores.state)?;
    let result = shell_stark_prover::canonical_producer::CanonicalProductionSource::capture(
        &chain,
        context.tip,
        context.block,
    );
    ensure(
        before == digest(&stores.state)?,
        "legacy source capture wrote native data",
    )?;
    let path = out.join(if recovered {
        "capture-recovered.json"
    } else {
        "capture-original.json"
    });
    ensure(!path.exists(), "retained legacy capture receipt exists")?;
    match result {
        Ok(source) => {
            let input: Value = serde_json::from_slice(source.identity())?;
            let actors: Value = read(&out.join("actors.json"))?;
            if actors["native_sdk_fips_proposer"] == true
                && !recovered
                && input["version"] == 1
                && input["proposer_key"].is_null()
            {
                std::fs::write(
                    out.join("sender-only-original-source.json"),
                    source.identity(),
                )?;
            }
            if actors["native_sdk_fips_proposer"] == true
                && recovered
                && out.join("sender-only-original-source.json").exists()
            {
                let old = std::fs::read(out.join("sender-only-original-source.json"))?;
                let restored =
                    shell_stark_prover::canonical_producer::CanonicalProductionSource::restore(
                        &chain, &old,
                    )?;
                let old_input: Value = serde_json::from_slice(restored.identity())?;
                ensure(
                    restored.identity() == old
                        && old_input["version"] == 1
                        && old_input["proposer_key"].is_null()
                        && old_input["proposer_sdk_fips"].is_null()
                        && before == digest(&stores.state)?,
                    "original sender-only source upgraded or wrote state",
                )?;
                write(
                    &out.join("sender-only-source-restored.json"),
                    &json!({"identity_hash":blake3_hash(&old),"exact_original_bytes":true,"still_sender_only":true,"all_kv_unchanged":true}),
                )?;
            }
            let expected_version = if actors["native_sdk_fips_proposer"] == true {
                5
            } else if actors["native_sdk_fips_sender"] == true {
                if actors["unbound_sender"] == true {
                    4
                } else {
                    3
                }
            } else {
                2
            };
            let full = input["version"] == expected_version && input["proposer_key"].is_array();
            write(
                &path,
                &json!({"supported":full,"captured_version":input["version"],"proposer_captured":input["proposer_key"].is_array(),"identity_hash":blake3_hash(source.identity()),"all_kv_unchanged":true,"native_digest":before}),
            )?;
            ensure(full, "genuine proposer missing from full production source")
        }
        Err(error) => {
            write(
                &path,
                &json!({"supported":false,"error":error,"all_kv_unchanged":true,"native_digest":before}),
            )?;
            Err(error.into())
        }
    }
}

fn legacy_roles(out: &Path) -> Result<(bool, bool), Error> {
    let actors: Value = read(&out.join("actors.json"))?;
    match (
        actors["sender_algorithm"].as_str(),
        actors["proposer_algorithm"].as_str(),
    ) {
        (Some("Dilithium3"), Some("MlDsa65")) => Ok((true, false)),
        (Some("MlDsa65"), Some("Dilithium3")) => Ok((false, true)),
        (Some("Dilithium3"), Some("Dilithium3")) => Ok((true, true)),
        _ => Err("unsupported retained Dilithium role profile".into()),
    }
}
pub(crate) async fn run(out: &Path, pause: bool, reference: bool) -> Result<(), Error> {
    let network = out.join("network-dilithium");
    let complete_name = if reference {
        "reference-complete.json"
    } else {
        "complete.json"
    };
    let paused_name = if reference {
        "reference-paused.json"
    } else {
        "paused.json"
    };
    let proof_name = if reference {
        "reference-proof.bin"
    } else {
        "proof.bin"
    };
    let manifest_name = if reference {
        "reference-manifest.json"
    } else {
        "manifest.json"
    };
    ensure(
        !network.join(complete_name).exists(),
        "Dilithium proof complete; use verify",
    )?;
    let mut context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join(if reference {
        "successor.json"
    } else {
        "candidate.json"
    }))?;
    let (legacy_sender, legacy_proposer) = legacy_roles(out)?;
    let actors: Value = read(&out.join("actors.json"))?;
    let unbound = actors["unbound_sender"] == true;
    let sdk = actors["native_sdk_fips_sender"] == true;
    let sdk_proposer = actors["native_sdk_fips_proposer"] == true;
    let sender_key: Vec<u8> = serde_json::from_value(actors["sender_key"].clone())?;
    let expected: Value = read(&out.join(if reference {
        "later-control.json"
    } else {
        "control.json"
    }))?;
    if reference {
        ensure(
            unbound && network.join("complete.json").exists(),
            "unbound Embedded proof must complete first",
        )?;
        let stores = RocksDbStore::open_all(network.join("provider/db"), None)?;
        let node = fixture::node(
            Arc::new(stores.state),
            context.authority,
            &context.authority_key,
        )?;
        if node
            .chain_store
            .get_head_block()?
            .ok_or("reference source head absent")?
            .number()
            == 1
        {
            node.import_block(block.clone(), &MultiVerifier)?;
            let mut round = shell_consensus::wpoa_state::WPoaRound::new(
                2,
                0,
                node.consensus.read().validator_weights(),
            );
            let _ = round.on_block_proposed(block.hash(), context.authority);
            *node.wpoa_round.lock() = Some(round);
            node.handle_wpoa_vote(
                context.authority,
                block.hash(),
                2,
                block.proposer_seal.clone().ok_or("reference seal absent")?,
            )
            .ok_or("reference genuine same-hash quorum absent")?;
        }
        ensure(
            node.chain_store.get_head_hash()? == Some(block.hash())
                && node.finality.read().last_finalized_number() == 2,
            "original signed Reference source not finalized",
        )?;
        node.store.flush()?;
        context.block = block.hash();
        context.tip = block.hash();
    }
    let faults = Arc::new(Faults::default());
    let provider = Live::start(
        &network.join("provider/db"),
        &context,
        vec![],
        false,
        true,
        Some(faults.clone()),
    )
    .await?;
    let receiver = match Live::start(
        &network.join("receiver/db"),
        &context,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await
    {
        Ok(receiver) => receiver,
        Err(error) => {
            provider.stop().await?;
            return Err(error);
        }
    };
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12 * 60 * 60);
        let mut last_progress = tokio::time::Instant::now();
        let mut previous = None;
        loop {
            ensure(!provider.task.is_finished() && !receiver.task.is_finished(), "Dilithium live node exited")?;
            let production = provider.call("admin_canonicalProofProduction", json!([block.hash()])).await?;
            let admission = receiver.call("admin_canonicalProofAdmission", json!([block.hash()])).await?;
            ensure(production["status"]["state"] != "failed", &format!("Dilithium production failed: {production}"))?;
            ensure(admission["status"]["state"] != "failed", &format!("Dilithium admission failed: {admission}"))?;
            let count = checkpoint_components(provider.node.store.as_ref(), block.hash())?;
            let height = receiver.node.chain_store.get_head_block()?.ok_or("Dilithium receiver head absent")?.number();
            let finalized = receiver.node.finality.read().last_finalized_number();
            let progress = json!({"components":count,"production":production["status"],"admission":admission,"height":height,"finalized":finalized});
            if previous.as_ref() != Some(&progress) {
                previous = Some(progress.clone()); last_progress = tokio::time::Instant::now();
                let tmp = network.join(if reference { "reference-progress.tmp" } else { "progress.tmp" });
                std::fs::write(&tmp, serde_json::to_vec(&progress)?)?;
                std::fs::rename(tmp, network.join(if reference { "reference-progress.json" } else { "progress.json" }))?;
                println!("Dilithium components={count}; height={height}; finalized={finalized}");
            }
            if pause && count > 0 { ensure(height == block.number()-1 && finalized == block.number()-1, "partial Dilithium proof changed native head")?; break; }
            if height == block.number() && finalized == block.number() {
                ensure(production["status"]["state"] == "complete" && admission["nativeCanonical"] == true && admission["status"]["state"] == "complete", "Dilithium import did not consume its proof")?;
                ensure(receiver.node.chain_store.get_receipts(&block.hash())?.map(serde_json::to_value).transpose()? == Some(expected["receipts"].clone()) && accounts(receiver.node.store.clone(), &block)? == expected["accounts"], "Dilithium peer native outputs differ")?;
                let manifest: CanonicalProofManifest = serde_json::from_value(admission["status"]["manifest"].clone())?;
                let cache = shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                ensure(cache.status(&manifest.id())?.result.as_ref().is_some_and(|v|v["proved_sender_signatures"] == 1 && v["proved_proposer_signature"] == true), "Dilithium import omitted full AIR")?;
                let bytes = cache.payload(&manifest.id())?;
                let proof = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
                let sender = &proof.transactions.first().ok_or("Dilithium sender proof absent")?.signature;
                let equation = &sender.transaction.signature.equation;
                let (bound, envelope, inner, seed) = if sdk && unbound {(6,3,1,48)} else if sdk {(5,3,1,48)} else if unbound {(4,2,2,32)} else if legacy_sender {(3,2,2,32)} else {(1,1,1,48)};
                let prop = proof.proposer.as_ref().ok_or("full proposer proof absent")?;
                let (prop_version, prop_seed) = if sdk_proposer {(3,48)} else if legacy_proposer {(2,32)} else {(1,48)};
                let prop_inner=if sdk_proposer {1} else {prop_version};
                ensure(proof.version == 2 && proof.transactions.len() == 1 && sender.version == bound && sender.transaction.version == envelope && sender.transaction.signature.version == inner && equation.challenge.version == inner && equation.challenge.seed == equation.signature.decoded.challenge[..seed] && prop.version == prop_version && prop.signature.version == prop_inner && prop.signature.equation.challenge.version == prop_inner && prop.signature.equation.challenge.seed == prop.signature.equation.signature.decoded.challenge[..prop_seed], "Dilithium/FIPS full proof profile mismatch")?;
                if unbound {
                    let address = sender.tagged_key.as_ref().ok_or("unbound address AIR absent")?;
                    ensure(address.message.first()==Some(&0) && address.message[1..]==sender_key && address.output == *block.transactions[0].from.as_bytes()
                        && receiver.node.chain_store.get_pubkey(&block.transactions[0].from)?.as_deref()==Some(sender_key.as_slice())
                        && receiver.node.world_state.read().get_account(&block.transactions[0].from)?.is_some_and(|a|a.pq_pubkey_hash==ShellHash::ZERO), "unbound address/registration/zero commitment differs")?;
                }
                if reference {
                    let first: Block = read(&out.join("candidate.json"))?;
                    let first_status=receiver.call("admin_canonicalProofAdmission",json!([first.hash()])).await?;
                    ensure(first_status["nativeCanonical"]==true && first_status["status"]["state"]=="complete", "first target lost proof admission")?;
                }
                let path = network.join(proof_name);
                if path.exists() { ensure(std::fs::read(&path)? == bytes, "retained Dilithium proof changed")?; } else { std::fs::write(path, &bytes)?; }
                write(&network.join(manifest_name), &manifest)?;
                write(&network.join(complete_name), &json!({"production":production["status"],"admission":admission,"height":height,"finalized":finalized,"unbound_sender":unbound,"both_original_targets_proof_admitted":reference,"genuine_unbound_dilithium_full_proof_admitted":unbound && !sdk,"genuine_unbound_sdk_tag0_fips_full_proof_admitted":sdk && unbound,"native_sdk_fips_sender":sdk,"native_sdk_fips_proposer":sdk_proposer,"genuine_sdk_tag0_fips_proposer_full_proof_admitted":sdk_proposer,"genuine_sdk_tag0_fips_full_proof_admitted":sdk && !unbound && !legacy_proposer,"genuine_sdk_sender_raw_proposer_full_proof_admitted":sdk && legacy_proposer && !sdk_proposer,"genuine_raw_sender_sdk_proposer_full_proof_admitted":legacy_sender && sdk_proposer && !sdk,"genuine_dilithium_sender_primary_proposer_full_proof_admitted":legacy_sender && !legacy_proposer && !unbound && !sdk,"genuine_dilithium_proposer_primary_sender_full_proof_admitted":legacy_proposer && !legacy_sender && !sdk_proposer,"genuine_dilithium_both_roles_full_proof_admitted":legacy_sender && legacy_proposer && !sdk && !sdk_proposer,"genuine_sdk_both_roles_full_proof_admitted":sdk && sdk_proposer,"native_outputs_match":true,"served_chunks":faults.chunks.load(Ordering::SeqCst)}))?;
                break;
            }
            ensure(tokio::time::Instant::now() < deadline && last_progress.elapsed() < Duration::from_secs(1800), "Dilithium progress bound exceeded")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok::<_, Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    if pause {
        write(
            &network.join(paused_name),
            &json!({"gracefully_stopped":true}),
        )?;
    }
    Ok(())
}

pub(crate) fn snapshot(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network-dilithium/provider/db"), None)?;
    let rows = stores
        .state
        .scan_prefix(b"local/canonical-production/v1/")?;
    let bytes: usize = rows
        .iter()
        .filter(|(k, _)| k != b"local/canonical-production/v1/bytes")
        .map(|(k, v)| k.len() + v.len())
        .sum();
    let recorded = stores
        .state
        .get(b"local/canonical-production/v1/bytes")?
        .unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
    ensure(
        recorded.as_slice() == (bytes as u64).to_be_bytes() && bytes <= 256 * 1024 * 1024,
        "Dilithium checkpoint accounting mismatch",
    )?;
    println!(
        "{}",
        json!({"native_digest":canonical_digest(&stores.state)?,"physical_checkpoint_bytes":bytes,"rows":rows.into_iter().map(|(k,v)|json!({"key":hex::encode(k),"bytes":v.len(),"hash":blake3_hash(&v)})).collect::<Vec<_>>()})
    );
    Ok(())
}

pub(crate) fn verify(out: &Path, advance: bool) -> Result<(), Error> {
    let network = out.join("network-dilithium");
    ensure(
        network.join("complete.json").exists(),
        "Dilithium proof admission incomplete",
    )?;
    let actors: Value = read(&out.join("actors.json"))?;
    let unbound = actors["unbound_sender"] == true;
    if unbound {
        ensure(
            network.join("reference-complete.json").exists(),
            "Reference full proof incomplete",
        )?;
    }
    let context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let second: Block = read(&out.join("successor.json"))?;
    let later: Block = if unbound {
        read(&out.join("advance.json"))?
    } else {
        second.clone()
    };
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    if advance
        && node
            .chain_store
            .get_head_block()?
            .ok_or("Dilithium head absent")?
            .number()
            == later.number() - 1
    {
        node.import_block(later.clone(), &MultiVerifier)?;
    }
    let current = node
        .chain_store
        .get_head_block()?
        .ok_or("Dilithium head absent")?;
    let changed = current.number() == later.number();
    ensure(
        current.hash()
            == if changed {
                later.hash()
            } else if unbound {
                second.hash()
            } else {
                block.hash()
            },
        "Dilithium current native head differs",
    )?;
    let control: Value = read(&out.join(if changed && unbound {
        "advance-control.json"
    } else if changed || unbound {
        "later-control.json"
    } else {
        "control.json"
    }))?;
    ensure(
        accounts(node.store.clone(), &current)? == control["accounts"]
            && node
                .chain_store
                .get_receipts(&current.hash())?
                .map(serde_json::to_value)
                .transpose()?
                == Some(control["receipts"].clone()),
        "Dilithium current state differs",
    )?;
    let before = digest(node.store.as_ref())?;
    let mut targets = vec![(block, "proof.bin", "control.json")];
    if unbound {
        targets.push((second, "reference-proof.bin", "later-control.json"));
    }
    let mut replays = Vec::new();
    for (block, path, control) in targets {
        let proof = shell_stark_prover::compact_canonical::decode_payload(&std::fs::read(
            network.join(path),
        )?)?;
        let replay =
            node.replay_canonical_transactions_with_proof(current.hash(), block.hash(), &proof)?;
        let expected: Value = read(&out.join(control))?;
        ensure(
            replay.proved_sender_signatures == 1
                && replay.proved_proposer_signature
                && replay.state_root.to_string()
                    == expected["state_root"].as_str().unwrap_or_default()
                && serde_json::to_value(&replay.receipts)? == expected["receipts"],
            "Dilithium cold historical replay differs",
        )?;
        replays.push(replay);
    }
    ensure(
        before == digest(node.store.as_ref())?,
        "Dilithium history wrote current KV",
    )?;
    let stem = if changed {
        "history-verified"
    } else {
        "verified"
    };
    let mut path = network.join(format!("{stem}.json"));
    let mut index = 2;
    while path.exists() {
        path = network.join(format!("{stem}-{index}.json"));
        index += 1;
    }
    write(
        &path,
        &json!({"all_kv_unchanged":true,"current_head":current.hash(),"current_height":current.number(),"ordinary_successor_not_proof_admitted":changed,"unbound_sender":unbound,"replay":replays[0],"replays":replays}),
    )?;
    node.store.flush()?;
    Ok(())
}

pub(crate) fn negative(out: &Path) -> Result<(), Error> {
    let network = out.join("network-dilithium");
    let context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let raw = std::fs::read(network.join("proof.bin"))?;
    let original = shell_stark_prover::compact_canonical::decode_payload(&raw)?;
    let (legacy_sender, legacy_proposer) = legacy_roles(out)?;
    let foreign = if legacy_proposer {
        &original
            .transactions
            .first()
            .ok_or("foreign sender proof absent")?
            .signature
            .transaction
            .signature
    } else {
        &original
            .proposer
            .as_ref()
            .ok_or("foreign proposer proof absent")?
            .signature
    };
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    let tip = node
        .chain_store
        .get_head_hash()?
        .ok_or("Dilithium negative tip absent")?;
    let before = digest(node.store.as_ref())?;
    let mut results = Vec::new();
    let actors: Value = read(&out.join("actors.json"))?;
    let unbound = actors["unbound_sender"] == true;
    let sdk = actors["native_sdk_fips_sender"] == true;
    let sdk_proposer = actors["native_sdk_fips_proposer"] == true;
    let mixed_sdk_raw = sdk && legacy_proposer && !sdk_proposer;
    let mixed_raw_sdk = !sdk && sdk_proposer && legacy_sender;
    let both = legacy_sender && legacy_proposer;
    let cases = if both {
        [
            ("foreign-key", "public key"),
            ("foreign-challenge", "challenge"),
            ("foreign-commitment", "final commitment"),
            ("relabelled-fips-profile", "version"),
        ]
    } else {
        [
            ("primary-key", "public key"),
            ("fips-challenge", "challenge"),
            ("fips-commitment", "final commitment"),
            ("relabelled-fips-profile", "version"),
        ]
    };
    let mut cases = cases.to_vec();
    let foreign_header = if sdk_proposer || mixed_sdk_raw {
        let path = network.join(if sdk_proposer {
            "sdk-proposer-foreign-header.json"
        } else {
            "raw-proposer-foreign-header.json"
        });
        let value = if path.exists() {
            read(&path)?
        } else {
            let successor: Block = read(&out.join("successor.json"))?;
            let proof = shell_stark_prover::header_hash::prove_header_hash(&successor.header)?;
            write(&path, &proof)?;
            proof
        };
        if sdk_proposer {
            cases[3] = ("relabelled-raw-signature", "version");
            cases.extend([
                ("sdk-proposer-as-primary-seal", "framing"),
                ("sdk-proposer-as-raw-seal", "version"),
                ("foreign-sdk-successor-header", "header"),
            ]);
        }
        Some(value)
    } else {
        None
    };
    if sdk && sdk_proposer {
        cases.extend([
            ("sdk-sender-as-primary-source", "SDK transaction"),
            ("sdk-sender-as-raw-account", "Dilithium3 shape"),
            (
                "sdk-sender-as-primary-account",
                if unbound {
                    "unbound signature"
                } else {
                    "framing"
                },
            ),
        ]);
    } else if sdk {
        cases[3] = ("relabelled-raw-signature", "version");
        cases.extend([
            ("sdk-as-primary-source", "SDK transaction"),
            ("sdk-as-raw-account", "Dilithium3 shape"),
            (
                "sdk-as-primary-account",
                if unbound {
                    "unbound signature"
                } else {
                    "framing"
                },
            ),
        ]);
    }
    if mixed_raw_sdk {
        cases.extend([
            ("raw-sender-as-sdk-source", "Dilithium3 shape"),
            ("raw-sender-as-sdk-account", "SDK transaction"),
            ("raw-sender-as-primary-account", "framing"),
        ]);
    }
    if mixed_sdk_raw {
        cases[3] = ("raw-proposer-as-fips-signature", "version");
        cases.extend([
            ("raw-proposer-as-sdk-seal", "version"),
            ("foreign-raw-successor-header", "header"),
            ("raw-proposer-as-primary-seal", "framing"),
        ]);
    }
    if sdk && unbound {
        cases.extend([
            ("raw-key-without-address-tag", "unbound sender address"),
            ("bound-sdk-profile-at-first-use", "no registered key"),
        ]);
    } else if unbound {
        cases.extend([
            ("raw-key-without-address-tag", "unbound sender address"),
            ("unbound-fips-profile", "unbound signature"),
            ("bound-profile-at-first-use", "no registered key"),
        ]);
    }
    for (index, (name, edge)) in cases.into_iter().enumerate() {
        let mut proof = original.clone();
        let target = if legacy_proposer {
            &mut proof
                .proposer
                .as_mut()
                .ok_or("raw proposer proof absent")?
                .signature
        } else {
            &mut proof.transactions[0].signature.transaction.signature
        };
        match index {
            0 => target.equation.key = foreign.equation.key.clone(),
            1 => target.equation.challenge = foreign.equation.challenge.clone(),
            2 => target.completion.commitment = foreign.completion.commitment.clone(),
            3 => {
                target.version = if mixed_sdk_raw {
                    1
                } else if sdk || sdk_proposer {
                    2
                } else {
                    1
                }
            }
            4 if sdk_proposer => {
                proof
                    .proposer
                    .as_mut()
                    .ok_or("SDK proposer absent")?
                    .version = 1
            }
            5 if sdk_proposer => {
                proof
                    .proposer
                    .as_mut()
                    .ok_or("SDK proposer absent")?
                    .version = 2
            }
            6 if sdk_proposer => {
                proof.proposer.as_mut().ok_or("SDK proposer absent")?.header = foreign_header
                    .as_ref()
                    .ok_or("foreign SDK header absent")?
                    .clone()
            }
            7 if sdk && sdk_proposer => proof.transactions[0].signature.transaction.version = 1,
            8 if sdk && sdk_proposer => {
                proof.transactions[0].signature.version = if unbound { 4 } else { 3 }
            }
            9 if sdk && sdk_proposer => {
                proof.transactions[0].signature.version = if unbound { 2 } else { 1 }
            }
            10 if sdk && sdk_proposer && unbound => {
                proof.transactions[0].signature.tagged_key = Some(
                    proof.transactions[0]
                        .signature
                        .transaction
                        .public_key_hash
                        .clone(),
                )
            }
            11 if sdk && sdk_proposer && unbound => proof.transactions[0].signature.version = 5,
            4 if sdk => proof.transactions[0].signature.transaction.version = 1,
            5 if sdk => proof.transactions[0].signature.version = if unbound { 4 } else { 3 },
            6 if sdk => proof.transactions[0].signature.version = if unbound { 2 } else { 1 },
            7 if mixed_raw_sdk => proof.transactions[0].signature.transaction.version = 3,
            8 if mixed_raw_sdk => proof.transactions[0].signature.version = 5,
            9 if mixed_raw_sdk => proof.transactions[0].signature.version = 1,
            7 if mixed_sdk_raw => {
                proof
                    .proposer
                    .as_mut()
                    .ok_or("raw proposer absent")?
                    .version = 3
            }
            8 if mixed_sdk_raw => {
                proof.proposer.as_mut().ok_or("raw proposer absent")?.header = foreign_header
                    .as_ref()
                    .ok_or("foreign raw header absent")?
                    .clone()
            }
            9 if mixed_sdk_raw => {
                proof
                    .proposer
                    .as_mut()
                    .ok_or("raw proposer absent")?
                    .version = 1
            }
            7 if sdk && unbound => {
                proof.transactions[0].signature.tagged_key = Some(
                    proof.transactions[0]
                        .signature
                        .transaction
                        .public_key_hash
                        .clone(),
                )
            }
            8 if sdk && unbound => proof.transactions[0].signature.version = 5,
            4 => {
                proof.transactions[0].signature.tagged_key = Some(
                    proof.transactions[0]
                        .signature
                        .transaction
                        .public_key_hash
                        .clone(),
                )
            }
            5 => proof.transactions[0].signature.version = 2,
            6 => proof.transactions[0].signature.version = 3,
            _ => unreachable!(),
        }
        let bytes =
            shell_stark_prover::compact_canonical::encode_payload(&proof, 256 * 1024 * 1024, true)?;
        let decoded = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
        let error = node
            .replay_canonical_transactions_with_proof(tip, block.hash(), &decoded)
            .err()
            .ok_or("foreign transcript/certificate accepted")?
            .to_string();
        ensure(
            error.contains(edge)
                && before == digest(node.store.as_ref())?
                && raw == std::fs::read(network.join("proof.bin"))?,
            "Dilithium refusal changed original data or failed at wrong edge",
        )?;
        std::fs::write(network.join(format!("{name}-refused.cbor")), &bytes)?;
        results.push(json!({"case":name,"correct_outer_hash":blake3_hash(&bytes),"error":error,"all_kv_unchanged":true,"original_proof_unchanged":true,"new_proofs_generated":0}));
    }
    write(
        &network.join("refusals.json"),
        &json!({"genuine_primary_certificates":!both,"genuine_foreign_raw_certificates":both && !sdk && !sdk_proposer,"genuine_foreign_sdk_certificates":both && sdk && sdk_proposer,"genuine_mixed_sdk_raw_certificates":mixed_sdk_raw,"genuine_mixed_raw_sdk_certificates":mixed_raw_sdk,"genuine_foreign_raw_header":mixed_sdk_raw,"genuine_unbound_address_certificate":unbound,"native_sdk_fips_sender":sdk,"native_sdk_fips_proposer":sdk_proposer,"genuine_foreign_sdk_header":sdk_proposer,"cases":results,"scope":"full historical predicate refusals, not new native block imports"}),
    )?;
    Ok(())
}
