use super::*;
use shell_rpc::api::{DebugApiServer, EthApiServer};
use shell_rpc::types::CallRequest;

const CONTRACT: Address = Address([0x99; 32]);
const DIRECTORY: &str = "SHELL_TEST_NATIVE_OVERLOAD_DIRECTORY";

#[derive(serde::Serialize, serde::Deserialize)]
struct Step {
    block: Block,
    words: [ShellHash; 3],
    sender_balance: U256,
    success: bool,
    inner_outputs: Option<Vec<Vec<u8>>>,
}

fn verify<S: KvStore + 'static>(node: &Node<S>, steps: &[Step]) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    let (events, _) = tokio::sync::broadcast::channel(16);
    let handler = shell_rpc::RpcHandler::new(
        Arc::clone(&node.chain_store),
        Arc::clone(&node.world_state),
        Arc::clone(&node.tx_pool),
        1337,
        None,
        events,
        Arc::new(RwLock::new(0)),
        Arc::new(RwLock::new(FinalityState::new())),
    );
    let before = node.store.scan_prefix(b"").unwrap();
    let tip_root = current_state_root(node);
    assert_eq!(
        node.chain_store.get_head_hash().unwrap(),
        Some(steps.last().unwrap().block.hash())
    );
    // Descending historical reads must survive later writes and must not mutate the tip.
    for step in steps.iter().rev() {
        let tx = &step.block.transactions[0];
        let state = WorldState::at_root(node.store.clone(), &step.block.header.state_root).unwrap();
        assert_eq!(state.get_nonce(&tx.from).unwrap(), tx.tx.nonce + 1);
        assert_eq!(state.get_balance(&tx.from).unwrap(), step.sender_balance);
        let receipts = node
            .chain_store
            .get_receipts(&step.block.hash())
            .unwrap()
            .unwrap();
        assert_eq!(receipts[0].tx_hash, tx.hash());
        assert_eq!(receipts[0].status, u8::from(step.success));
        for (slot, signature) in [b"owner()".as_slice(), b"amount()", b"writes()"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                state
                    .get_storage(
                        &CONTRACT,
                        &ShellHash::from(U256::from(slot).to_be_bytes::<32>())
                    )
                    .unwrap(),
                step.words[slot]
            );
            let result = runtime
                .block_on(EthApiServer::call(
                    &handler,
                    CallRequest {
                        from: Some(tx.from),
                        to: Some(CONTRACT),
                        data: Some(format!(
                            "0x{}",
                            hex::encode(&shell_primitives::keccak256(signature).as_bytes()[..4])
                        )),
                        value: None,
                        gas: Some("0x7a120".into()),
                        access_list: None,
                    },
                    Some(format!("0x{:x}", step.block.number())),
                ))
                .unwrap();
            assert_eq!(result, step.words[slot].to_string());
        }
        let trace = runtime
            .block_on(DebugApiServer::trace_transaction(
                &handler,
                tx.hash().to_string(),
                None,
            ))
            .unwrap();
        assert_eq!(trace["failed"], !step.success);
        if let Some(outputs) = &step.inner_outputs {
            let trace = runtime
                .block_on(DebugApiServer::trace_transaction(
                    &handler,
                    tx.hash().to_string(),
                    Some(serde_json::json!({"tracer":"callTracer"})),
                ))
                .unwrap();
            let calls = trace["calls"].as_array().unwrap();
            assert_eq!(calls.len(), outputs.len());
            for (call, output) in calls.iter().zip(outputs) {
                assert_eq!(call["to"], CONTRACT.to_string());
                assert_eq!(call["output"], format!("0x{}", hex::encode(output)));
            }
        }
        assert_eq!(current_state_root(node), tip_root);
        assert_eq!(node.store.scan_prefix(b"").unwrap(), before);
    }
}

fn write_history(directory: &std::path::Path, signer: &dyn Signer, aa: bool) {
    let (leader, proposer) = setup_node();
    let authority = leader.config.proposer_address.unwrap();
    let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
    let follower = setup_node_with_store(authority, Arc::new(stores.state));
    let sender = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let first = native_struct_word(0x34, 0x12);
    let second = native_struct_word(0x56, 0x12);
    let initial_balance = U256::from(10_000_000_000_000_000_000u64);
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../pqvm/tests/fixtures/native-stateful-overloads.json"
    ))
    .unwrap();
    let code = fixture["artifacts"]["pqvm"]["deployedBytecode"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x");
    let genesis: shell_genesis::GenesisConfig = serde_json::from_value(serde_json::json!({
        "chain_id":1337, "timestamp":0, "network_type":"Dev", "fee_accounting_activation_height":0,
        "consensus":{"engine":"poa","authorities":[authority],"authority_pubkeys":[hex::encode(proposer.public_key())],"block_time_secs":1},
        "alloc":{sender.to_string():{"balance":initial_balance}, first.to_string():{"balance":initial_balance}, CONTRACT.to_string():{"balance":U256::ZERO,"code":code}}
    })).unwrap();
    std::fs::write(
        directory.join("genesis.json"),
        serde_json::to_vec(&genesis).unwrap(),
    )
    .unwrap();
    macro_rules! initialize {
        ($node:expr) => {{
            $node.register_authority_pubkey(authority, proposer.public_key().to_vec());
            let block = shell_genesis::initialize_genesis(&genesis, $node.store.clone()).unwrap();
            *$node.world_state.write() =
                WorldState::at_root($node.store.clone(), &block.header.state_root).unwrap();
        }};
    }
    initialize!(leader);
    initialize!(follower);
    let word = U256::from_be_bytes(*first.as_bytes());
    let integer_result = ShellHash::from((word + U256::from(1)).to_be_bytes::<32>());
    let address_input = |value: Address| {
        let mut data = shell_primitives::keccak256(b"set(address)").as_bytes()[..4].to_vec();
        data.extend_from_slice(value.as_bytes());
        data
    };
    let integer_input = |value: U256| {
        let mut data = shell_primitives::keccak256(b"set(uint256)").as_bytes()[..4].to_vec();
        data.extend_from_slice(&value.to_be_bytes::<32>());
        data
    };
    let mut truncated = address_input(first);
    truncated.pop();
    // Expected words come from the original Solidity declarations: address identity,
    // integer +1, and a counter that advances only for committed successful calls.
    let ordinary = [
        (
            address_input(first),
            true,
            ShellHash::from(*first.as_bytes()),
            ShellHash::ZERO,
            1,
        ),
        (
            integer_input(word),
            true,
            ShellHash::from(*first.as_bytes()),
            integer_result,
            2,
        ),
        (
            address_input(second),
            true,
            ShellHash::from(*second.as_bytes()),
            integer_result,
            3,
        ),
        (
            address_input(Address::ZERO),
            false,
            ShellHash::from(*second.as_bytes()),
            integer_result,
            3,
        ),
        (
            truncated,
            false,
            ShellHash::from(*second.as_bytes()),
            integer_result,
            3,
        ),
        (
            integer_input(U256::MAX),
            false,
            ShellHash::from(*second.as_bytes()),
            integer_result,
            3,
        ),
        (
            integer_input(U256::ZERO),
            true,
            ShellHash::from(*second.as_bytes()),
            ShellHash::from(U256::from(1).to_be_bytes::<32>()),
            4,
        ),
    ];
    let cases = if aa {
        let first_word = ShellHash::from(*first.as_bytes());
        let second_word = ShellHash::from(*second.as_bytes());
        let one = ShellHash::from(U256::from(1).to_be_bytes::<32>());
        let mut truncated = address_input(second);
        truncated.pop();
        vec![
            (
                vec![address_input(first), integer_input(word)],
                true,
                first_word,
                integer_result,
                2,
            ),
            (
                vec![address_input(second), integer_input(U256::ZERO)],
                true,
                second_word,
                one,
                4,
            ),
            // Each failure follows successful inner writes; all fields and the counter roll back.
            (
                vec![
                    address_input(first),
                    integer_input(word),
                    address_input(Address::ZERO),
                ],
                false,
                second_word,
                one,
                4,
            ),
            (
                vec![address_input(first), integer_input(U256::MAX)],
                false,
                second_word,
                one,
                4,
            ),
            (
                vec![address_input(first), truncated],
                false,
                second_word,
                one,
                4,
            ),
            (
                vec![integer_input(word), address_input(first)],
                true,
                first_word,
                integer_result,
                6,
            ),
            (
                vec![address_input(second), integer_input(U256::MAX)],
                false,
                first_word,
                integer_result,
                6,
            ),
        ]
    } else {
        ordinary
            .into_iter()
            .map(|(data, success, owner, amount, writes)| {
                (vec![data], success, owner, amount, writes)
            })
            .collect()
    };
    let expected_output = |data: &[u8]| {
        if data.len() != 36 {
            return vec![];
        }
        if data[..4] == address_input(first)[..4] {
            if data[4..] == [0; 32] {
                vec![]
            } else {
                data[4..].to_vec()
            }
        } else {
            let value = U256::from_be_slice(&data[4..]);
            if value == U256::MAX {
                let mut panic = hex::decode("4e487b71").unwrap();
                panic.extend_from_slice(&U256::from(0x11).to_be_bytes::<32>());
                panic
            } else {
                (value + U256::from(1)).to_be_bytes::<32>().to_vec()
            }
        }
    };
    let mut fees = U256::ZERO;
    let mut steps = Vec::new();
    for (nonce, (calls, success, owner, amount, writes)) in cases.into_iter().enumerate() {
        let tx = Transaction {
            chain_id: 1337,
            nonce: nonce as u64,
            to: if aa { None } else { Some(CONTRACT) },
            value: U256::ZERO,
            data: if aa {
                Bytes::new()
            } else {
                Bytes::from(calls[0].clone())
            },
            gas_limit: if aa { 1_500_000 } else { 500_000 },
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE * if aa { 2 } else { 1 },
            max_priority_fee_per_gas: u64::from(aa),
            access_list: None,
            tx_type: if aa { AA_BUNDLE_TX_TYPE } else { 2 },
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let max_fee = tx.max_fee_per_gas;
        let priority_fee = tx.max_priority_fee_per_gas;
        let signed = if aa {
            let mut signed = SignedTransaction::with_aa_bundle(
                sender,
                tx,
                PQSignature::new(signer.sig_type(), vec![]),
                PubkeyMode::Embedded(signer.public_key().to_vec()),
                AaBundle {
                    inner_calls: calls
                        .iter()
                        .map(|data| InnerCall {
                            to: Some(CONTRACT),
                            value: U256::ZERO,
                            data: Bytes::from(data.clone()),
                            gas_limit: 300_000,
                        })
                        .collect(),
                    ..AaBundle::default()
                },
            )
            .unwrap();
            signed.signature = signer
                .sign(signed.sender_signing_hash().as_bytes())
                .unwrap();
            signed
        } else {
            let signature = signer
                .sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes())
                .unwrap();
            SignedTransaction::with_pubkey(sender, tx, signature, signer.public_key().to_vec())
        };
        let before = leader.store.scan_prefix(b"").unwrap();
        let root = current_state_root(&leader);
        let mut changed = signed.clone();
        let changed_input = if aa {
            &mut changed.aa_bundle.as_mut().unwrap().inner_calls[0].data
        } else {
            &mut changed.tx.data
        };
        let mut changed_data = changed_input.0.to_vec();
        changed_data[4] ^= 1;
        *changed_input = Bytes::from(changed_data);
        let mut tampered = signed.clone();
        tampered.signature.data[0] ^= 1;
        let mut wrong_sender = signed.clone();
        wrong_sender.from = first;
        for bad in [tampered, changed, wrong_sender] {
            assert!(leader
                .tx_pool
                .insert(
                    bad,
                    &mut leader.world_state.write(),
                    leader.chain_store.as_ref(),
                    &MultiVerifier
                )
                .is_err());
            assert_eq!(leader.store.scan_prefix(b"").unwrap(), before);
            assert_eq!(current_state_root(&leader), root);
        }
        let hash = signed.hash();
        leader
            .tx_pool
            .insert(
                signed,
                &mut leader.world_state.write(),
                leader.chain_store.as_ref(),
                &MultiVerifier,
            )
            .unwrap();
        let block = leader.produce_block(&proposer, 100).unwrap();
        assert_eq!(block.number(), nonce as u64 + 1);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].hash(), hash);
        follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();
        let receipts = leader
            .chain_store
            .get_receipts(&block.hash())
            .unwrap()
            .unwrap();
        assert_eq!(receipts[0].status, u8::from(success));
        assert_eq!(
            follower
                .chain_store
                .get_receipts(&block.hash())
                .unwrap()
                .unwrap(),
            receipts
        );
        // Compute the consensus guide's min(max fee, base fee + tip) directly.
        // Included failed AA batches still consume one outer nonce and pay billed gas.
        fees += U256::from(receipts[0].gas_used)
            * U256::from(max_fee.min(block.header.base_fee_per_gas + priority_fee));
        steps.push(Step {
            block,
            words: [
                owner,
                amount,
                ShellHash::from(U256::from(writes).to_be_bytes::<32>()),
            ],
            sender_balance: initial_balance - fees,
            success,
            inner_outputs: aa.then(|| calls.iter().map(|data| expected_output(data)).collect()),
        });
        assert_eq!(
            current_state_root(&leader),
            steps.last().unwrap().block.header.state_root
        );
        assert_eq!(
            current_state_root(&follower),
            steps.last().unwrap().block.header.state_root
        );
    }
    verify(&leader, &steps);
    verify(&follower, &steps);
    std::fs::write(
        directory.join("steps.json"),
        serde_json::to_vec(&steps).unwrap(),
    )
    .unwrap();
    // Exercise WAL recovery after process exit without dropping any database handles.
    std::process::exit(0);
}

fn process_exit(aa: bool) {
    if let Some(directory) = std::env::var_os(DIRECTORY) {
        let directory = std::path::PathBuf::from(directory);
        if std::env::var("SHELL_TEST_NATIVE_OVERLOAD_ALGORITHM").as_deref() == Ok("mldsa") {
            write_history(&directory, &MlDsaSigner::generate(), aa);
        } else {
            write_history(&directory, &DilithiumSigner::generate(), aa);
        }
        unreachable!();
    }
    for algorithm in ["dilithium", "mldsa"] {
        let directory = std::env::temp_dir().join(format!(
            "shell-native-overload-{}-{algorithm}-{}-{}",
            if aa { "aa" } else { "ordinary" },
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let status = Command::new(std::env::current_exe().unwrap()).args(["--exact", if aa {"node::tests::native_overload_tests::native_overload_aa_survives_process_exit"} else {"node::tests::native_overload_tests::native_overload_signed_import_survives_process_exit"}, "--nocapture"]).env(DIRECTORY, &directory).env("SHELL_TEST_NATIVE_OVERLOAD_ALGORITHM",algorithm).status().unwrap();
        assert!(
            status.success(),
            "overload writer failed; retained {}",
            directory.display()
        );
        let steps: Vec<Step> =
            serde_json::from_slice(&std::fs::read(directory.join("steps.json")).unwrap()).unwrap();
        let tip = &steps.last().unwrap().block;
        let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
        let mut config = NodeConfig::dev(tip.header.proposer);
        config.consensus =
            crate::config::ConsensusEngineConfig::Poa(PoaConfig::new(vec![tip.header.proposer], 1));
        let (node, recovered_store) =
            crate::builder::NodeBuilder::new(config, Arc::new(stores.state))
                .build()
                .unwrap();
        verify(&node, &steps);
        assert_eq!(current_state_root(&node), tip.header.state_root);
        drop(node);
        drop(recovered_store);
        drop(stores.chain);
        drop(stores.receipts);
        drop(stores.index);
        drop(stores.witness);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn native_overload_signed_import_survives_process_exit() {
    process_exit(false);
}

#[test]
fn native_overload_aa_survives_process_exit() {
    process_exit(true);
}
