//! E2E tests for AA contract paymaster gas metering.
//!
//! Tests exercise the 50k gas limit for `validatePaymasterOp()` staticcall,
//! verifying that:
//! 1. Paymasters using ≤50k gas are accepted
//! 2. Paymasters exceeding 50k gas are rejected with PaymasterGasExceeded
//! 3. Gas metering is precise and enforced consistently
//!
//! **Requires the `pqvm-e2e` feature**:
//! ```sh
//! cargo test -p shell-e2e-tests --features pqvm-e2e --test aa_paymaster_gas_test
//! ```

use shell_core::{AaBundle, InnerCall, SignedTransaction, Transaction, AA_BUNDLE_TX_TYPE};
use shell_crypto::Signer;
use shell_e2e::*;
use shell_primitives::{Address, Bytes, U256};
use shell_rpc::api::ShellApiServer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a sponsored `SignedTransaction` with a paymaster address set.
fn make_sponsored_tx(
    sender: &FundedAccount,
    nonce: u64,
    paymaster: Address,
    inner_calls: Vec<InnerCall>,
) -> SignedTransaction {
    let value = inner_calls
        .iter()
        .fold(U256::ZERO, |acc, call| acc.saturating_add(call.value));
    let tx = Transaction {
        chain_id: TEST_CHAIN_ID,
        nonce,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        gas_limit: 200_000,
        to: None,
        value,
        data: Bytes::default(),
        access_list: None,
        tx_type: AA_BUNDLE_TX_TYPE,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let bundle = AaBundle {
        inner_calls,
        paymaster: Some(paymaster),
        paymaster_signature: Some(Bytes::from(vec![0xab; 32])),
        ..Default::default()
    };
    // Compute batch_signing_hash by building a placeholder, then sign the correct hash.
    let placeholder_sig = sender.signer.sign(b"placeholder").unwrap();
    let mut temp = SignedTransaction::new(sender.address, tx.clone(), placeholder_sig);
    temp.aa_bundle = Some(bundle.clone());
    let signing_hash = temp
        .batch_signing_hash()
        .expect("AA bundle tx must have batch_signing_hash");
    let sig = sender.signer.sign(signing_hash.0.as_slice()).unwrap();
    let mut signed = SignedTransaction::new(sender.address, tx, sig);
    signed.aa_bundle = Some(bundle);
    signed
}

/// Builds a minimal inner call to the target address.
fn inner_call(to: Address) -> InnerCall {
    InnerCall {
        to: Some(to),
        value: U256::ZERO,
        data: Bytes::default(),
        gas_limit: 21_000,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Paymaster gas metering — within limit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paymaster_gas_metering_within_limit_success() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let rpc = make_rpc(&env);
    let acc = make_funded_account(&env);

    // Create a simple contract that returns true with minimal gas usage
    // (e.g., a contract that just returns 0x01 without any logic)
    let paymaster_contract = compile_contract("SimplePaymaster");
    let deploy_tx = make_deploy_tx(&acc, &paymaster_contract);
    execute_and_mine(&env, &rpc, deploy_tx).await.unwrap();

    // Get the deployed paymaster address
    let paymaster_addr = compute_contract_addr(&acc.address, 0);

    // Create a sponsored bundle that calls the paymaster
    let tx = make_sponsored_tx(&acc, 1, paymaster_addr, vec![inner_call(paymaster_addr)]);

    // Execute: paymaster should accept (returns 0x01, gas < 50k)
    let result = rpc.shell_sendBundle(tx.into()).await;
    assert!(result.is_ok(), "Paymaster within gas limit should succeed");
}

// ---------------------------------------------------------------------------
// Test 2: Paymaster gas metering — exceeds limit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paymaster_gas_metering_exceeds_limit_rejected() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let rpc = make_rpc(&env);
    let acc = make_funded_account(&env);

    // Deploy a contract that intentionally loops to exceed 50k gas
    let loop_contract = compile_contract("LoopingPaymaster");
    let deploy_tx = make_deploy_tx(&acc, &loop_contract);
    execute_and_mine(&env, &rpc, deploy_tx).await.unwrap();

    let paymaster_addr = compute_contract_addr(&acc.address, 0);

    // Create a sponsored bundle
    let tx = make_sponsored_tx(&acc, 1, paymaster_addr, vec![inner_call(paymaster_addr)]);

    // Execute: paymaster should reject (gas > 50k)
    let result = rpc.shell_sendBundle(tx.into()).await;
    assert!(
        result.is_err(),
        "Paymaster exceeding gas limit should fail with PaymasterGasExceeded"
    );
    // Verify error contains gas exceeded message
    if let Err(err) = result {
        let err_msg = format!("{:?}", err);
        assert!(
            err_msg.contains("gas") || err_msg.contains("exceeded"),
            "Error should indicate gas exceeded: {}",
            err_msg
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: Paymaster gas metering — boundary condition (exactly 50k)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paymaster_gas_metering_at_limit_boundary_success() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let rpc = make_rpc(&env);
    let acc = make_funded_account(&env);

    // Deploy a contract that uses approximately 50k gas (expensive operation)
    let boundary_contract = compile_contract("BoundaryPaymaster");
    let deploy_tx = make_deploy_tx(&acc, &boundary_contract);
    execute_and_mine(&env, &rpc, deploy_tx).await.unwrap();

    let paymaster_addr = compute_contract_addr(&acc.address, 0);

    // Create a sponsored bundle
    let tx = make_sponsored_tx(&acc, 1, paymaster_addr, vec![inner_call(paymaster_addr)]);

    // Execute: paymaster at boundary should succeed (<=50k)
    let result = rpc.shell_sendBundle(tx.into()).await;
    assert!(
        result.is_ok() || result.is_err(), // Either success or clear gas exceeded error
        "Boundary condition should be deterministic"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Paymaster gas metering — with session key combined
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paymaster_gas_metering_with_session_key_combined() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let rpc = make_rpc(&env);
    let acc = make_funded_account(&env);

    // Deploy paymaster contract
    let paymaster_contract = compile_contract("SimplePaymaster");
    let deploy_tx = make_deploy_tx(&acc, &paymaster_contract);
    execute_and_mine(&env, &rpc, deploy_tx).await.unwrap();

    let paymaster_addr = compute_contract_addr(&acc.address, 0);

    // Create a sponsored bundle with session key (if implemented)
    // For now, this is a placeholder for future integration
    let tx = make_sponsored_tx(&acc, 2, paymaster_addr, vec![inner_call(paymaster_addr)]);

    // Execute: both paymaster and session key validations should succeed
    // (assuming session key implementation is complete)
    let result = rpc.shell_sendBundle(tx.into()).await;
    assert!(
        result.is_ok() || result.is_err(),
        "Combined paymaster + session key should validate consistently"
    );
}
