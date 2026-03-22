use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use shell_primitives::{
    BasicFeesPerGas, BasicTransactionPayload, ChainId, CreateTransactionPayload, ExecutionAddress,
    GasPrice, PrimitiveError, Root, TransactionPayload, TransactionPayloadSsz, TxValue, U256,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionVector {
    id: String,
    category: String,
    description: String,
    input: VectorInput,
    expected_outcome: String,
    #[serde(default)]
    expected_error: Option<ExpectedError>,
    owned_by: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    payload_tag: Option<u8>,
    #[serde(default)]
    payload_root: Option<String>,
    #[serde(default)]
    authorization_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorInput {
    #[serde(default)]
    payload: Option<PayloadInput>,
    #[serde(default)]
    wire_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PayloadInput {
    Basic {
        chain_id: String,
        nonce: u64,
        gas_limit: u64,
        fees: FeeInput,
        to: String,
        value: String,
        input_hex: String,
        access_commitment: String,
    },
    Create {
        chain_id: String,
        nonce: u64,
        gas_limit: u64,
        fees: FeeInput,
        value: String,
        initcode_hex: String,
        access_commitment: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeeInput {
    regular: String,
    max_priority_fee_per_gas: String,
    max_witness_priority_fee: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    kind: String,
    #[serde(default)]
    tag: Option<u8>,
    #[serde(default)]
    context: Option<String>,
}

#[test]
fn transaction_vectors_match_the_closed_codec_and_root_contract() {
    let mut paths = fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one transaction fixture under vectors/transactions"
    );

    for path in paths {
        let fixture = load_fixture(&path);
        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some(fixture.id.as_str())
        );
        assert_eq!(fixture.category, "transaction");
        assert_eq!(fixture.owned_by, "shell-primitives");
        assert!(
            !fixture.description.trim().is_empty(),
            "fixture {} must document the invariant it covers",
            fixture.id
        );
        if let Some(notes) = &fixture.notes {
            assert!(
                !notes.trim().is_empty(),
                "fixture {} notes must not be empty when present",
                fixture.id
            );
        }

        match fixture.expected_outcome.as_str() {
            "accept" => assert_accept_fixture(&fixture),
            "reject" => assert_reject_fixture(&fixture),
            other => panic!("unsupported expected_outcome {other} in {}", fixture.id),
        }
    }
}

fn assert_accept_fixture(fixture: &TransactionVector) {
    let payload = build_payload(
        fixture
            .input
            .payload
            .as_ref()
            .unwrap_or_else(|| panic!("{} is missing input.payload", fixture.id)),
    );
    let wire = payload
        .to_wire_bytes()
        .unwrap_or_else(|err| panic!("{} encode failed: {err:?}", fixture.id));
    let decoded = TransactionPayloadSsz::from_wire_bytes(&wire)
        .unwrap_or_else(|err| panic!("{} decode failed: {err:?}", fixture.id));
    let root = payload
        .hash_tree_root()
        .unwrap_or_else(|err| panic!("{} root failed: {err:?}", fixture.id));

    assert_eq!(payload, decoded, "{} failed wire round-trip", fixture.id);

    let expected_tag = fixture
        .payload_tag
        .unwrap_or_else(|| panic!("{} is missing payload_tag", fixture.id));
    assert_eq!(
        payload.protocol_tag(),
        expected_tag,
        "{} payload_tag mismatch",
        fixture.id
    );

    let expected_root = parse_root(
        fixture
            .payload_root
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing payload_root", fixture.id)),
    );
    assert_eq!(root, expected_root, "{} payload_root mismatch", fixture.id);
    assert_eq!(
        decoded.hash_tree_root().expect("decoded root"),
        expected_root,
        "{} decoded payload_root mismatch",
        fixture.id
    );

    let expected_wire = parse_hex(
        fixture
            .input
            .wire_hex
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing input.wire_hex", fixture.id)),
    );
    assert_eq!(wire, expected_wire, "{} wire_hex mismatch", fixture.id);

    assert_eq!(
        fixture.authorization_count,
        Some(0),
        "{} should keep authorization_count explicit for payload-only vectors",
        fixture.id
    );
}

fn assert_reject_fixture(fixture: &TransactionVector) {
    let wire = parse_hex(
        fixture
            .input
            .wire_hex
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing input.wire_hex", fixture.id)),
    );
    let error = TransactionPayloadSsz::from_wire_bytes(&wire).expect_err(&format!(
        "{} should reject malformed or unsupported bytes",
        fixture.id
    ));
    let expected = fixture
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));

    match (&*expected.kind, error) {
        ("UnsupportedPayloadVariant", PrimitiveError::UnsupportedPayloadVariant(actual)) => {
            assert_eq!(
                Some(actual.tag),
                expected.tag,
                "{} rejected with the wrong unsupported tag",
                fixture.id
            );
        }
        ("MalformedSsz", PrimitiveError::MalformedSsz(actual)) => {
            assert_eq!(
                Some(actual.context),
                expected.context.as_deref(),
                "{} rejected with the wrong malformed context",
                fixture.id
            );
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind}, got {:?}",
            fixture.id, actual
        ),
    }
}

fn build_payload(input: &PayloadInput) -> TransactionPayloadSsz {
    match input {
        PayloadInput::Basic {
            chain_id,
            nonce,
            gas_limit,
            fees,
            to,
            value,
            input_hex,
            access_commitment,
        } => TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
            chain_id: ChainId(U256(parse_bytes_32(chain_id))),
            nonce: *nonce,
            gas_limit: *gas_limit,
            fees: parse_fees(fees),
            to: parse_address(to),
            value: TxValue(U256(parse_bytes_32(value))),
            input: parse_hex(input_hex),
            access_commitment: parse_root(access_commitment),
        })),
        PayloadInput::Create {
            chain_id,
            nonce,
            gas_limit,
            fees,
            value,
            initcode_hex,
            access_commitment,
        } => TransactionPayloadSsz::new(TransactionPayload::Create(CreateTransactionPayload {
            chain_id: ChainId(U256(parse_bytes_32(chain_id))),
            nonce: *nonce,
            gas_limit: *gas_limit,
            fees: parse_fees(fees),
            value: TxValue(U256(parse_bytes_32(value))),
            initcode: parse_hex(initcode_hex),
            access_commitment: parse_root(access_commitment),
        })),
    }
}

fn parse_fees(fees: &FeeInput) -> BasicFeesPerGas {
    BasicFeesPerGas {
        regular: GasPrice(U256(parse_bytes_32(&fees.regular))),
        max_priority_fee_per_gas: GasPrice(U256(parse_bytes_32(&fees.max_priority_fee_per_gas))),
        max_witness_priority_fee: GasPrice(U256(parse_bytes_32(&fees.max_witness_priority_fee))),
    }
}

fn fixture_paths() -> Vec<PathBuf> {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/transactions");
    fs::read_dir(&fixture_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixture_dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("json")).then_some(path)
        })
        .collect()
}

fn load_fixture(path: &Path) -> TransactionVector {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn parse_root(value: &str) -> Root {
    parse_bytes_32(value)
}

fn parse_address(value: &str) -> ExecutionAddress {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 20-byte hex string, got {len} bytes in {value}"))
}

fn parse_bytes_32(value: &str) -> [u8; 32] {
    let bytes = parse_hex(value);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32-byte hex string, got {len} bytes in {value}"))
}

fn parse_hex(value: &str) -> Vec<u8> {
    let hex = value
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("hex values must use a 0x prefix: {value}"));
    assert!(
        hex.len() % 2 == 0,
        "hex values must contain an even number of digits: {value}"
    );

    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex byte at offset {index} in {value}"))
        })
        .collect()
}
