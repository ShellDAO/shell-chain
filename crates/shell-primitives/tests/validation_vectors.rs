//! Fixture-driven tests for the three closed T1 validation rules in `shell-primitives`.
//!
//! Each fixture in `vectors/validation/` covers one of:
//! - `authorization_count`        → `check_authorization_count`
//! - `authorization_payload_roots` → `check_authorization_payload_roots`
//! - `user_signature_size`        → `check_user_signature_size`
//!
//! The fixture schema is intentionally separate from the codec vectors in
//! `vectors/transactions/` because these rules operate on already-decoded
//! structures rather than on raw wire bytes.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use shell_primitives::{
    check_authorization_count, check_authorization_payload_roots, check_user_signature_size,
    Authorization, PrimitiveError, Root, TransactionPayloadSsz, MAX_USER_SIGNATURE_BYTES,
};

// ────── Fixture schema ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationVector {
    id: String,
    category: String,
    rule: String,
    description: String,
    input: ValidationInput,
    expected_outcome: String,
    #[serde(default)]
    expected_error: Option<ValidationError>,
    owned_by: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationInput {
    /// Present for `authorization_count` and `authorization_payload_roots` rules.
    #[serde(default)]
    authorizations: Option<Vec<AuthorizationInput>>,
    /// Present for `authorization_payload_roots` rule (canonical SSZ wire bytes of the payload).
    #[serde(default)]
    wire_hex: Option<String>,
    /// Present for `user_signature_size` rule (number of zero bytes to synthesise).
    #[serde(default)]
    signature_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationInput {
    scheme_id: u8,
    /// Hex-encoded 32-byte payload root.
    payload_root: String,
    /// Hex-encoded raw signature bytes.
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationError {
    kind: String,
    // AuthorizationCount fields
    #[serde(default)]
    expected_at_least: Option<usize>,
    #[serde(default)]
    actual: Option<usize>,
    // PayloadRootMismatch fields
    #[serde(default)]
    expected_root: Option<String>,
    #[serde(default)]
    actual_root: Option<String>,
    // SignatureSizeExceeded fields
    #[serde(default)]
    max_bytes: Option<usize>,
    #[serde(default)]
    actual_bytes: Option<usize>,
}

// ────── Test entry point ──────────────────────────────────────────────────────

#[test]
fn validation_vectors_match_the_closed_t1_rules() {
    let mut paths = fixture_paths();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "expected at least one validation fixture under vectors/validation"
    );

    for path in paths {
        let fixture = load_fixture(&path);

        assert_eq!(
            path.file_stem().and_then(|s| s.to_str()),
            Some(fixture.id.as_str()),
            "fixture id must match filename stem"
        );
        assert_eq!(
            fixture.category, "validation",
            "{} must declare category 'validation'",
            fixture.id
        );
        assert_eq!(
            fixture.owned_by, "shell-primitives",
            "{} must be owned by shell-primitives",
            fixture.id
        );
        assert!(
            !fixture.description.trim().is_empty(),
            "fixture {} must document the invariant it covers",
            fixture.id
        );
        if let Some(notes) = &fixture.notes {
            assert!(
                !notes.trim().is_empty(),
                "fixture {} notes field must not be blank when present",
                fixture.id
            );
        }

        match fixture.expected_outcome.as_str() {
            "accept" => assert_accept(&fixture),
            "reject" => assert_reject(&fixture),
            other => panic!("unsupported expected_outcome {:?} in {}", other, fixture.id),
        }
    }
}

// ────── Accept / reject dispatchers ──────────────────────────────────────────

fn assert_accept(fixture: &ValidationVector) {
    match fixture.rule.as_str() {
        "authorization_count" => {
            let auths = build_authorizations(fixture);
            check_authorization_count(&auths)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        "authorization_payload_roots" => {
            let payload = decode_payload(fixture);
            let auths = build_authorizations(fixture);
            check_authorization_payload_roots(&payload, &auths)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        "user_signature_size" => {
            let sig = build_signature(fixture);
            check_user_signature_size(&sig)
                .unwrap_or_else(|err| panic!("{} should accept but got {err:?}", fixture.id));
        }
        rule => panic!("{} has unrecognised rule {:?}", fixture.id, rule),
    }
}

fn assert_reject(fixture: &ValidationVector) {
    let expected = fixture
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("{} is missing expected_error", fixture.id));

    match fixture.rule.as_str() {
        "authorization_count" => {
            let auths = build_authorizations(fixture);
            let err = check_authorization_count(&auths)
                .expect_err(&format!("{} should reject but accepted", fixture.id));
            assert_authorization_count_error(fixture, expected, err);
        }
        "authorization_payload_roots" => {
            let payload = decode_payload(fixture);
            let auths = build_authorizations(fixture);
            let err = check_authorization_payload_roots(&payload, &auths)
                .expect_err(&format!("{} should reject but accepted", fixture.id));
            assert_payload_root_mismatch_error(fixture, expected, err);
        }
        "user_signature_size" => {
            let sig = build_signature(fixture);
            let err = check_user_signature_size(&sig)
                .expect_err(&format!("{} should reject but accepted", fixture.id));
            assert_signature_size_error(fixture, expected, err);
        }
        rule => panic!("{} has unrecognised rule {:?}", fixture.id, rule),
    }
}

// ────── Error assertion helpers ───────────────────────────────────────────────

fn assert_authorization_count_error(
    fixture: &ValidationVector,
    expected: &ValidationError,
    err: PrimitiveError,
) {
    match (&*expected.kind, err) {
        ("AuthorizationCount", PrimitiveError::AuthorizationCount(actual)) => {
            if let Some(exp_least) = expected.expected_at_least {
                assert_eq!(
                    actual.expected_at_least, exp_least,
                    "{} expected_at_least mismatch",
                    fixture.id
                );
            }
            if let Some(exp_actual) = expected.actual {
                assert_eq!(
                    actual.actual, exp_actual,
                    "{} actual count mismatch",
                    fixture.id
                );
            }
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

fn assert_payload_root_mismatch_error(
    fixture: &ValidationVector,
    expected: &ValidationError,
    err: PrimitiveError,
) {
    match (&*expected.kind, err) {
        ("PayloadRootMismatch", PrimitiveError::PayloadRootMismatch(actual)) => {
            if let Some(exp_root_str) = &expected.expected_root {
                let exp_root = parse_root(exp_root_str);
                assert_eq!(
                    actual.expected, exp_root,
                    "{} expected_root mismatch",
                    fixture.id
                );
            }
            if let Some(act_root_str) = &expected.actual_root {
                let act_root = parse_root(act_root_str);
                assert_eq!(
                    actual.actual, act_root,
                    "{} actual_root mismatch",
                    fixture.id
                );
            }
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

fn assert_signature_size_error(
    fixture: &ValidationVector,
    expected: &ValidationError,
    err: PrimitiveError,
) {
    match (&*expected.kind, err) {
        ("SignatureSizeExceeded", PrimitiveError::SignatureSizeExceeded(actual)) => {
            if let Some(exp_max) = expected.max_bytes {
                assert_eq!(
                    actual.max_bytes, exp_max,
                    "{} max_bytes mismatch",
                    fixture.id
                );
                assert_eq!(
                    actual.max_bytes, MAX_USER_SIGNATURE_BYTES,
                    "{} max_bytes must equal MAX_USER_SIGNATURE_BYTES",
                    fixture.id
                );
            }
            if let Some(exp_actual) = expected.actual_bytes {
                assert_eq!(
                    actual.actual_bytes, exp_actual,
                    "{} actual_bytes mismatch",
                    fixture.id
                );
            }
        }
        (kind, actual) => panic!(
            "{} expected error kind {kind:?}, got {actual:?}",
            fixture.id
        ),
    }
}

// ────── Input builders ────────────────────────────────────────────────────────

fn build_authorizations(fixture: &ValidationVector) -> Vec<Authorization> {
    fixture
        .input
        .authorizations
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|a| Authorization {
            scheme_id: a.scheme_id,
            payload_root: parse_root(&a.payload_root),
            signature: parse_hex(&a.signature_hex),
        })
        .collect()
}

fn decode_payload(fixture: &ValidationVector) -> TransactionPayloadSsz {
    let wire_hex = fixture
        .input
        .wire_hex
        .as_deref()
        .unwrap_or_else(|| panic!("{} is missing input.wire_hex", fixture.id));
    let wire = parse_hex(wire_hex);
    TransactionPayloadSsz::from_wire_bytes(&wire)
        .unwrap_or_else(|err| panic!("{} failed to decode payload: {err:?}", fixture.id))
}

fn build_signature(fixture: &ValidationVector) -> Vec<u8> {
    let size = fixture
        .input
        .signature_size
        .unwrap_or_else(|| panic!("{} is missing input.signature_size", fixture.id));
    vec![0u8; size]
}

// ────── Fixture loading ───────────────────────────────────────────────────────

fn fixture_paths() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/validation");
    fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("json")).then_some(path)
        })
        .collect()
}

fn load_fixture(path: &Path) -> ValidationVector {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

// ────── Hex / byte helpers ────────────────────────────────────────────────────

fn parse_root(value: &str) -> Root {
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
