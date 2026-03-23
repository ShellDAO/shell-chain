#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod codec;
pub mod domains;
pub mod errors;
pub mod ssz;
pub mod traits;
pub mod types;
pub mod validation;

pub use crate::domains::{build_signing_data, DomainSelector, DOMAIN_TYPE_WIDTH};
pub use crate::errors::{
    AuthorizationCountError, DomainError, MalformedSszError, PayloadRootMismatchError,
    PrimitiveError, SignatureSizeExceededError, SigningRootConstructionError,
    UnsupportedPayloadVariant,
};
pub use crate::traits::{
    ProtocolObject, StateMetadata, TransactionMetadata, ValidationOutcome, ValidationStage,
};
pub use crate::types::{
    canonicalize_execution_address, Authorization, BasicFeesPerGas, BasicTransactionPayload,
    Bytes31, Bytes32, Bytes4, ChainId, CreateTransactionPayload, ExecutionAddress, GasPrice,
    MockProgressiveByteList, MockProgressiveList, Root, SigningData, StateKey, StateWitness,
    TransactionEnvelope, TransactionPayload, TransactionPayloadSsz, TxValue,
    MOCK_PROGRESSIVE_BYTE_LIST_LIMIT, MOCK_PROGRESSIVE_LIST_LIMIT, U256,
};
pub use crate::validation::{
    check_authorization_count, check_authorization_payload_roots, check_user_signature_size,
    MAX_USER_SIGNATURE_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Existing structural tests (must remain green) ───────────────────────

    #[test]
    fn transaction_payload_tags_match_the_current_spec() {
        let basic = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let create = TransactionPayloadSsz::new(TransactionPayload::Create(
            CreateTransactionPayload::default(),
        ));

        assert_eq!(basic.protocol_tag(), TransactionPayloadSsz::TAG_BASIC);
        assert_eq!(create.protocol_tag(), TransactionPayloadSsz::TAG_CREATE);
    }

    #[test]
    fn address_canonicalization_left_pads_to_bytes32() {
        let address: ExecutionAddress = [0x11; 20];
        let key = canonicalize_execution_address(&address);

        assert_eq!(&key[..12], &[0; 12]);
        assert_eq!(&key[12..], &address);
    }

    #[test]
    fn transaction_domain_tag_remains_explicitly_unfinalized() {
        let err = build_signing_data([0; 32], DomainSelector::TransactionAuthorization)
            .expect_err("domain bytes should stay TODO-shaped until the spec freezes them");

        assert_eq!(err.domain_name, "transaction-authorization");
        assert_eq!(DOMAIN_TYPE_WIDTH, 4);
    }

    // ─── Wire encode / decode (closed rules: tx-basic-valid, tx-create-valid, tx-unknown-tag) ──

    #[test]
    fn basic_payload_round_trips_through_wire_encoding() {
        let original =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                nonce: 42,
                gas_limit: 21_000,
                ..BasicTransactionPayload::default()
            }));
        let wire = original.to_wire_bytes().expect("encode must succeed");
        let decoded = TransactionPayloadSsz::from_wire_bytes(&wire)
            .expect("decode must succeed on valid bytes");
        assert_eq!(original, decoded);
    }

    #[test]
    fn create_payload_round_trips_through_wire_encoding() {
        let original =
            TransactionPayloadSsz::new(TransactionPayload::Create(CreateTransactionPayload {
                nonce: 1,
                gas_limit: 500_000,
                initcode: alloc::vec![0x60, 0x00, 0x60, 0x00, 0x52],
                ..CreateTransactionPayload::default()
            }));
        let wire = original.to_wire_bytes().expect("encode must succeed");
        let decoded = TransactionPayloadSsz::from_wire_bytes(&wire)
            .expect("decode must succeed on valid bytes");
        assert_eq!(original, decoded);
    }

    #[test]
    fn wire_encoding_first_byte_is_the_protocol_tag() {
        let basic = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let create = TransactionPayloadSsz::new(TransactionPayload::Create(
            CreateTransactionPayload::default(),
        ));
        assert_eq!(
            basic.to_wire_bytes().unwrap()[0],
            TransactionPayloadSsz::TAG_BASIC
        );
        assert_eq!(
            create.to_wire_bytes().unwrap()[0],
            TransactionPayloadSsz::TAG_CREATE
        );
    }

    #[test]
    fn unknown_tag_in_wire_bytes_is_rejected() {
        let basic = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let mut wire = basic.to_wire_bytes().unwrap();
        wire[0] = 0xFF;
        let err = TransactionPayloadSsz::from_wire_bytes(&wire)
            .expect_err("unknown tag 0xFF must be rejected");
        assert!(
            matches!(err, PrimitiveError::UnsupportedPayloadVariant(ref e) if e.tag == 0xFF),
            "expected UnsupportedPayloadVariant(0xFF), got {err:?}"
        );
    }

    #[test]
    fn empty_wire_bytes_are_rejected_as_malformed() {
        let err =
            TransactionPayloadSsz::from_wire_bytes(&[]).expect_err("empty bytes must be rejected");
        assert!(matches!(err, PrimitiveError::MalformedSsz(_)));
    }

    #[test]
    fn truncated_wire_bytes_are_rejected_as_malformed() {
        // tag byte only, no payload body
        let truncated = alloc::vec![TransactionPayloadSsz::TAG_BASIC, 0x00, 0x01];
        let err = TransactionPayloadSsz::from_wire_bytes(&truncated)
            .expect_err("truncated payload must be rejected");
        assert!(matches!(err, PrimitiveError::MalformedSsz(_)));
    }

    // ─── hash_tree_root (canonical root calculation) ─────────────────────────

    #[test]
    fn hash_tree_root_is_deterministic() {
        let payload =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                nonce: 7,
                gas_limit: 42_000,
                ..Default::default()
            }));
        let root1 = payload.hash_tree_root().expect("first call must succeed");
        let root2 = payload.hash_tree_root().expect("second call must succeed");
        assert_eq!(root1, root2);
    }

    #[test]
    fn different_payload_variants_have_different_roots() {
        let basic = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let create = TransactionPayloadSsz::new(TransactionPayload::Create(
            CreateTransactionPayload::default(),
        ));
        assert_ne!(
            basic.hash_tree_root().unwrap(),
            create.hash_tree_root().unwrap(),
            "Basic(default) and Create(default) must have distinct roots (different union tags)"
        );
    }

    #[test]
    fn hash_tree_root_changes_when_nonce_changes() {
        let p0 = TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
            nonce: 0,
            ..Default::default()
        }));
        let p1 = TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
            nonce: 1,
            ..Default::default()
        }));
        assert_ne!(p0.hash_tree_root().unwrap(), p1.hash_tree_root().unwrap());
    }

    #[test]
    fn hash_tree_root_changes_when_input_bytes_change() {
        let empty =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                input: alloc::vec![],
                ..Default::default()
            }));
        let non_empty =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                input: alloc::vec![0xDE, 0xAD],
                ..Default::default()
            }));
        assert_ne!(
            empty.hash_tree_root().unwrap(),
            non_empty.hash_tree_root().unwrap()
        );
    }

    // ─── payload_root binding ────────────────────────────────────────────────

    #[test]
    fn payload_root_on_envelope_matches_payload_hash_tree_root() {
        let payload =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                nonce: 99,
                ..Default::default()
            }));
        let envelope = TransactionEnvelope {
            payload: payload.clone(),
            authorizations: alloc::vec![],
        };
        assert_eq!(
            payload.hash_tree_root().unwrap(),
            envelope.payload_root().unwrap(),
            "envelope.payload_root() must equal payload.hash_tree_root()"
        );
    }

    #[test]
    fn authorization_round_trips_through_wire_encoding() {
        let authorization = Authorization {
            scheme_id: 7,
            payload_root: [0xAB; 32],
            signature: alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let wire = crate::codec::encode_authorization(&authorization).expect("encode must succeed");
        let decoded =
            crate::codec::decode_authorization(&wire).expect("decode must succeed on valid bytes");

        assert_eq!(authorization, decoded);
    }

    #[test]
    fn envelope_round_trips_through_wire_encoding() {
        let payload =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                nonce: 42,
                gas_limit: 50_000,
                ..Default::default()
            }));
        let payload_root = payload.hash_tree_root().expect("payload root must exist");
        let envelope = TransactionEnvelope {
            payload,
            authorizations: alloc::vec![
                Authorization {
                    scheme_id: 1,
                    payload_root,
                    signature: alloc::vec![0x11, 0x22],
                },
                Authorization {
                    scheme_id: 2,
                    payload_root,
                    signature: alloc::vec![0x33, 0x44, 0x55],
                },
            ],
        };

        let wire = envelope.to_wire_bytes().expect("encode must succeed");
        let decoded = TransactionEnvelope::from_wire_bytes(&wire)
            .expect("decode must succeed on valid envelope bytes");

        assert_eq!(envelope, decoded);
    }

    #[test]
    fn envelope_root_is_deterministic() {
        let payload =
            TransactionPayloadSsz::new(TransactionPayload::Create(CreateTransactionPayload {
                nonce: 3,
                initcode: alloc::vec![0x60, 0x00],
                ..Default::default()
            }));
        let payload_root = payload.hash_tree_root().expect("payload root must exist");
        let envelope = TransactionEnvelope {
            payload,
            authorizations: alloc::vec![Authorization {
                scheme_id: 9,
                payload_root,
                signature: alloc::vec![0x99; 64],
            }],
        };

        let root1 = envelope
            .canonical_root()
            .expect("first root call must succeed");
        let root2 = envelope
            .canonical_root()
            .expect("second root call must succeed");
        assert_eq!(root1, root2);
    }

    #[test]
    fn envelope_root_changes_when_authorization_signature_changes() {
        let payload = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let payload_root = payload.hash_tree_root().expect("payload root must exist");
        let first = TransactionEnvelope {
            payload: payload.clone(),
            authorizations: alloc::vec![Authorization {
                scheme_id: 3,
                payload_root,
                signature: alloc::vec![0xAA],
            }],
        };
        let second = TransactionEnvelope {
            payload,
            authorizations: alloc::vec![Authorization {
                scheme_id: 3,
                payload_root,
                signature: alloc::vec![0xAA, 0xBB],
            }],
        };

        assert_ne!(
            first.canonical_root().unwrap(),
            second.canonical_root().unwrap()
        );
    }

    // ─── SigningData root ─────────────────────────────────────────────────────

    #[test]
    fn signing_data_hash_tree_root_is_deterministic() {
        let sd = SigningData {
            object_root: [0xAB; 32],
            domain_type: [0x01, 0x00, 0x00, 0x00],
        };
        let root1 = crate::ssz::signing_root(&sd).unwrap();
        let root2 = crate::ssz::signing_root(&sd).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn signing_data_root_changes_when_object_root_changes() {
        let sd1 = SigningData {
            object_root: [0x00; 32],
            domain_type: [0x01, 0x00, 0x00, 0x00],
        };
        let sd2 = SigningData {
            object_root: [0x01; 32],
            domain_type: [0x01, 0x00, 0x00, 0x00],
        };
        assert_ne!(
            crate::ssz::signing_root(&sd1).unwrap(),
            crate::ssz::signing_root(&sd2).unwrap()
        );
    }

    #[test]
    fn signing_data_root_changes_when_domain_type_changes() {
        let sd1 = SigningData {
            object_root: [0xAB; 32],
            domain_type: [0x01, 0x00, 0x00, 0x00],
        };
        let sd2 = SigningData {
            object_root: [0xAB; 32],
            domain_type: [0x02, 0x00, 0x00, 0x00],
        };
        assert_ne!(
            crate::ssz::signing_root(&sd1).unwrap(),
            crate::ssz::signing_root(&sd2).unwrap()
        );
    }

    // ─── Validation helpers ───────────────────────────────────────────────────

    #[test]
    fn empty_authorization_list_fails_count_check() {
        let err = check_authorization_count(&[])
            .expect_err("empty authorizations must fail the closed-rule check");
        assert!(matches!(err, PrimitiveError::AuthorizationCount(ref e) if e.actual == 0));
    }

    #[test]
    fn non_empty_authorization_list_passes_count_check() {
        check_authorization_count(&[Authorization::default()])
            .expect("one authorization must pass the count check");
    }

    #[test]
    fn oversized_signature_is_rejected_on_user_path() {
        let sig = alloc::vec![0u8; MAX_USER_SIGNATURE_BYTES + 1];
        let err =
            check_user_signature_size(&sig).expect_err("signature exceeding 8 KB must be rejected");
        assert!(
            matches!(err, PrimitiveError::SignatureSizeExceeded(ref e) if e.actual_bytes == MAX_USER_SIGNATURE_BYTES + 1)
        );
    }

    #[test]
    fn signature_at_exact_max_size_is_accepted_on_user_path() {
        let sig = alloc::vec![0u8; MAX_USER_SIGNATURE_BYTES];
        check_user_signature_size(&sig).expect("signature at exactly 8 KB must be accepted");
    }

    #[test]
    fn mismatched_payload_root_in_authorization_is_rejected() {
        let payload = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let correct_root = payload.hash_tree_root().unwrap();
        let wrong_root = {
            let mut r = correct_root;
            r[0] ^= 0xFF;
            r
        };
        let auth = Authorization {
            payload_root: wrong_root,
            ..Authorization::default()
        };
        let err = check_authorization_payload_roots(&payload, &[auth])
            .expect_err("mismatched payload_root must be rejected before signature verification");
        assert!(
            matches!(err, PrimitiveError::PayloadRootMismatch(ref e) if e.expected == correct_root),
            "expected PayloadRootMismatch with correct expected root, got {err:?}"
        );
    }

    #[test]
    fn matching_payload_root_in_authorization_passes_check() {
        let payload = TransactionPayloadSsz::new(TransactionPayload::Basic(
            BasicTransactionPayload::default(),
        ));
        let root = payload.hash_tree_root().unwrap();
        let auth = Authorization {
            payload_root: root,
            ..Authorization::default()
        };
        check_authorization_payload_roots(&payload, &[auth])
            .expect("authorization with correct payload_root must pass");
    }
}
