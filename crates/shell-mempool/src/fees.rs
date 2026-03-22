use core::cmp::Ordering;

use shell_primitives::{BasicFeesPerGas, GasPrice, TransactionEnvelope, TransactionPayload, U256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeLane {
    Payload,
    Witness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeeSchedule {
    pub payload_lane_base_fee: GasPrice,
    pub witness_lane_base_fee: GasPrice,
}

pub fn payload_lane_fee(envelope: &TransactionEnvelope) -> GasPrice {
    transaction_fees(envelope).regular
}

pub fn witness_lane_fee(envelope: &TransactionEnvelope) -> GasPrice {
    transaction_fees(envelope).max_witness_priority_fee
}

pub fn gas_price_covers(actual: GasPrice, required: GasPrice) -> bool {
    compare_u256(&actual.0, &required.0) != Ordering::Less
}

fn transaction_fees(envelope: &TransactionEnvelope) -> &BasicFeesPerGas {
    match envelope.payload.payload() {
        TransactionPayload::Basic(payload) => &payload.fees,
        TransactionPayload::Create(payload) => &payload.fees,
    }
}

fn compare_u256(left: &U256, right: &U256) -> Ordering {
    for (left_byte, right_byte) in left.0.iter().rev().zip(right.0.iter().rev()) {
        match left_byte.cmp(right_byte) {
            Ordering::Equal => continue,
            ordering => return ordering,
        }
    }

    Ordering::Equal
}
