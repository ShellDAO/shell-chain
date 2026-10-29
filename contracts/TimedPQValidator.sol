// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./DefaultPQValidator.sol";

/// @notice Owner-bound ML-DSA validation that unlocks at a chain timestamp.
/// @dev Every operation using this policy, including clearing the policy, is
/// rejected before unlockTime. The deadline and authorized key are immutable.
contract TimedPQValidator is IAccountValidator {
    uint256 public immutable unlockTime;
    DefaultPQValidator public immutable verifier;

    constructor(bytes memory ownerPubkey, uint256 unlockTime_) {
        unlockTime = unlockTime_;
        verifier = new DefaultPQValidator(ownerPubkey);
    }

    function validateTransaction(
        bytes32 txHash,
        bytes calldata sig,
        bytes calldata pubkey
    ) external view override returns (bytes1) {
        if (block.timestamp < unlockTime) return 0x00;
        return verifier.validateTransaction(txHash, sig, pubkey);
    }
}
