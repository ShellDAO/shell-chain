// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IAccountValidator {
    function validateTransaction(
        bytes32 txHash,
        bytes calldata sig,
        bytes calldata pubkey
    ) external view returns (bytes1);
}

/// @title DefaultPQValidator
/// @notice Reference AA validator that mirrors Shell-Chain's built-in
/// ML-DSA-65 verification with an explicitly configured owner public key.
/// @dev Calls the Shell-Chain ML-DSA-65 precompile at 0x0001 using the native
/// length-prefixed wire format:
/// [4-byte pubkey length][pubkey][4-byte message length][32-byte tx hash][sig]
contract DefaultPQValidator is IAccountValidator {
    address internal constant ML_DSA_65_VERIFY = address(0x0001);
    address internal constant BLAKE3_256 = address(0x0004);
    bytes32 public immutable ownerPubkeyHash;

    /// Deploy with the public key authorized to control accounts using this policy.
    /// AccountManager key rotation preserves custom policy; replace this instance
    /// explicitly when changing the policy key.
    constructor(bytes memory ownerPubkey) {
        require(ownerPubkey.length != 0, "empty owner public key");
        (bool ok, bytes memory output) = BLAKE3_256.staticcall(ownerPubkey);
        require(ok && output.length == 32, "owner key hash unavailable");
        ownerPubkeyHash = abi.decode(output, (bytes32));
    }

    function validateTransaction(
        bytes32 txHash,
        bytes calldata sig,
        bytes calldata pubkey
    ) external view override returns (bytes1) {
        (bool hashOk, bytes memory hashOutput) = BLAKE3_256.staticcall(pubkey);
        if (!hashOk || hashOutput.length != 32 ||
            abi.decode(hashOutput, (bytes32)) != ownerPubkeyHash) {
            return 0x00;
        }

        bytes memory input = abi.encodePacked(
            uint32(pubkey.length),
            pubkey,
            uint32(32),
            txHash,
            sig
        );

        (bool ok, bytes memory output) = ML_DSA_65_VERIFY.staticcall(input);
        if (!ok || output.length < 32) {
            return 0x00;
        }

        return output[31] == 0x01 ? bytes1(0x01) : bytes1(0x00);
    }
}
