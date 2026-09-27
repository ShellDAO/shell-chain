// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface INativeRegistryView {
    function getValidators() external view returns (bytes32[] memory);
    function isValidator(bytes32 account) external view returns (bool);
}

contract ValidatorCheck {
    // The native Registry view is separate from PQ verification at address 1.
    INativeRegistryView constant REGISTRY = INativeRegistryView(address(uint160(0x100000001)));

    function currentValidators() external view returns (bytes32[] memory) {
        return REGISTRY.getValidators();
    }

    function isActiveValidator(bytes32 account) external view returns (bool) {
        return REGISTRY.isValidator(account);
    }
}
