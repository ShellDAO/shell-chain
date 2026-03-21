# Validation Rules

> Implementation specification for block and transaction validation in shell-chain.

## Status: DRAFT (protocol mapping complete; pipeline details TODO)

## Purpose

Define the validation logic implementation: ordering of checks, error types, and the relationship between protocol-level rules and Rust code.

## 1. Error Type Taxonomy

- `SidecarMismatchError(ExpectedRoot, ActualRoot)`: 侧车承诺校验失败。
- `WitnessSizeExceededError(MaxSize, ActualSize)`: 见证文件体积超限 (对应 TCP-001 8KB 上界)。

## 2. 协议层规则映射 (Protocol Rule Mapping)

*   **Rule 1: Header Stateless Check**
    *   **职责范围**: 区块接收时的前置检查（提取 Header 后核实 `witness_bytes`）
    *   **负责模块**: `shell-consensus` 或 `shell-network` (具体须视 crate 边界权责而定)
*   **Rule 2: Header/Body Binding Check**
    *   **负责模块**: `shell-consensus`
*   **Rule 3: Sidecar Matching Check**
    *   **负责模块**: `shell-consensus`
*   **Rule 4: Stateless Execution Check**
    *   **负责模块**: `shell-execution`

## Sections (TODO)

- [ ] Transaction validation pipeline
- [ ] Block validation pipeline
- [ ] Signature verification dispatch
- [ ] Validation ordering constraints
