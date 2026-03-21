# Testing Vectors

> Reference test vectors and invariants for shell-chain validation.

## Status: STUB

## Purpose

Define canonical test vectors, invariant assertions, and example transactions/states that implementations must pass.

## Research Source

- `research/docs/target-chain/testing-invariants-vectors.md`

## 模块测试边界划分 (Validation Responsibility)

在实现具体的测试向量前，各 Crate 应明确验收边界：
- **`shell-primitives`**: 负责底层 Transaction/Block/Witness 结构的 SSZ 序列化/边界处理机制。
- **`shell-crypto`**: 负责各 Signature Scheme 的哈希定轨与边界向量测试。
- **`shell-state`**: 负责 Unified Binary Tree 的 `StatePatch` 无状态变迁与不变量 (Invariants) 校验。
- **`shell-consensus`**: 负责 Block Header 与 Sidecar 绑定的逻辑验证（对应 Rule 2 & 3）。

## Sections (TODO)

- [ ] Transaction serialization/deserialization vectors
- [ ] Signature verification vectors
- [ ] Block validation vectors
- [ ] State transition invariants
- [ ] Edge case and failure mode vectors
