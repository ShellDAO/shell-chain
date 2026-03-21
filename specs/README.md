# shell-chain Implementation Specifications

Index for implementation-level specifications.

> **注意**：协议层面的全网一致性规范（Wire-Level Truth）位于父仓库的 `../../specs/protocol/` 目录。本目录下的规范仅针对 `shell-chain` 的内部工程实现（如 Rust 数据结构映射、验证规则分工等）。
> 任何跨目录的规范链接应使用相对路径 `../../specs/protocol/` 或附带完整的 Repository URL，以避免在 Submodule 独立视角的断链现象。

## Contents

| Spec | Status | Description |
|---|---|---|
| [Crate Structure](crate-structure.md) | stub | Module layout and dependency rules |
| [Data Types](data-types.md) | stub | Core data type definitions |
| [Validation Rules](validation-rules.md) | draft | Block/transaction validation logic (protocol mapping complete) |
| [Testing Vectors](testing-vectors.md) | stub | Reference test vectors and invariants |
