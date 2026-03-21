# Crate Structure & Module Boundaries

> 规范 `shell-chain` Rust 源码实现的工作区 (Workspace) 拓扑结构与依赖管理。

## 1. 原则 (Design Principles)
- **无状态验证优先**: 数据结构 (Primitives) 必须与网络栈 (Networking) 和共识执行 (Consensus execution) 物理隔离，确保轻客户端可用极简依赖编译。
- **协议映射**: 必须严格映射 `../../specs/protocol/` 下的业务边界。
- **接口防腐**: PQ 密码学库的变化不应影响 `shell-state` 和 `shell-mempool`，通过统一的 Trait 进行隔离。

## 2. 工作区 (Workspace) 拓扑

```text
shell-chain/
├── crates/
│   ├── shell-primitives/  # 底层基础：SSZ 派生、U256/H256、Block/Tx 数据体声明
│   ├── shell-crypto/      # 密码学隔离：PQ 签名包装 (ML-DSA 等)、SHA-256 统一定义
│   ├── shell-state/       # 状态层：统一二叉状态树 (Unified Binary Tree) 的实现
│   ├── shell-execution/   # 执行引擎：EVM 兼容层交互、计价模型、状态流转
│   ├── shell-mempool/     # 内存池：基于 Sidecar 分离原则的交易缓冲与准入规则
│   ├── shell-consensus/   # 共识控制：信包 (Envelope) 与 Sidecar 的生命周期管理
│   ├── shell-network/     # P2P 层：Gossipsub 传播、节点发现、Sidecar 同步
│   └── shell-cli/         # 入口程序：节点启动，RPC 注册
```

## 3. 跨模块协作契约
- `shell-primitives` 是所有其他模块的基础。**绝对禁止** `primitives` 反向依赖 `state` 或 `consensus`。
- `shell-mempool` 只依赖 `primitives` 和 `crypto`。它不应当直接拉取 `state` 的完整实现，而应通过 `trait StateReader` 请求无状态验证接口。
- `ExecutionWitnessSidecar` 的组装是在 `shell-execution` 完成后，由 `shell-consensus` 负责配对并向下传递给 `shell-network` 进行传播。

## 4. 第三方关键依赖约束
由于 ADR-004 和 ADR-005 的锁定，以下第三方库需要在 `Cargo.toml` 工作区全局控制：
- **SSZ**: `ssz_rs` (或与其等效的 Lighthouse/Ethereum 官方宏)，严格控制派生。
- **Hash**: 统一依赖性能最高的 `sha2` (纯 Rust 实现或搭配 SIMD 加速)，隔离所有遗留的 `keccak` （仅在智能合约内部哈希时保留）。
- **PQ Signatures**: 等待密码学套件提供符合 `shell-crypto` Trait 的绑定。
