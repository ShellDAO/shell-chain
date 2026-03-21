# Data Types (Rust API Mapping)

> **Non-Normative Binding**: 本文档仅规定 `shell-chain` 的内部 Rust API 与 Trait 映射。有关链上数据结构的绝对通信规范依据（Wire-Level Truth），请参阅 `../../specs/protocol/` (如 `transaction-format.md`)。

## 1. 领域驱动的语义类型映射
不再穿透底层 `ssz_rs` 容器，而是用强类型的 Rust 结构体安全包裹，并赋予必须的派生约束：

```rust
use ssz_rs::prelude::*;

// 从字节别名为语义化指针
pub type Root = Vector<u8, 32>;
pub type Bytes32 = Vector<u8, 32>;
pub type ExecutionAddress = Vector<u8, 20>;

// 防出错模型 (明确要求派生 SimpleSerialize)
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct ChainId(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct TxValue(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct GasPrice(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct BasicFeesPerGas {
    pub regular: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub max_witness_priority_fee: GasPrice,
}

// ==========================================
// ⚠️ IMPLEMENTATION PLACEHOLDER (Mock)
// ==========================================
// 协议规范要求这里是 EIP-7688 定义的 Progressive 结构。
// 在当前客户端暂缺原生 Progressive 支持时，使用带 Mock 前缀的有限 List 进行模拟。
// 任何依赖于此处具体边界值的准入或计费策略均视为实现 Bug，不等同于协议最终 merkleization。
// 参见 `../../specs/protocol/transaction-format.md` 第 1 节 Mock 纪律约束
pub type MockProgressiveByteList = List<u8, 1048576>;
pub type MockProgressiveList<T> = List<T, 8192>;     
```

## 2. Crate 级交易结构的承接

通过 Rust API 承接 `Protocol SSZ Schema`：

```rust
#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct BasicTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub to: ExecutionAddress,
    pub value: TxValue,
    pub input: MockProgressiveByteList, 
    pub access_commitment: Root, 
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct CreateTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub value: TxValue,
    pub initcode: MockProgressiveByteList,
    pub access_commitment: Root,
}

// SSZ 编码契约落实点：
// Rust Enum 默认并不等同于 SSZ Union。此处的实现必须提供定制的 wrapper 
// 或专属 derive，以确保其在线缆层面产生符合 EIP-6493 的 CompatibleUnion 布局。
// Tag 映射必须刚性锁定：0 => Basic, 1 => Create。严禁重排。
#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub enum TransactionPayload {
    Basic(BasicTransactionPayload),
    Create(CreateTransactionPayload),
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct Authorization {
    pub scheme_id: u8,
    pub payload_root: Root,
    pub signature: MockProgressiveByteList,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct TransactionEnvelope {
    pub payload: TransactionPayload,
    pub authorizations: MockProgressiveList<Authorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct SigningData {
    pub object_root: Root,
    pub domain_type: Bytes32,
}
```

## 3. State 层 API Boundaries (`shell-state`)

```rust
pub enum StateKey {
    AccountHeader(ExecutionAddress),
    StorageSlot { address: ExecutionAddress, slot: Bytes32 },
    CodeChunk { address: ExecutionAddress, chunk_index: u32 },
    RawTreeKey(Bytes32),
    Stem(Bytes31), 
}

/// 全局唯一地址规范化出口。
/// Rust 实现层必须且仅能调用此函数将 20 字节 ExecutionAddress 转为 32 字节树键。
/// 算法: Left-pad with 12 zero bytes.
pub fn canonicalize_execution_address(addr: &ExecutionAddress) -> Bytes32 {
    let mut key = Bytes32::default();
    key[12..32].copy_from_slice(addr.as_ref());
    key
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct StateWitness {
    pub key: StateKey,
    pub leaf_value: MockProgressiveByteList,
    pub proof: MockProgressiveList<Bytes32>, // Schema 以 protocol 为准
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct StatePatch {
    pub accesses: MockProgressiveList<StateKey>,
    pub new_values: MockProgressiveList<MockProgressiveByteList>,
}

pub trait StateAccumulator {
    fn get_witness_for_accesses(&self, accesses: &[StateKey]) -> Result<Vec<StateWitness>, StateError>;
    
    fn apply_transition(&mut self, patch: StatePatch) -> Result<Root, StateError>;
    
    /// 提取实际逻辑上的“状态累加器根”，区分于对象层面的 hash_tree_root
    fn state_root(&self) -> Root;
}
```
