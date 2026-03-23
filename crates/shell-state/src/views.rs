use shell_primitives::{ExecutionAddress, StateMetadata, U256};

pub trait ReadOnlyStateView {
    fn account_nonce(&self, address: &ExecutionAddress) -> Option<u64>;
    fn account_balance(&self, address: &ExecutionAddress) -> Option<U256>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataAdapter<V> {
    inner: V,
}

impl<V> MetadataAdapter<V> {
    pub fn new(inner: V) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &V {
        &self.inner
    }

    pub fn into_inner(self) -> V {
        self.inner
    }
}

impl<V> StateMetadata for MetadataAdapter<V>
where
    V: ReadOnlyStateView,
{
    fn account_nonce(&self, address: &ExecutionAddress) -> Option<u64> {
        self.inner.account_nonce(address)
    }

    fn account_balance(&self, address: &ExecutionAddress) -> Option<U256> {
        self.inner.account_balance(address)
    }
}
