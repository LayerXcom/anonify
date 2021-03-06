use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use web3::types::Address as ContractAddr;

type BlockNum = u64;

/// Cache data from events for arrival guarantee and order guarantee.
/// Unordered events are cached.
#[derive(Debug, Default, Clone)]
pub struct EventCache {
    inner: Arc<RwLock<InnerEventCache>>,
}

impl EventCache {
    pub fn inner(&self) -> &Arc<RwLock<InnerEventCache>> {
        &self.inner
    }
}

/// Do not implement `Clone` trait due to cache duplication.
#[derive(Debug, Default)]
pub struct InnerEventCache {
    block_num_counter: HashMap<ContractAddr, BlockNum>,
}

impl InnerEventCache {
    pub fn insert_next_block_num(
        &mut self,
        contract_addr: ContractAddr,
        block_num: BlockNum,
    ) -> Option<BlockNum> {
        debug!("Insert: Cached block number: {}", block_num);
        self.block_num_counter.insert(contract_addr, block_num)
    }

    pub fn get_latest_block_num(&self, contract_addr: ContractAddr) -> Option<BlockNum> {
        let block_num = self.block_num_counter.get(&contract_addr).copied();
        debug!("Get: Cached block number: {:?}", block_num);
        block_num
    }
}
