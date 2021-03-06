use anonify_ecall_types::cmd::*;
use anonify_eth_driver::{Dispatcher, EventCache};
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_BIN_PATH, FACTORY_ABI_PATH};
use sgx_types::sgx_enclave_id_t;
use std::{env, str::FromStr};
use web3::types::Address;

mod error;
pub mod handlers;
#[cfg(test)]
mod test;

const DEFAULT_GAS: u64 = 5_000_000;

#[derive(Debug, Clone)]
pub struct Server {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub bin_path: String,
    pub sender_address: Address,
    pub dispatcher: Dispatcher,
    pub cmd_encryption_algo: CmdEncryptionAlgo,
    pub instance_id: String,
}

impl Server {
    pub async fn new(eid: sgx_enclave_id_t) -> Self {
        let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
        let account_index: usize = env::var("ACCOUNT_INDEX")
            .expect("ACCOUNT_INDEX is not set")
            .parse()
            .expect("Failed to parse ACCOUNT_INDEX to usize");
        let password: Option<String> = env::var("PASSWORD").ok();
        let confirmations: usize = env::var("CONFIRMATIONS")
            .expect("CONFIRMATIONS is not set")
            .parse()
            .expect("Failed to parse CONFIRMATIONS to usize");
        let factory_contract_address = Address::from_str(
            &env::var("FACTORY_CONTRACT_ADDRESS").expect("FACTORY_CONTRACT_ADDRESS is not set"),
        )
        .unwrap();
        let instance_id = env::var("MY_ROSTER_IDX").expect("MY_ROSTER_IDX is not set");

        let cache = EventCache::default();
        let dispatcher = Dispatcher::new(eid, &eth_url, confirmations, cache, &instance_id)
            .set_anonify_contract_address(
                &*FACTORY_ABI_PATH,
                factory_contract_address,
                &*ANONIFY_ABI_PATH,
            )
            .await
            .unwrap();

        let sender_address = dispatcher
            .get_account(account_index, password.as_deref())
            .await
            .unwrap();

        Server {
            eid,
            eth_url,
            abi_path: (&*ANONIFY_ABI_PATH.to_str().unwrap()).to_string(),
            bin_path: (&*ANONIFY_BIN_PATH.to_str().unwrap()).to_string(),
            sender_address,
            dispatcher,
            cmd_encryption_algo: CmdEncryptionAlgo::EnclaveKey,
            instance_id,
        }
    }

    pub fn use_treekem(mut self) -> Self {
        self.cmd_encryption_algo = CmdEncryptionAlgo::TreeKem;
        self
    }

    pub async fn run(mut self) -> Self {
        let sync_time: u64 = env::var("SYNC_BC_TIME")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .expect("Failed to parse SYNC_BC_TIME to u64");

        let dispatcher = match self.cmd_encryption_algo {
            CmdEncryptionAlgo::EnclaveKey => self
                .dispatcher
                .run(
                    sync_time,
                    self.sender_address,
                    DEFAULT_GAS,
                    FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD,
                    None,
                    JOIN_GROUP_ENCLAVE_KEY_CMD,
                )
                .await
                .unwrap()
                .set_healthy(),
            CmdEncryptionAlgo::TreeKem => self
                .dispatcher
                .run(
                    sync_time,
                    self.sender_address,
                    DEFAULT_GAS,
                    FETCH_CIPHERTEXT_TREEKEM_CMD,
                    Some(FETCH_HANDSHAKE_TREEKEM_CMD),
                    JOIN_GROUP_TREEKEM_CMD,
                )
                .await
                .unwrap()
                .set_healthy(),
        };

        self.dispatcher = dispatcher;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CmdEncryptionAlgo {
    EnclaveKey,
    TreeKem,
}
