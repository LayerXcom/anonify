use std::{sync::Arc, io, env};
use sgx_types::sgx_enclave_id_t;
use anonify_eth_driver::{
    Dispatcher,
    EventDB, BlockNumDB,
    traits::*,
    eth::*,
};
use frame_host::EnclaveDir;
use handlers::*;
use actix_web::{web, App, HttpServer};
use web3::types::Address;
use crate::store_path_secrets::StorePathSecrets;

mod handlers;
mod store_path_secrets;

#[derive(Debug)]
pub struct Server<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub bin_path: String,
    pub confirmations: usize,
    pub account_index: usize,
    pub password: String,
    pub store_path_secrets: StorePathSecrets,
    pub dispatcher: Dispatcher<D, S, W, DB>,
}

impl<D, S, W, DB> Server<D, S, W, DB>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
        let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
        let bin_path = env::var("BIN_PATH").expect("BIN_PATH is not set");
        let account_index: usize = env::var("ACCOUNT_INDEX")
            .expect("ACCOUNT_INDEX is not set")
            .parse()
            .expect("Failed to parse ACCOUNT_INDEX to usize");
        let password = env::var("PASSWORD").expect("PASSWORD is not set");
        let confirmations: usize = env::var("CONFIRMATIONS")
            .expect("CONFIRMATIONS is not set")
            .parse()
            .expect("Failed to parse ACCOUNT_INDEX to usize");

        let store_path_secrets = StorePathSecrets::new();
        let event_db = Arc::new(DB::new());
        let dispatcher = Dispatcher::<D,S,W,DB>::new(eid, &eth_url, event_db).unwrap();

        Server {
            eid,
            eth_url,
            abi_path,
            bin_path,
            confirmations,
            account_index,
            password,
            store_path_secrets,
            dispatcher,
        }
    }
}

fn main() -> io::Result<()> {
    env_logger::init();
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
            .init_enclave(true)
            .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(
        Server::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid)
    );

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/api/v1/deploy", web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/join_group", web::post().to(handle_join_group::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/init_state", web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/transfer", web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/approve", web::post().to(handle_approve::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/transfer_from", web::post().to(handle_transfer_from::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/mint", web::post().to(handle_mint::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/burn", web::post().to(handle_burn::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/allowance", web::get().to(handle_allowance::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/balance_of", web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/start_sync_bc", web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/set_contract_addr", web::get().to(handle_set_contract_addr::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/register_notification", web::post().to(handle_register_notification::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
    })
    .bind(anonify_url)?
    .run()
}
