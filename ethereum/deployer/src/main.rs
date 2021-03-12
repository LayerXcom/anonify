use eth_deployer::EthDeployer;
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_BIN_PATH, CREATE2_ABI_PATH, CREATE2_BIN_PATH};
use std::{env, str::FromStr};

const GAS: u64 = 5_000_000;

#[tokio::main]
async fn main() {
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let account_index = env::var("ACCOUNT_INDEX")
        .unwrap_or_else(|_| "0".to_string())
        .parse::<usize>()
        .unwrap();
    let password = env::var("PASSWORD").ok();
    let confirmations = env::var("CONFIRMATIONS")
        .expect("CONFIRMATIONS is not set")
        .parse::<usize>()
        .expect("Failed to parse CONFIRMATIONS to usize");
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 2 || args.len() == 3);

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer
        .get_account(account_index, password.as_deref())
        .await
        .unwrap();

    match args[1].as_str() {
        "create2" => {
            let contract_address = deployer
                .deploy(
                    &*CREATE2_ABI_PATH,
                    &*CREATE2_BIN_PATH,
                    confirmations,
                    GAS,
                    signer,
                )
                .await
                .unwrap();
            println!("{:x}", contract_address);
        }
        contract_address if web3::types::Address::from_str(contract_address).is_ok() => {
            let create2_address = web3::types::Address::from_str(contract_address).unwrap();
            let mut salt = [0u8; 32];
            if args.len() == 3 {
                let vec = hex::decode(&args[2]).unwrap();
                assert_eq!(vec.len(), 32);
                salt.copy_from_slice(&vec[..]);
            }

            let tx_hash = deployer
                .deploy_anonify_by_create2(&*CREATE2_ABI_PATH, signer, GAS, salt, create2_address)
                .await
                .unwrap();
            println!("tx_hash: {:x}", tx_hash);
        }
        _ => panic!("Invalid arguments"),
    };
}
