#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
ANONIFY_ROOT=/root/anonify

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
solc -o contract-build --bin --abi --optimize --overwrite ethereum/contracts/Anonify.sol ethereum/contracts/Factory.sol

cd frame/types
cargo build

# Generate each signed.so and measurement.txt

echo "Integration testing..."
cd ${ANONIFY_ROOT}/scripts
unset BACKUP
export ENCLAVE_PKG_NAME=key_vault
make DEBUG=1 ENCLAVE_DIR=example/key-vault/enclave
export BACKUP=disable
export ENCLAVE_PKG_NAME=erc20
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave

#
# Integration Tests
#

# Module Tests

cd ${ANONIFY_ROOT}/tests/integration
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -- --nocapture

# Deploy a FACTORY Contract
cd ${ANONIFY_ROOT}/ethereum/deployer
FACTORY_CONTRACT_ADDRESS=`cargo run factory`

# ERC20 Application Tests

cd ${ANONIFY_ROOT}/ethereum/deployer
cargo run $FACTORY_CONTRACT_ADDRESS
cd ${ANONIFY_ROOT}/nodes/state-runtime/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_evaluate_access_policy_by_user_id_field -- --nocapture  -- SALT
sleep 1

cd ${ANONIFY_ROOT}/ethereum/deployer
cargo run $FACTORY_CONTRACT_ADDRESS
cd ${ANONIFY_ROOT}/nodes/state-runtime/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_multiple_messages -- --nocapture -- SALT
sleep 1

cd ${ANONIFY_ROOT}/ethereum/deployer
cargo run $FACTORY_CONTRACT_ADDRESS
cd ${ANONIFY_ROOT}/nodes/state-runtime/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_skip_invalid_event -- --nocapture -- SALT
sleep 1

cd ${ANONIFY_ROOT}/ethereum/deployer
cargo run $FACTORY_CONTRACT_ADDRESS
cd ${ANONIFY_ROOT}/nodes/state-runtime/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_node_recovery -- --nocapture -- SALT
sleep 1

cd ${ANONIFY_ROOT}/ethereum/deployer
cargo run $FACTORY_CONTRACT_ADDRESS
cd ${ANONIFY_ROOT}/nodes/state-runtime/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_join_group_then_handshake -- --nocapture -- SALT
sleep 1

cd ${ANONIFY_ROOT}/ethereum/deployer
cargo run $FACTORY_CONTRACT_ADDRESS
cd ${ANONIFY_ROOT}/nodes/state-runtime/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_duplicated_out_of_order_request_from_same_user -- --nocapture -- SALT

# Secret Backup Application Tests

cd ${ANONIFY_ROOT}/scripts
unset BACKUP
export ENCLAVE_PKG_NAME=erc20
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave

cd ${ANONIFY_ROOT}/nodes/key-vault
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_backup_path_secret -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_recover_without_key_vault -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_manually_backup_all -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_manually_recover_all -- --nocapture

#
# Unit Tests
#

echo "Unit testing..."
export ENCLAVE_PKG_NAME=units
export BACKUP=disable
cd ${ANONIFY_ROOT}/scripts
make DEBUG=1 TEST=1 ENCLAVE_DIR=tests/units/enclave

cd ${ANONIFY_ROOT}
RUST_BACKTRACE=1 RUST_LOG=debug TEST=1 cargo test \
  -p unit-tests-host \
  -p frame-runtime \
  -p frame-retrier \
  -p frame-sodium -- --nocapture

#
# Compile Checks
#

./scripts/build-cli.sh
cd ${ANONIFY_ROOT}/example/erc20/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo c
cd ${ANONIFY_ROOT}/example/key-vault/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo c
cd ${ANONIFY_ROOT}/example/wallet
RUST_BACKTRACE=1 RUST_LOG=debug cargo c
