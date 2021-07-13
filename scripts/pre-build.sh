#!/bin/bash

set -e

export PATH=~/.cargo/bin:$PATH
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

echo 'build frame/types...'
cd ${ANONIFY_ROOT}/frame/types
cargo build

echo 'build Anonify_common_t.o'
cd ${ANONIFY_ROOT}/scripts
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave ENCLAVE_PKG_NAME=erc20 ../build/Anonify_common_t.o
make DEBUG=1 TEST=1 ENCLAVE_DIR=example/erc20/enclave ENCLAVE_PKG_NAME=erc20 ../build/Anonify_test_t.o
