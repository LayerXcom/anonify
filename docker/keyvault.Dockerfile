# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.3 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"

SHELL ["/bin/bash", "-c"]

RUN set -x && \
    rm -rf /root/sgx && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    git clone --depth 1 -b v1.1.3 https://github.com/baidu/rust-sgx-sdk.git sgx

COPY . /root/anonify
WORKDIR /root/anonify

RUN source /opt/sgxsdk/environment && \
    source /root/.cargo/env && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    cd scripts && \
    make ENCLAVE_DIR=example/erc20/enclave ENCLAVE_PKG_NAME=erc20 CARGO_FLAGS=--release && \
    make ENCLAVE_DIR=example/key-vault/enclave ENCLAVE_PKG_NAME=key_vault CARGO_FLAGS=--release && \
    cd ../example/key-vault/server && \
    RUST_BACKTRACE=1 RUST_LOG=debug /root/.cargo/bin/cargo build --release

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.3
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify

RUN cd /root/anonify
COPY --from=builder /root/anonify/config/ias_root_cert.pem ./config/ias_root_cert.pem
COPY --from=builder /root/anonify/.anonify/key_vault.signed.so ./.anonify/key_vault.signed.so
COPY --from=builder /root/anonify/.anonify/erc20_measurement.txt ./.anonify/erc20_measurement.txt
COPY --from=builder /root/anonify/.anonify/key_vault_measurement.txt ./.anonify/key_vault_measurement.txt
COPY --from=builder /root/anonify/target/release/key-vault-server ./target/release/

CMD ["./target/release/key-vault-server"]
