//! Encryption / Decryption for [encrypted-sql-ops-ecall-types::enc_type](encrypted-sql-ops-ecall-types::enc_type).

// 128-bit key
// TODO: Generate inside enclave or acquire from sealed one.
const MASTER_KEY: [u8; 16] = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

mod pad16bytes_crypt;

pub(crate) use pad16bytes_crypt::{Pad16BytesDecrypt, Pad16BytesEncrypt};
