//! Definitions of events from blockchain nodes.

use ethabi::{Event, EventParam, Hash, ParamType};
use once_cell::sync::Lazy;

pub static STORE_TREEKEM_CIPHERTEXT_EVENT: Lazy<Hash> = Lazy::new(|| {
    Event {
        name: "StoreTreeKemCiphertext".to_owned(),
        inputs: vec![
            EventParam {
                name: "ciphertext".to_owned(),
                kind: ParamType::Bytes,
                indexed: true,
            },
            EventParam {
                name: "stateCounter".to_owned(),
                kind: ParamType::Uint(256),
                indexed: true,
            },
            EventParam {
                name: "_traceId".to_owned(),
                kind: ParamType::FixedBytes(16),
                indexed: true,
            },
        ],
        anonymous: false,
    }
    .signature()
});

pub static STORE_TREEKEM_HANDSHAKE_EVENT: Lazy<Hash> = Lazy::new(|| {
    Event {
        name: "StoreTreeKemHandshake".to_owned(),
        inputs: vec![
            EventParam {
                name: "handshake".to_owned(),
                kind: ParamType::Bytes,
                indexed: true,
            },
            EventParam {
                name: "stateCounter".to_owned(),
                kind: ParamType::Uint(256),
                indexed: true,
            },
            EventParam {
                name: "_traceId".to_owned(),
                kind: ParamType::FixedBytes(16),
                indexed: true,
            },
        ],
        anonymous: false,
    }
    .signature()
});

pub static STORE_ENCLAVE_KEY_CIPHERTEXT_EVENT: Lazy<Hash> = Lazy::new(|| {
    Event {
        name: "StoreEnclaveKeyCiphertext".to_owned(),
        inputs: vec![
            EventParam {
                name: "ciphertext".to_owned(),
                kind: ParamType::Bytes,
                indexed: true,
            },
            EventParam {
                name: "stateCounter".to_owned(),
                kind: ParamType::Uint(256),
                indexed: true,
            },
            EventParam {
                name: "_traceId".to_owned(),
                kind: ParamType::FixedBytes(16),
                indexed: true,
            },
        ],
        anonymous: false,
    }
    .signature()
});
