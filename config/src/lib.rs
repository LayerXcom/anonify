#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![allow(unused_imports)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(feature = "sgx")]
use anyhow_sgx as local_anyhow;
#[cfg(feature = "std")]
use anyhow_std as local_anyhow;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as local_serde;
#[cfg(feature = "std")]
use serde_std as local_serde;
#[macro_use]
extern crate lazy_static;

use crate::local_anyhow::Result;
use crate::localstd::{env, ffi::OsStr, path::PathBuf, string::String, vec::Vec};

#[cfg(feature = "sgx")]
lazy_static! {
    pub static ref IAS_ROOT_CERT: Vec<u8> = {
        let ias_root_cert = include_bytes!("../ias_root_cert.pem");
        let pem = pem::parse(ias_root_cert).expect("Cannot parse PEM File");
        pem.contents
    };
}
