mod basic_enclave_use_case;
mod state_runtime_enclave_use_case;

pub use basic_enclave_use_case::BasicEnclaveUseCase;
use frame_types::EnclaveStatus;
use serde::{de::DeserializeOwned, Serialize};
pub use state_runtime_enclave_use_case::StateRuntimeEnclaveUseCase;

use anyhow::anyhow;
use bincode::Options;
use log::{error, debug};
use std::{format, ptr};

fn mk_input_ecall_entry_point<EI>(
    input_buf: *mut u8,
    input_len: usize,
    ecall_max_size: usize,
) -> anyhow::Result<EI>
where
    EI: DeserializeOwned,
{
    let input_payload = unsafe { std::slice::from_raw_parts_mut(input_buf, input_len) };
    bincode::DefaultOptions::new()
        .with_limit(ecall_max_size as u64)
        .deserialize(&input_payload[..])
        .map_err(|e| anyhow!("{:?}", e))
}

fn mk_output_ecall_entry_point<EO>(
    enclave_output: EO,
    output_buf: *mut u8,
    ecall_max_size: usize,
    output_len: &mut usize,
) -> anyhow::Result<EnclaveStatus>
where
    EO: Serialize,
{
    let ser_out = bincode::serialize(&enclave_output)?;

    let ser_out_len = ser_out.len();
    debug!("##### ser_out_len: {:?}", ser_out_len);
    *output_len = ser_out_len;

    if ser_out_len > ecall_max_size {
        error!(
            "Result buffer length is over ecall_max_size: ecall_max_size={}, res_len={}",
            ecall_max_size, ser_out_len
        );
        Ok(frame_types::EnclaveStatus::error())
    } else {
        unsafe {
            ptr::copy_nonoverlapping(ser_out.as_ptr(), output_buf, ser_out_len);
        }
        Ok(frame_types::EnclaveStatus::success())
    }
}
