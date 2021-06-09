use frame_common::{state_types::StateType, EnclaveInput, EnclaveOutput};
use frame_runtime::ContextOps;
use serde::{de::DeserializeOwned, Serialize};

use super::{mk_input_ecall_entry_point, mk_output_ecall_entry_point};

pub trait StateRuntimeEnclaveUseCase<'c, C>: Sized
where
    C: ContextOps<S = StateType> + Clone,
{
    type EI: EnclaveInput + DeserializeOwned;
    type EO: EnclaveOutput + Serialize;

    /// Use the same ID with EcallController.
    const ENCLAVE_USE_CASE_ID: u32;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self>;

    /// Evaluate policies like authentication and idempotency
    fn eval_policy(&self) -> anyhow::Result<()>;

    fn run(self) -> anyhow::Result<Self::EO>;

    fn ecall_entry_point(
        input_buf: *mut u8,
        input_len: usize,
        output_buf: *mut u8,
        ecall_max_size: usize,
        output_len: &mut usize,
        enclave_context: &'c C,
    ) -> anyhow::Result<frame_types::EnclaveStatus> {
        let enclave_input = mk_input_ecall_entry_point(input_buf, input_len, ecall_max_size)?;
        let slf = Self::new(enclave_input, enclave_context)?;
        let enclave_output = slf.run()?;
        mk_output_ecall_entry_point(enclave_output, output_buf, ecall_max_size, output_len)
    }
}
