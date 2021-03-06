//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use super::host_types::{HostEncAvgStateWithNext, HostOutputEncAvgState};
use frame_host::ecall_controller::EcallController;
use module_encrypted_sql_ops_ecall_types::enclave_types::{
    EnclaveEncAvgState, EnclaveEncAvgStateWithNext,
};

/// State function of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct EncIntegerAvgStateFuncController;

impl EcallController for EncIntegerAvgStateFuncController {
    type HI = HostEncAvgStateWithNext;
    type EI = EnclaveEncAvgStateWithNext;
    type EO = EnclaveEncAvgState;
    type HO = HostOutputEncAvgState;
    const EI_MAX_SIZE: usize = 256;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(host_input.into())
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(enclave_output.into())
    }
}
