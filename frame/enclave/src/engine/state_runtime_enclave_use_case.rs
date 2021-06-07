use frame_common::{state_types::StateType, EnclaveInput, EnclaveOutput};
use frame_runtime::{ContextOps, RuntimeExecutor};
use serde::{de::DeserializeOwned, Serialize};

pub trait StateRuntimeEnclaveUseCase: Sized + Default {
    type EI: EnclaveInput + DeserializeOwned + Default;
    type EO: EnclaveOutput + Serialize;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    /// Evaluate policies like authentication and idempotency
    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run<R, C>(self, _enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone;
}
