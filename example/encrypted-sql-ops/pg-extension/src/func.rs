use crate::{
    init::Enclave,
    typ::{AvgState, EncInteger},
};
use frame_host::engine::HostEngine;
use module_encrypted_sql_ops_ecall_types::{
    ecall_cmd::ENCINTEGER_FROM, enc_type::EncInteger as ModuleEncInteger,
};
use module_encrypted_sql_ops_host::workflow::{host_input::RawInteger, EncIntegerFromWorkflow};
use pgx::*;

#[pg_extern]
fn encinteger_from(raw_integer: i32) -> EncInteger {
    let host_input = RawInteger::new(raw_integer, ENCINTEGER_FROM);
    let eid = Enclave::global().geteid();

    let host_output = EncIntegerFromWorkflow::exec(host_input, eid).unwrap_or_else(|e| {
        panic!(
            "failed to encrypt raw INTEGER in enclave (Enclave ID: {}), {:?}",
            eid, e
        )
    });

    EncInteger::from(ModuleEncInteger::from(host_output))
}

#[pg_extern]
fn encinteger_avg_state_func(_internal_state: AvgState, _next_data_value: EncInteger) -> AvgState {
    todo!("create Workflow")
}

#[pg_extern]
fn encinteger_avg_final_func(_internal_state: AvgState) -> i32 {
    todo!("create Workflow")
}