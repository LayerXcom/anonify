use frame_host::ecall_controller::*;
use key_vault_ecall_types::*;

pub const EI_MAX_SIZE: usize = 2000;// 4096; // 2048;

pub struct StartServerController;

impl EcallController for StartServerController {
    type HI = host_input::StartServer;
    type EI = input::CallServerStarter;
    type EO = output::Empty;
    type HO = host_output::StartServer;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::CallServerStarter::default())
    }

    fn translate_output(_enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::StartServer::default())
    }
}

pub struct StopServerController;

impl EcallController for StopServerController {
    type HI = host_input::StopServer;
    type EI = input::CallServerStopper;
    type EO = output::Empty;
    type HO = host_output::StopServer;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::CallServerStopper::default())
    }

    fn translate_output(_enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::StopServer::default())
    }
}

pub mod host_input {
    use super::*;

    pub struct StartServer {}

    impl StartServer {
        pub fn new() -> Self {
            StartServer {}
        }
    }

    impl HostInput for StartServer {}

    pub struct StopServer {}

    impl StopServer {
        pub fn new() -> Self {
            StopServer {}
        }
    }

    impl HostInput for StopServer {}
}

pub mod host_output {
    use super::*;

    #[derive(Default)]
    pub struct StartServer;

    impl HostOutput for StartServer {}

    #[derive(Default)]
    pub struct StopServer;

    impl HostOutput for StopServer {}
}
