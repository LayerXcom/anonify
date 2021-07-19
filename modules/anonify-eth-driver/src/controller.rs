use anonify_ecall_types::*;
use frame_common::{
    crypto::{AccountId, ExportHandshake},
    state_types::StateCounter,
};
use frame_host::ecall_controller::*;
use frame_sodium::SodiumCiphertext;

pub const EI_MAX_SIZE: usize = 2800;

pub struct CommandController;

impl EcallController for CommandController {
    type HI = host_input::Command;
    type EI = input::Command;
    type EO = output::Command;
    type HO = host_output::Command;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Command::new(
            host_input.ciphertext,
            host_input.user_id,
        ))
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::Command { enclave_output })
    }
}

pub struct JoinGroupController;

impl EcallController for JoinGroupController {
    type HI = host_input::JoinGroup;
    type EI = input::Empty;
    type EO = output::ReturnJoinGroup;
    type HO = host_output::JoinGroup;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty::default())
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::JoinGroup { enclave_output })
    }
}

pub struct RegisterReportController;

impl EcallController for RegisterReportController {
    type HI = host_input::RegisterReport;
    type EI = input::Empty;
    type EO = output::ReturnRegisterReport;
    type HO = host_output::RegisterReport;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty::default())
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::RegisterReport { enclave_output })
    }
}

pub struct HandshakeController;

impl EcallController for HandshakeController {
    type HI = host_input::Handshake;
    type EI = input::Empty;
    type EO = output::ReturnHandshake;
    type HO = host_output::Handshake;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty::default())
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::Handshake { enclave_output })
    }
}

pub struct RegisterNotificationController;

impl EcallController for RegisterNotificationController {
    type HI = host_input::RegisterNotification;
    type EI = SodiumCiphertext;
    type EO = output::Empty;
    type HO = host_output::RegisterNotification;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(host_input.ciphertext)
    }

    fn translate_output(_enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::RegisterNotification::default())
    }
}

pub struct GetStateController;

impl EcallController for GetStateController {
    type HI = host_input::GetState;
    type EI = SodiumCiphertext;
    type EO = output::ReturnState;
    type HO = host_output::GetState;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(host_input.ciphertext)
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::GetState { enclave_output })
    }
}

pub struct InsertCiphertextController;

impl EcallController for InsertCiphertextController {
    type HI = host_input::InsertCiphertext;
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;
    type HO = host_output::InsertCiphertext;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::InsertCiphertext::new(
            host_input.ciphertext,
            host_input.state_counter,
        ))
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::InsertCiphertext { enclave_output })
    }
}

pub struct InsertHandshakeController;

impl EcallController for InsertHandshakeController {
    type HI = host_input::InsertHandshake;
    type EI = input::InsertHandshake;
    type EO = output::Empty;
    type HO = host_output::InsertHandshake;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::InsertHandshake::new(
            host_input.handshake,
            host_input.state_counter,
        ))
    }

    fn translate_output(_enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::InsertHandshake::default())
    }
}

pub struct GetEncryptionKeyController;

impl EcallController for GetEncryptionKeyController {
    type HI = host_input::GetEncryptionKey;
    type EI = input::Empty;
    type EO = output::ReturnEncryptionKey;
    type HO = host_output::ReturnEncryptionKey;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty::default())
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::ReturnEncryptionKey { enclave_output })
    }
}

pub struct BackupController;

impl EcallController for BackupController {
    type HI = host_input::Backup;
    type EI = input::Empty;
    type EO = output::Empty;
    type HO = host_output::Backup;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty::default())
    }

    fn translate_output(_enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::Backup::default())
    }
}

pub struct RecoverController;

impl EcallController for RecoverController {
    type HI = host_input::Recover;
    type EI = input::Empty;
    type EO = output::Empty;
    type HO = host_output::Recover;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(_host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty)
    }

    fn translate_output(_enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::Recover::default())
    }
}

pub struct GetUserCounterController;

impl EcallController for GetUserCounterController {
    type HI = host_input::GetUserCounter;
    type EI = SodiumCiphertext;
    type EO = output::ReturnUserCounter;
    type HO = host_output::GetUserCounter;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(host_input.ciphertext)
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::GetUserCounter { enclave_output })
    }
}

pub mod host_input {
    use super::*;

    pub struct Command {
        pub(super) ciphertext: SodiumCiphertext,
        pub(super) user_id: Option<AccountId>,
    }

    impl Command {
        pub fn new(ciphertext: SodiumCiphertext, user_id: Option<AccountId>) -> Self {
            Command {
                ciphertext,
                user_id,
            }
        }
    }

    impl HostInput for Command {}

    pub struct JoinGroup {}

    impl JoinGroup {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl HostInput for JoinGroup {}

    pub struct RegisterReport {}

    impl RegisterReport {
        pub fn new() -> Self {
            RegisterReport {}
        }
    }

    impl HostInput for RegisterReport {}

    pub struct Handshake {}

    impl Handshake {
        pub fn new() -> Self {
            Handshake {}
        }
    }

    impl HostInput for Handshake {}

    pub struct RegisterNotification {
        pub(super) ciphertext: SodiumCiphertext,
    }

    impl RegisterNotification {
        pub fn new(ciphertext: SodiumCiphertext) -> Self {
            RegisterNotification { ciphertext }
        }
    }

    impl HostInput for RegisterNotification {}

    pub struct GetState {
        pub(super) ciphertext: SodiumCiphertext,
    }

    impl GetState {
        pub fn new(ciphertext: SodiumCiphertext) -> Self {
            GetState { ciphertext }
        }
    }

    impl HostInput for GetState {}

    pub struct GetUserCounter {
        pub(super) ciphertext: SodiumCiphertext,
    }

    impl GetUserCounter {
        pub fn new(ciphertext: SodiumCiphertext) -> Self {
            GetUserCounter { ciphertext }
        }
    }

    impl HostInput for GetUserCounter {}

    pub struct InsertCiphertext {
        pub(super) ciphertext: CommandCiphertext,
        pub(super) state_counter: StateCounter,
    }

    impl InsertCiphertext {
        pub fn new(ciphertext: CommandCiphertext, state_counter: StateCounter) -> Self {
            InsertCiphertext {
                ciphertext,
                state_counter,
            }
        }
    }

    impl HostInput for InsertCiphertext {}

    pub struct InsertHandshake {
        pub(super) handshake: ExportHandshake,
        pub(super) state_counter: StateCounter,
    }

    impl InsertHandshake {
        pub fn new(handshake: ExportHandshake, state_counter: StateCounter) -> Self {
            InsertHandshake {
                handshake,
                state_counter,
            }
        }
    }

    impl HostInput for InsertHandshake {}

    pub struct GetEncryptionKey {}

    impl GetEncryptionKey {
        pub fn new() -> Self {
            GetEncryptionKey {}
        }
    }

    impl HostInput for GetEncryptionKey {}

    pub struct Backup {}

    impl Backup {
        pub fn new() -> Self {
            Backup {}
        }
    }

    impl HostInput for Backup {}

    pub struct Recover {}

    impl Recover {
        pub fn new() -> Self {
            Recover {}
        }
    }

    impl HostInput for Recover {}
}

pub mod host_output {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Command {
        pub enclave_output: output::Command,
    }

    impl HostOutput for Command {}

    #[derive(Debug, Clone)]
    pub struct JoinGroup {
        pub enclave_output: output::ReturnJoinGroup,
    }

    impl HostOutput for JoinGroup {}

    #[derive(Debug, Clone)]
    pub struct RegisterReport {
        pub enclave_output: output::ReturnRegisterReport,
    }

    impl HostOutput for RegisterReport {}

    #[derive(Debug, Clone)]
    pub struct Handshake {
        pub enclave_output: output::ReturnHandshake,
    }

    impl HostOutput for Handshake {}

    #[derive(Default)]
    pub struct RegisterNotification;

    impl HostOutput for RegisterNotification {}

    pub struct GetState {
        pub enclave_output: output::ReturnState,
    }

    impl HostOutput for GetState {}

    pub struct GetUserCounter {
        pub enclave_output: output::ReturnUserCounter,
    }

    impl HostOutput for GetUserCounter {}

    pub struct InsertCiphertext {
        pub enclave_output: output::ReturnNotifyState,
    }

    impl HostOutput for InsertCiphertext {}

    #[derive(Default)]
    pub struct InsertHandshake;

    impl HostOutput for InsertHandshake {}

    pub struct ReturnEncryptionKey {
        pub enclave_output: output::ReturnEncryptionKey,
    }

    impl HostOutput for ReturnEncryptionKey {}

    #[derive(Default)]
    pub struct Backup;

    impl HostOutput for Backup {}

    #[derive(Default)]
    pub struct Recover;

    impl HostOutput for Recover {}
}
