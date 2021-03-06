use crate::bincode;
use crate::localstd::{fmt, str, string::String, vec::Vec};
use crate::serde::{
    de::{self, Error, SeqAccess},
    ser::SerializeSeq,
    Deserialize, Serialize, Serializer,
};
use crate::serde_bytes;
use crate::serde_json;
use crate::CommandCiphertext;
use frame_common::{
    crypto::{AccountId, ExportHandshake},
    state_types::{StateCounter, StateType, UserCounter},
    traits::AccessPolicy,
    EnclaveInput, EnclaveOutput,
};
use frame_sodium::{SodiumCiphertext, SodiumPubKey};

pub mod input {
    use super::*;

    #[derive(Debug, Clone, Deserialize, Serialize, Default)]
    #[serde(crate = "crate::serde")]
    pub struct Command {
        ciphertext: SodiumCiphertext,
        user_id: Option<AccountId>,
    }

    impl EnclaveInput for Command {}

    impl Command {
        pub fn new(ciphertext: SodiumCiphertext, user_id: Option<AccountId>) -> Self {
            Self {
                ciphertext,
                user_id,
            }
        }

        pub fn ciphertext(&self) -> &SodiumCiphertext {
            &self.ciphertext
        }

        pub fn user_id(&self) -> Option<AccountId> {
            self.user_id
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct InsertCiphertext {
        ciphertext: CommandCiphertext,
        state_counter: StateCounter,
    }

    impl EnclaveInput for InsertCiphertext {}

    impl InsertCiphertext {
        pub fn new(ciphertext: CommandCiphertext, state_counter: StateCounter) -> Self {
            InsertCiphertext {
                ciphertext,
                state_counter,
            }
        }

        pub fn ciphertext(&self) -> &CommandCiphertext {
            &self.ciphertext
        }

        pub fn state_counter(&self) -> StateCounter {
            self.state_counter
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct InsertHandshake {
        handshake: ExportHandshake,
        state_counter: StateCounter,
    }

    impl EnclaveInput for InsertHandshake {}

    impl InsertHandshake {
        pub fn new(handshake: ExportHandshake, state_counter: StateCounter) -> Self {
            InsertHandshake {
                handshake,
                state_counter,
            }
        }

        pub fn handshake(&self) -> &ExportHandshake {
            &self.handshake
        }

        pub fn state_counter(&self) -> StateCounter {
            self.state_counter
        }
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(crate = "crate::serde")]
    pub struct GetState<AP: AccessPolicy> {
        #[serde(deserialize_with = "AP::deserialize")]
        pub access_policy: AP,
        pub runtime_params: serde_json::Value,
        pub state_name: String,
    }

    impl<AP> Default for GetState<AP>
    where
        AP: AccessPolicy,
    {
        fn default() -> Self {
            Self {
                access_policy: AP::default(),
                runtime_params: serde_json::Value::Null,
                state_name: String::default(),
            }
        }
    }

    impl<AP: AccessPolicy> GetState<AP> {
        pub fn new(
            access_policy: AP,
            runtime_params: serde_json::Value,
            state_name: String,
        ) -> Self {
            GetState {
                access_policy,
                runtime_params,
                state_name,
            }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }

        pub fn runtime_params(&self) -> &serde_json::Value {
            &self.runtime_params
        }

        pub fn state_name(&self) -> &str {
            &self.state_name
        }
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(crate = "crate::serde")]
    pub struct GetUserCounter<AP: AccessPolicy> {
        #[serde(deserialize_with = "AP::deserialize")]
        pub access_policy: AP,
    }

    impl<AP> Default for GetUserCounter<AP>
    where
        AP: AccessPolicy,
    {
        fn default() -> Self {
            Self {
                access_policy: AP::default(),
            }
        }
    }

    impl<AP: AccessPolicy> GetUserCounter<AP> {
        pub fn new(access_policy: AP) -> Self {
            GetUserCounter { access_policy }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct RegisterNotification<AP: AccessPolicy> {
        #[serde(deserialize_with = "AP::deserialize")]
        access_policy: AP,
    }

    impl<AP: AccessPolicy> EnclaveInput for RegisterNotification<AP> {}

    impl<AP: AccessPolicy> RegisterNotification<AP> {
        pub fn new(access_policy: AP) -> Self {
            RegisterNotification { access_policy }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct Empty;

    impl EnclaveInput for Empty {}
}

pub mod output {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Command {
        enclave_sig: secp256k1::Signature,
        ciphertext: CommandCiphertext,
        recovery_id: secp256k1::RecoveryId,
    }

    impl Default for Command {
        fn default() -> Self {
            let enclave_sig = secp256k1::Signature::parse(&[0u8; 64]);
            let recovery_id = secp256k1::RecoveryId::parse(0).unwrap();
            Self {
                enclave_sig,
                ciphertext: CommandCiphertext::default(),
                recovery_id,
            }
        }
    }

    impl EnclaveOutput for Command {}

    impl Serialize for Command {
        // not for human readable, used for binary encoding
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&self.encode_enclave_sig()[..])?;
            seq.serialize_element(&self.encode_recovery_id())?;
            seq.serialize_element(&self.encode_ciphertext())?;
            seq.end()
        }
    }

    impl<'de> Deserialize<'de> for Command {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct CommandVisitor;

            impl<'de> de::Visitor<'de> for CommandVisitor {
                type Value = Command;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("ecall output command")
                }

                fn visit_seq<V>(self, mut seq: V) -> Result<Command, V::Error>
                where
                    V: SeqAccess<'de>,
                {
                    let enclave_sig_v: &[u8] = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                    let recovery_id_v = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    let ciphertext_v: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                    let enclave_sig = secp256k1::Signature::parse_slice(&enclave_sig_v[..])
                        .map_err(|_e| V::Error::custom("InvalidSignature"))?;
                    let recovery_id = secp256k1::RecoveryId::parse(recovery_id_v)
                        .map_err(|_e| V::Error::custom("InvalidRecoveryId"))?;
                    let ciphertext = bincode::deserialize(&ciphertext_v[..])
                        .map_err(|_e| V::Error::custom("InvalidCiphertext"))?;

                    Ok(Command::new(ciphertext, enclave_sig, recovery_id))
                }
            }

            deserializer.deserialize_seq(CommandVisitor)
        }
    }

    impl Command {
        pub fn new(
            ciphertext: CommandCiphertext,
            enclave_sig: secp256k1::Signature,
            recovery_id: secp256k1::RecoveryId,
        ) -> Self {
            Command {
                enclave_sig,
                ciphertext,
                recovery_id,
            }
        }

        pub fn ciphertext(&self) -> &CommandCiphertext {
            &self.ciphertext
        }

        pub fn encode_ciphertext(&self) -> Vec<u8> {
            bincode::serialize(&self.ciphertext).unwrap() // must not fail
        }

        pub fn encode_recovery_id(&self) -> u8 {
            self.recovery_id.serialize()
        }

        pub fn encode_enclave_sig(&self) -> [u8; 64] {
            self.enclave_sig.serialize()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnNotifyState {
        pub state: Option<serde_bytes::ByteBuf>,
    }

    impl EnclaveOutput for ReturnNotifyState {}

    impl Default for ReturnNotifyState {
        fn default() -> Self {
            ReturnNotifyState { state: None }
        }
    }

    impl ReturnNotifyState {
        pub fn update(&mut self, state: Vec<u8>) {
            self.state = Some(serde_bytes::ByteBuf::from(state))
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnEncryptionKey {
        enclave_encryption_key: SodiumPubKey,
    }

    impl EnclaveOutput for ReturnEncryptionKey {}

    impl ReturnEncryptionKey {
        pub fn new(enclave_encryption_key: SodiumPubKey) -> Self {
            ReturnEncryptionKey {
                enclave_encryption_key,
            }
        }

        pub fn enclave_encryption_key(self) -> SodiumPubKey {
            self.enclave_encryption_key
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct Empty;

    impl EnclaveOutput for Empty {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnState {
        pub state: StateType,
    }

    impl EnclaveOutput for ReturnState {}

    impl ReturnState {
        pub fn new(state: StateType) -> Self {
            ReturnState { state }
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnUserCounter {
        pub user_counter: UserCounter,
    }

    impl EnclaveOutput for ReturnUserCounter {}

    impl ReturnUserCounter {
        pub fn new(user_counter: UserCounter) -> Self {
            ReturnUserCounter { user_counter }
        }
    }

    #[derive(Serialize, Deserialize, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnJoinGroup {
        #[serde(with = "serde_bytes")]
        report: Vec<u8>,
        #[serde(with = "serde_bytes")]
        report_sig: Vec<u8>,
        handshake: Option<Vec<u8>>,
        mrenclave_ver: u32,
        roster_idx: u32,
    }

    impl fmt::Debug for ReturnJoinGroup {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.handshake() {
                Some(handshake) => {
                    write!(
                        f,
                        "ReturnJoinGroup {{ report: 0x{}, report_sig: 0x{}, handshake: 0x{}, mrenclave_ver: {:?}, roster_idx: {:?} }}",
                        hex::encode(&self.report()),
                        hex::encode(&self.report_sig()),
                        hex::encode(&handshake),
                        self.mrenclave_ver,
                        self.roster_idx
                    )
                }
                None => {
                    write!(
                        f,
                        "ReturnJoinGroup {{ report: 0x{}, report_sig: 0x{}, mrenclave_ver: {:?}, roster_idx: {:?} }}",
                        hex::encode(&self.report()),
                        hex::encode(&self.report_sig()),
                        self.mrenclave_ver,
                        self.roster_idx
                    )
                }
            }
        }
    }

    impl EnclaveOutput for ReturnJoinGroup {}

    impl ReturnJoinGroup {
        pub fn new(
            report: Vec<u8>,
            report_sig: Vec<u8>,
            handshake: Option<Vec<u8>>,
            mrenclave_ver: usize,
            roster_idx: u32,
        ) -> Self {
            ReturnJoinGroup {
                report,
                report_sig,
                handshake,
                mrenclave_ver: mrenclave_ver as u32,
                roster_idx,
            }
        }

        pub fn report(&self) -> &[u8] {
            &self.report[..]
        }

        pub fn report_sig(&self) -> &[u8] {
            &self.report_sig[..]
        }

        pub fn handshake(&self) -> Option<&[u8]> {
            self.handshake.as_deref()
        }

        pub fn mrenclave_ver(&self) -> u32 {
            self.mrenclave_ver
        }

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }

    #[derive(Serialize, Deserialize, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnRegisterReport {
        #[serde(with = "serde_bytes")]
        report: Vec<u8>,
        #[serde(with = "serde_bytes")]
        report_sig: Vec<u8>,
        mrenclave_ver: u32,
        roster_idx: u32,
    }

    impl fmt::Debug for ReturnRegisterReport {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ReturnRegisterReport {{ report: 0x{}, report_sig: 0x{}, mrenclave_ver: {:?}, roster_idx: {:?} }}",
                hex::encode(&self.report),
                hex::encode(&self.report_sig),
                self.mrenclave_ver,
                self.roster_idx
            )
        }
    }

    impl EnclaveOutput for ReturnRegisterReport {}

    impl ReturnRegisterReport {
        pub fn new(
            report: Vec<u8>,
            report_sig: Vec<u8>,
            mrenclave_ver: usize,
            roster_idx: u32,
        ) -> Self {
            ReturnRegisterReport {
                report,
                report_sig,
                mrenclave_ver: mrenclave_ver as u32,
                roster_idx,
            }
        }

        pub fn report(&self) -> &[u8] {
            &self.report[..]
        }

        pub fn report_sig(&self) -> &[u8] {
            &self.report_sig[..]
        }

        pub fn mrenclave_ver(&self) -> u32 {
            self.mrenclave_ver
        }

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }

    #[derive(Debug, Clone)]
    pub struct ReturnHandshake {
        enclave_sig: secp256k1::Signature,
        recovery_id: secp256k1::RecoveryId,
        handshake: ExportHandshake,
    }

    impl Default for ReturnHandshake {
        fn default() -> Self {
            let enclave_sig = secp256k1::Signature::parse(&[0u8; 64]);
            let recovery_id = secp256k1::RecoveryId::parse(0).unwrap();
            Self {
                enclave_sig,
                recovery_id,
                handshake: ExportHandshake::default(),
            }
        }
    }

    impl EnclaveOutput for ReturnHandshake {}

    impl Serialize for ReturnHandshake {
        // not for human readable, used for binary encoding
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(4))?;
            seq.serialize_element(&self.encode_enclave_sig()[..])?;
            seq.serialize_element(&self.encode_recovery_id())?;
            seq.serialize_element(&self.encode_handshake())?;
            seq.end()
        }
    }

    impl<'de> Deserialize<'de> for ReturnHandshake {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct ReturnHandshakeVisitor;

            impl<'de> de::Visitor<'de> for ReturnHandshakeVisitor {
                type Value = ReturnHandshake;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("ecall output ReturnHandshake")
                }

                fn visit_seq<V>(self, mut seq: V) -> Result<ReturnHandshake, V::Error>
                where
                    V: SeqAccess<'de>,
                {
                    let enclave_sig_v: &[u8] = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                    let recovery_id_v = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    let handshake_v: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                    let enclave_sig = secp256k1::Signature::parse_slice(&enclave_sig_v[..])
                        .map_err(|_e| V::Error::custom("InvalidSignature"))?;
                    let recovery_id = secp256k1::RecoveryId::parse(recovery_id_v)
                        .map_err(|_e| V::Error::custom("InvalidRecoverId"))?;
                    let handshake = bincode::deserialize(&handshake_v[..])
                        .map_err(|_e| V::Error::custom("InvalidHandshake"))?;

                    Ok(ReturnHandshake::new(handshake, enclave_sig, recovery_id))
                }
            }

            deserializer.deserialize_seq(ReturnHandshakeVisitor)
        }
    }

    impl ReturnHandshake {
        pub fn new(
            handshake: ExportHandshake,
            enclave_sig: secp256k1::Signature,
            recovery_id: secp256k1::RecoveryId,
        ) -> Self {
            ReturnHandshake {
                handshake,
                enclave_sig,
                recovery_id,
            }
        }

        pub fn handshake(&self) -> &ExportHandshake {
            &self.handshake
        }

        pub fn encode_handshake(&self) -> Vec<u8> {
            bincode::serialize(&self.handshake).unwrap() // must not fail
        }

        pub fn encode_recovery_id(&self) -> u8 {
            self.recovery_id.serialize()
        }

        pub fn encode_enclave_sig(&self) -> [u8; 64] {
            self.enclave_sig.serialize()
        }
    }
}
