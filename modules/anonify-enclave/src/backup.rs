#![cfg(feature = "backup-enable")]

use crate::context::AnonifyEnclaveContext;
use crate::enclave_key::DEC_KEY_FILE_NAME;
use anonify_ecall_types::cmd::{
    BACKUP_ENCLAVE_KEY_CMD, BACKUP_PATH_SECRETS_CMD, RECOVER_ENCLAVE_KEY_CMD,
    RECOVER_PATH_SECRETS_CMD,
};
use anonify_ecall_types::*;
use anyhow::{anyhow, Result};
use frame_enclave::StateRuntimeEnclaveUseCase;
use frame_mra_tls::key_vault::request::{
    BackupPathSecretRequestBody, BackupPathSecretsRequestBody, RecoverPathSecretsRequestBody,
};
use frame_runtime::traits::*;
use frame_sodium::SealedEnclaveDecryptionKey;
use frame_treekem::PathSecret;
use std::vec::Vec;

/// A PathSecret Backupper
#[derive(Debug, Clone)]
pub struct PathSecretsBackupper<'c> {
    enclave_context: &'c AnonifyEnclaveContext,
}

impl<'c> StateRuntimeEnclaveUseCase<'c, AnonifyEnclaveContext> for PathSecretsBackupper<'c> {
    type EI = input::Empty;
    type EO = output::Empty;
    const ENCLAVE_USE_CASE_ID: u32 = BACKUP_PATH_SECRETS_CMD;

    fn new(
        _enclave_input: Self::EI,
        enclave_context: &'c AnonifyEnclaveContext,
    ) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run(self) -> Result<Self::EO> {
        let store_path_secrets = self.enclave_context.store_path_secrets();
        // retrieve local path_secrets IDs
        let ids = store_path_secrets.get_all_path_secret_ids()?;
        let roster_idx = (&*self.enclave_context.read_group_key()).my_roster_idx();

        // backup path_secrets to key-vault server
        let mut backup_path_secrets: Vec<BackupPathSecretRequestBody> = vec![];
        for id in ids {
            let eps = store_path_secrets.load_from_local_filesystem(&id)?;
            let ps = PathSecret::try_from_importing(eps.clone())?;
            let backup_path_secret = BackupPathSecretRequestBody::new(
                ps.as_bytes().to_vec(),
                eps.epoch(),
                roster_idx,
                id,
            );
            backup_path_secrets.push(backup_path_secret);
        }

        self.enclave_context
            .manually_backup_path_secrets(BackupPathSecretsRequestBody::new(backup_path_secrets))?;

        Ok(output::Empty::default())
    }
}

/// A PathSecret Recoverer
#[derive(Debug, Clone)]
pub struct PathSecretsRecoverer<'c> {
    enclave_context: &'c AnonifyEnclaveContext,
}

impl<'c> StateRuntimeEnclaveUseCase<'c, AnonifyEnclaveContext> for PathSecretsRecoverer<'c> {
    type EI = input::Empty;
    type EO = output::Empty;
    const ENCLAVE_USE_CASE_ID: u32 = RECOVER_PATH_SECRETS_CMD;

    fn new(
        _enclave_input: Self::EI,
        enclave_context: &'c AnonifyEnclaveContext,
    ) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run(self) -> Result<Self::EO> {
        // fetch path_secrets from key-vault server
        let group_key = &*self.enclave_context.read_group_key();
        let roster_idx = group_key.my_roster_idx();
        let recover_request = RecoverPathSecretsRequestBody::new(roster_idx);
        let recovered_path_secrets = self
            .enclave_context
            .manually_recover_path_secrets(recover_request)?;

        // save path_secrets to own file system
        for rps in recovered_path_secrets {
            let path_secret = PathSecret::from(rps.path_secret());
            let eps = path_secret
                .clone()
                .try_into_exporting(rps.epoch(), rps.id())?;
            self.enclave_context
                .store_path_secrets()
                .save_to_local_filesystem(&eps)?;
        }
        Ok(output::Empty::default())
    }
}

/// A EnclaveKey Backupper
#[derive(Debug, Clone)]
pub struct EnclaveKeyBackupper<'c> {
    enclave_context: &'c AnonifyEnclaveContext,
}

impl<'c> StateRuntimeEnclaveUseCase<'c, AnonifyEnclaveContext> for EnclaveKeyBackupper<'c> {
    type EI = input::Empty;
    type EO = output::Empty;
    const ENCLAVE_USE_CASE_ID: u32 = BACKUP_ENCLAVE_KEY_CMD;

    fn new(
        _enclave_input: Self::EI,
        enclave_context: &'c AnonifyEnclaveContext,
    ) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run(self) -> Result<Self::EO> {
        self.enclave_context.backup_enclave_key()?;
        Ok(output::Empty::default())
    }
}

/// A EnclaveKey Recoverer
#[derive(Debug, Clone)]
pub struct EnclaveKeyRecoverer<'c> {
    enclave_context: &'c AnonifyEnclaveContext,
}

impl<'c> StateRuntimeEnclaveUseCase<'c, AnonifyEnclaveContext> for EnclaveKeyRecoverer<'c> {
    type EI = input::Empty;
    type EO = output::Empty;
    const ENCLAVE_USE_CASE_ID: u32 = RECOVER_ENCLAVE_KEY_CMD;

    fn new(
        _enclave_input: Self::EI,
        enclave_context: &'c AnonifyEnclaveContext,
    ) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run(self) -> Result<Self::EO> {
        // fetch path_secrets from key-vault server
        let dec_key = self.enclave_context.recover_enclave_key()?;

        // save path_secrets to own file system
        let encoded = dec_key.try_into_sealing()?;
        let sealed =
            SealedEnclaveDecryptionKey::decode(&encoded).map_err(|e| anyhow!("{:?}", e))?;

        let store_dec_key = self.enclave_context.store_enclave_dec_key();
        store_dec_key.save_to_local_filesystem(&sealed, DEC_KEY_FILE_NAME)?;

        Ok(output::Empty::default())
    }
}
