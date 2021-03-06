use crate::context::AnonifyEnclaveContext;

use super::executor::CommandExecutor;
use super::plaintext::CommandPlaintext;
use super::ContextWithCmdCipherPaddingSize;
use anonify_ecall_types::cmd::FETCH_CIPHERTEXT_TREEKEM_CMD;
use anonify_ecall_types::cmd::SEND_COMMAND_TREEKEM_CMD;
use anonify_ecall_types::*;
use anyhow::anyhow;
use frame_common::{
    crypto::{AccountId, Sha256},
    state_types::StateType,
    AccessPolicy,
};
use frame_enclave::StateRuntimeEnclaveUseCase;
use frame_runtime::traits::*;
use std::marker::PhantomData;

/// A message sender that encrypts commands
#[derive(Debug, Clone)]
pub struct CommandByTreeKemSender<'c, R, AP: AccessPolicy> {
    command_plaintext: CommandPlaintext<AP>,
    enclave_context: &'c ContextWithCmdCipherPaddingSize<'c>,
    user_id: Option<AccountId>,
    _p: PhantomData<R>,
}

impl<'c, R, AP> StateRuntimeEnclaveUseCase<'c, ContextWithCmdCipherPaddingSize<'c>>
    for CommandByTreeKemSender<'c, R, AP>
where
    R: RuntimeExecutor<AnonifyEnclaveContext, S = StateType>,
    AP: AccessPolicy,
{
    type EI = input::Command;
    type EO = output::Command;
    const ENCLAVE_USE_CASE_ID: u32 = SEND_COMMAND_TREEKEM_CMD;

    fn new(
        enclave_input: Self::EI,
        enclave_context: &'c ContextWithCmdCipherPaddingSize<'c>,
    ) -> anyhow::Result<Self> {
        let buf = enclave_context.ctx.decrypt(enclave_input.ciphertext())?;
        let command_plaintext = serde_json::from_slice(&buf[..])?;

        Ok(Self {
            command_plaintext,
            enclave_context,
            user_id: enclave_input.user_id(),
            _p: PhantomData::default(),
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        if self.command_plaintext.access_policy().verify().is_err() {
            return Err(anyhow!("Failed to verify access policy"));
        }

        if let Some(user_id_for_verify) = self.user_id {
            let user_id = self.command_plaintext.access_policy().into_account_id();
            if user_id != user_id_for_verify {
                return Err(anyhow!(
                    "Invalid user_id. user_id in the ciphertext: {:?}, user_id for verification: {:?}",
                    user_id,
                    user_id_for_verify
                ));
            }
        }

        Ok(())
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        let group_key = &mut *self.enclave_context.ctx.write_group_key();
        let roster_idx = group_key.my_roster_idx();
        // ratchet sender's app keychain per tx.
        group_key.sender_ratchet(roster_idx as usize)?;

        let my_account_id = self.command_plaintext.access_policy().into_account_id();
        let ciphertext = CommandExecutor::<R, AnonifyEnclaveContext, AP>::new(
            my_account_id,
            self.command_plaintext,
        )?
        .encrypt_with_treekem(group_key, self.enclave_context.cmd_cipher_padding_size)?;

        let msg = Sha256::hash_for_attested_treekem_tx(
            &ciphertext.encode(),
            roster_idx,
            ciphertext.generation(),
            ciphertext.epoch(),
        );
        let enclave_sig = self.enclave_context.ctx.sign(msg.as_bytes())?;
        let command_output = output::Command::new(
            CommandCiphertext::TreeKem(ciphertext),
            enclave_sig.0,
            enclave_sig.1,
        );

        Ok(command_output)
    }
}

/// A message receiver that decrypt commands and make state transition
#[derive(Debug, Clone)]
pub struct CommandByTreeKemReceiver<'c, R, AP> {
    enclave_input: input::InsertCiphertext,
    enclave_context: &'c AnonifyEnclaveContext,
    _p: PhantomData<(R, AP)>,
}

impl<'c, R, AP> StateRuntimeEnclaveUseCase<'c, AnonifyEnclaveContext>
    for CommandByTreeKemReceiver<'c, R, AP>
where
    R: RuntimeExecutor<AnonifyEnclaveContext, S = StateType>,
    AP: AccessPolicy,
{
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;
    const ENCLAVE_USE_CASE_ID: u32 = FETCH_CIPHERTEXT_TREEKEM_CMD;

    fn new(
        enclave_input: Self::EI,
        enclave_context: &'c AnonifyEnclaveContext,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            enclave_input,
            enclave_context,
            _p: PhantomData,
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// NOTE: Since this operation is stateful, you need to be careful about the order of processing, considering the possibility of processing failure.
    /// 1. Verify the order of transactions for each State Runtime node (verify_state_counter_increment)
    /// 2. Ratchet keychains
    /// 3. Verify the order of transactions for each user (verify_user_counter_increment)
    /// 4. State transitions
    fn run(self) -> anyhow::Result<Self::EO> {
        let group_key = &mut *self.enclave_context.write_group_key();
        let treekem_ciphertext = match self.enclave_input.ciphertext() {
            CommandCiphertext::TreeKem(ciphertext) => ciphertext,
            _ => return Err(anyhow!("CommandCiphertext is not for treekem")),
        };

        let roster_idx = treekem_ciphertext.roster_idx() as usize;
        let msg_gen = treekem_ciphertext.generation();

        // Even if group_key's ratchet operations and state transitions fail, state_counter must be incremented so it doesn't get stuck.
        self.enclave_context
            .verify_state_counter_increment(self.enclave_input.state_counter())?;

        // Since the sender's keychain has already ratcheted,
        // even if an error occurs in the state transition, the receiver's keychain also ratchet.
        // `receiver_ratchet` fails if
        //   1. Roster index is out of range of the keychain
        //   2. error occurs in HKDF
        //   3. the generation is over u32::MAX
        // In addition to these, `sync_ratchet` fails even if the receiver generation is larger than that of the sender
        // So if you run `sync_ratchet` first,
        // it will either succeed or both fail for the mutable `app_keychain`, so it will be atomic.
        group_key.sync_ratchet(roster_idx, msg_gen)?;
        group_key.receiver_ratchet(roster_idx)?;

        let mut output = output::ReturnNotifyState::default();
        let decrypted_cmds = CommandExecutor::<R, AnonifyEnclaveContext, AP>::decrypt_with_treekem(
            treekem_ciphertext,
            group_key,
        )?;
        if let Some(cmds) = decrypted_cmds {
            // Since the command data is valid for the error at the time of state transition,
            // `user_counter` must be verified and incremented before the state transition.
            self.enclave_context
                .verify_user_counter_increment(cmds.my_account_id(), cmds.counter())?;
            // Even if an error occurs in the state transition logic here, there is no problem because the state of `app_keychain` is consistent.
            let state_iter = cmds.state_transition(self.enclave_context.clone())?;

            if let Some(notify_state) = self
                .enclave_context
                .update_state(state_iter.0, state_iter.1)
            {
                let json = serde_json::to_vec(&notify_state)?;
                let bytes = bincode::serialize(&json[..])?;
                output.update(bytes);
            }
        }

        Ok(output)
    }
}
