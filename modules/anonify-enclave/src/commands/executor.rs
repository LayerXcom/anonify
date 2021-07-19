use super::plaintext::CommandPlaintext;
use crate::error::Result;
use anonify_ecall_types::EnclaveKeyCiphertext;
use anyhow::anyhow;
use frame_common::{
    crypto::AccountId,
    state_types::{NotifyState, ReturnState, StateType, UpdatedState, UserCounter},
    AccessPolicy, TreeKemCiphertext,
};
use frame_runtime::traits::*;
use frame_sodium::{SodiumCiphertext, SodiumPrivateKey, SodiumPubKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, vec::Vec};

type UpdatedStates = Vec<UpdatedState<StateType>>;
type NotifyStates = Vec<Option<NotifyState>>;

/// Command data which make state update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecutor<R: RuntimeExecutor<CTX>, CTX: ContextOps<S = StateType>, AP> {
    my_account_id: AccountId,
    #[serde(deserialize_with = "R::C::deserialize")]
    call_kind: R::C,
    counter: UserCounter,
    phantom: PhantomData<CTX>,
    ap: PhantomData<AP>,
}

impl<R, CTX, AP> CommandExecutor<R, CTX, AP>
where
    R: RuntimeExecutor<CTX, S = StateType>,
    CTX: ContextOps<S = StateType>,
    AP: AccessPolicy,
{
    pub fn new(my_account_id: AccountId, command_plaintext: CommandPlaintext<AP>) -> Result<Self> {
        let call_kind = R::C::new(
            command_plaintext.cmd_name(),
            command_plaintext.runtime_params.clone(),
        )?;

        Ok(CommandExecutor {
            my_account_id,
            call_kind,
            counter: command_plaintext.counter(),
            phantom: PhantomData,
            ap: PhantomData,
        })
    }

    pub fn encrypt_with_treekem<GK: GroupKeyOps>(
        &self,
        key: &GK,
        cmd_cipher_padding_size: usize,
    ) -> Result<TreeKemCiphertext> {
        let mut buf = bincode::serialize(&self).unwrap(); // must not fail
        Self::append_padding(&mut buf, cmd_cipher_padding_size);
        key.encrypt(buf).map_err(Into::into)
    }

    pub fn encrypt_with_enclave_key<RNG: RngCore + CryptoRng>(
        &self,
        csprng: &mut RNG,
        pubkey: SodiumPubKey,
        cmd_cipher_padding_size: usize,
        roster_idx: u32,
    ) -> Result<EnclaveKeyCiphertext> {
        let mut buf = bincode::serialize(&self).unwrap(); // must not fail
        Self::append_padding(&mut buf, cmd_cipher_padding_size);
        let encrypted_state = SodiumCiphertext::encrypt(csprng, &pubkey, &buf)?;
        Ok(EnclaveKeyCiphertext::new(encrypted_state, roster_idx))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    /// Only if the TEE belongs to the group, you can receive ciphertext and decrypt it,
    /// otherwise do nothing.
    pub fn state_transition(
        self,
        ctx: CTX,
    ) -> Result<(
        impl Iterator<Item = UpdatedState<StateType>>,
        impl Iterator<Item = Option<NotifyState>>,
    )> {
        let stf_res = self.stf_call(ctx)?;
        Ok((stf_res.0.into_iter(), stf_res.1.into_iter()))
    }

    pub fn decrypt_with_treekem<GK: GroupKeyOps>(
        ciphertext: &TreeKemCiphertext,
        key: &mut GK,
    ) -> Result<Option<Self>> {
        match key.decrypt(ciphertext)? {
            Some(plaintext) => CommandExecutor::decode(&plaintext[..]).map(Some),
            None => Ok(None),
        }
    }

    pub fn decrypt_with_enclave_key(
        ciphertext: &SodiumCiphertext,
        privkey: &SodiumPrivateKey,
    ) -> Result<Self> {
        ciphertext
            .decrypt(privkey)
            .map_err(Into::into)
            .and_then(|bytes| CommandExecutor::decode(&bytes[..]))
    }

    fn stf_call(self, ctx: CTX) -> Result<(UpdatedStates, NotifyStates)> {
        let res = R::new(ctx).execute(self.call_kind, self.my_account_id)?;

        match res {
            ReturnState::Updated(updates) => Ok(updates),
            ReturnState::Get(_) => Err(anyhow!(
                "Calling state transition function, but the called function is for getting state."
            )
            .into()),
        }
    }

    // Add padding to fix the ciphertext size of all state types.
    // The padding works for fixing the ciphertext size so that
    // other people cannot distinguish what state is encrypted based on the size.
    fn append_padding(buf: &mut Vec<u8>, cmd_cipher_padding_size: usize) {
        println!("#### buf: {:?}", buf.len());
        println!("#### cmd_cipher_padding_size: {:?}", cmd_cipher_padding_size);
        let padding_size = cmd_cipher_padding_size - buf.len();
        let padding = vec![0u8; padding_size];
        buf.extend_from_slice(&padding);
    }

    pub fn my_account_id(&self) -> AccountId {
        self.my_account_id
    }

    pub fn counter(&self) -> UserCounter {
        self.counter
    }
}
