use crate::application::AppKeyChain;
use crate::crypto::{
    dh::DhPubKey, ecies::EciesCiphertext, hash::hash_encodable, secrets::PathSecret, CryptoRng,
};
use crate::StorePathSecrets;
use anyhow::{anyhow, Result};
use frame_common::crypto::{ExportHandshake, ExportPathSecret};
use ring::digest::Digest;
use serde::{Deserialize, Serialize};
use std::sync::SgxRwLock as RwLock;
use std::{boxed::Box, collections::HashMap, string::String, sync::Arc, vec::Vec};

/// A handshake operates sharing a group key to each member.
pub trait Handshake: Sized {
    /// Create a handshake to broadcast other members.
    fn create_handshake(&self, source: &PathSecretSource) -> Result<(HandshakeParams, PathSecret)>;

    /// Process a received handshake from other members.
    fn process_handshake<
        #[cfg(feature = "backup-enable")] F: FnOnce(&[u8], u32) -> Result<PathSecret>,
    >(
        &mut self,
        store_path_secrets: &StorePathSecrets,
        handshake: &HandshakeParams,
        source: &PathSecretSource,
        max_roster_idx: u32,
        #[cfg(feature = "backup-enable")] recover_path_secret_from_key_vault: F,
    ) -> Result<AppKeyChain>;
}

// TODO: Does need signature over the group's history?
/// This `Handshake` is sent to global ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeParams {
    /// This is equal to the epoch of the current groupstate
    /// at the time of receicing and applying the handshake.
    prior_epoch: u32,
    roster_idx: u32,
    path: DirectPathMsg,
}

impl HandshakeParams {
    pub fn new(prior_epoch: u32, roster_idx: u32, path: DirectPathMsg) -> Self {
        HandshakeParams {
            prior_epoch,
            roster_idx,
            path,
        }
    }

    pub fn hash(&self) -> Digest {
        hash_encodable(&self)
    }

    pub fn into_export(self) -> ExportHandshake {
        ExportHandshake::new(
            self.prior_epoch,
            self.roster_idx,
            bincode::serialize(&self).unwrap(),
        )
    }

    pub fn from_export(export: ExportHandshake) -> Result<Self> {
        bincode::deserialize(&export.handshake()[..]).map_err(Into::into)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(bytes)
    }

    pub fn prior_epoch(&self) -> u32 {
        self.prior_epoch
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn path(&self) -> &DirectPathMsg {
        &self.path
    }
}

/// Encrypted direct path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPathMsg {
    pub node_msgs: Vec<DirectPathNodeMsg>,
}

impl DirectPathMsg {
    pub fn new(node_msgs: Vec<DirectPathNodeMsg>) -> Self {
        DirectPathMsg { node_msgs }
    }
}

/// Containes a direct path node's public key and encrypted secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPathNodeMsg {
    pub public_key: DhPubKey,
    pub node_secrets: Vec<EciesCiphertext>,
}

impl DirectPathNodeMsg {
    pub fn new(public_key: DhPubKey, node_secrets: Vec<EciesCiphertext>) -> Self {
        DirectPathNodeMsg {
            public_key,
            node_secrets,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PathSecretSource {
    Local,
    Remote(String),
    #[cfg(debug_assertions)]
    LocalTestKV(PathSecretKVS),
}

#[derive(Debug, Clone, Default)]
pub struct PathSecretKVS(HashMap<AccessKey, PathSecret>);

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct AccessKey {
    roster_idx: u32,
    epoch: u32,
}

impl AccessKey {
    pub fn new(roster_idx: u32, epoch: u32) -> Self {
        AccessKey { roster_idx, epoch }
    }
}

impl PathSecretKVS {
    pub fn new() -> Self {
        let map: HashMap<AccessKey, PathSecret> = HashMap::new();
        PathSecretKVS(map)
    }

    pub fn get(&self, roster_idx: u32, epoch: u32) -> Option<&PathSecret> {
        let key = AccessKey { roster_idx, epoch };
        self.0.get(&key)
    }

    pub fn insert_random_path_secret<R: CryptoRng>(
        &mut self,
        roster_idx: u32,
        epoch: u32,
        csprng: &mut R,
    ) {
        let key = AccessKey { roster_idx, epoch };
        let value = PathSecret::new_from_random(csprng);
        self.0.insert(key, value);
    }
}

#[derive(Debug, Clone)]
pub struct CurrentPathSecret(pub Arc<RwLock<PathSecret>>);

impl CurrentPathSecret {
    pub fn new_from_random() -> Self {
        let path_secret = PathSecret::new_from_random_sgx();
        CurrentPathSecret(Arc::new(RwLock::new(path_secret)))
    }
}
