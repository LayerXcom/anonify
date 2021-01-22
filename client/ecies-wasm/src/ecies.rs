use super::{
    dh::{decapsulate, encapsulate, DhPrivateKey, DhPubKey},
    hkdf,
    hmac::HmacKey,
};
use anyhow::{anyhow, Result};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use serde::{Deserialize, Serialize};
use codec::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode, Default, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct EciesCiphertext {
    ephemeral_public_key: DhPubKey,
    ciphertext: Vec<u8>,
}

impl EciesCiphertext {
    pub fn encrypt(others_pub_key: &DhPubKey, mut plaintext: Vec<u8>) -> Result<Self> {
        let my_ephemeral_secret = DhPrivateKey::from_random()?;
        let my_ephemeral_pub_key = DhPubKey::from_private_key(&my_ephemeral_secret);

        let aes_key = encapsulate(&my_ephemeral_secret, &others_pub_key)?;
        let (ub_key, nonce_seq) = derive_ecies_key_nonce(&aes_key)?;
        let mut sealing_key = SealingKey::new(ub_key, nonce_seq);
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut plaintext)
            .map_err(|e| anyhow!("{:?}", e))?;

        let ciphertext = plaintext;

        Ok(EciesCiphertext {
            ephemeral_public_key: my_ephemeral_pub_key,
            ciphertext,
        })
    }

    pub fn decrypt(self, my_priv_key: &DhPrivateKey) -> Result<Vec<u8>> {
        let aes_key = decapsulate(&my_priv_key, &self.ephemeral_public_key)?;
        let (ub_key, nonce_seq) = derive_ecies_key_nonce(&aes_key)?;
        let mut opening_key = OpeningKey::new(ub_key, nonce_seq);

        let mut ciphertext = self.ciphertext;
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut ciphertext)
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(plaintext.to_vec())
    }
}

#[derive(Debug, Encode)]
struct EciesLabel {
    length: u16,
    label: Vec<u8>,
}

impl EciesLabel {
    pub fn new(label: &[u8], length: u16) -> Self {
        EciesLabel {
            length,
            label: [b"anonifyecies", label].concat(),
        }
    }
}

fn derive_ecies_key_nonce(shared_secret_bytes: &[u8]) -> Result<(UnboundKey, OneNonceSequence)> {
    let key_label = EciesLabel::new(b"key", AES_256_GCM_KEY_SIZE as u16);
    let nonce_label = EciesLabel::new(b"nonce", AES_256_GCM_NONCE_SIZE as u16);

    let prk = HmacKey::from(shared_secret_bytes);
    let mut key_buf = [0u8; AES_256_GCM_KEY_SIZE];
    let mut nonce_buf = [0u8; AES_256_GCM_NONCE_SIZE];

    hkdf::expand(&prk, &key_label, &mut key_buf[..], hkdf::Aes256GcmKey)?;
    hkdf::expand(&prk, &nonce_label, &mut nonce_buf[..], hkdf::Aes256GcmNonce)?;

    let ub_key = UnboundKey::new(&AES_256_GCM, &key_buf).map_err(|e| anyhow!("{:?}", e))?;
    let nonce = Nonce::assume_unique_for_key(nonce_buf);
    let nonce_seq = OneNonceSequence::new(nonce);

    Ok((ub_key, nonce_seq))
}

pub const AES_256_GCM_KEY_SIZE: usize = 256 / 8;
pub const AES_256_GCM_NONCE_SIZE: usize = 96 / 8;

/// A sequences of unique nonces.
/// See: https://briansmith.org/rustdoc/ring/aead/trait.NonceSequence.html
pub struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    pub fn new(nonce: Nonce) -> Self {
        OneNonceSequence(Some(nonce))
    }
}

impl NonceSequence for OneNonceSequence {
    fn advance(
        &mut self,
    ) -> std::result::Result<Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}
