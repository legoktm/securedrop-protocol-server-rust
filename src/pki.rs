use anyhow::{Context, Result};
use blake2b_simd::Params as Blake2bParams;
use crypto_box::SecretKey;
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, Verifier,
    VerifyingKey,
};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
pub struct RootKeyPair {
    #[serde(with = "serde_base64")]
    secret: [u8; 32],
    #[serde(with = "serde_base64")]
    public: [u8; 32],
}

impl RootKeyPair {
    pub fn as_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SigningKeyPair {
    #[serde(with = "serde_base64")]
    secret: [u8; 32],
    #[serde(with = "serde_base64")]
    public: [u8; 32],
    #[serde(with = "serde_base64")]
    signature: [u8; 64],
}

impl SigningKeyPair {
    fn as_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret)
    }

    fn verify(&self, signer: &mut SigningKey) -> Result<()> {
        let sig = Signature::from_slice(&self.signature)?;
        signer.verify(&self.public, &sig)?;
        Ok(())
    }
}

pub fn generate_root_keypair() -> RootKeyPair {
    let mut csprng = OsRng;
    let secret_key = SigningKey::generate(&mut csprng);
    RootKeyPair {
        secret: secret_key.to_bytes(),
        public: secret_key.verifying_key().to_bytes(),
    }
}

/// Generate a signing key pair. This is used for the root
/// and intermediate keys.
pub fn generate_signed_keypair(signer: &mut SigningKey) -> SigningKeyPair {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    // sign the public key
    let signature = sign_data(signer, &signing_key.verifying_key().to_bytes());
    SigningKeyPair {
        secret: signing_key.to_bytes(),
        public: signing_key.verifying_key().to_bytes(),
        signature,
    }
}

/// Sign a key using another key. Used to establish a chain of trust from the
/// root -> intermediate -> journalist.
// TODO: Add type level safety that we only sign public keys
fn sign_data(signer: &mut SigningKey, bytes: &[u8]) -> [u8; 64] {
    let signature = signer.sign(bytes);
    // Verify the signature we just created
    assert!(signer.verify(bytes, &signature).is_ok());
    signature.to_bytes()
}

fn load_intermediate_key() -> Result<SigningKeyPair> {
    // FIXME: hardcoded path
    // TODO: remove i/o from this function
    let key: SigningKeyPair =
        serde_json::from_str(&fs::read_to_string("keys/intermediate.key")?)?;
    Ok(key)
}

/// Verify a signature from the intermediate key
pub fn verify_intermediate_signature(
    contents: &[u8],
    signature: &[u8],
) -> Result<()> {
    let intermediate = load_intermediate_key()?;
    intermediate
        .as_signing_key()
        .verify(contents, &Signature::from_slice(signature)?)?;
    Ok(())
}

pub fn verify_root_intermediate(folder: &Path) -> Result<()> {
    // TODO: remove i/o from this function
    // Load the root and intermediate keys
    let root: RootKeyPair =
        serde_json::from_str(&fs::read_to_string(folder.join("root.key"))?)?;
    let intermediate: SigningKeyPair = serde_json::from_str(
        &fs::read_to_string(folder.join("intermediate.key"))?,
    )?;
    // Verify the signature created by the root key of the intermediate key
    intermediate.verify(&mut root.as_signing_key())
}

pub(crate) fn generate_encrypting_keypair(
    signer: &mut SigningKey,
) -> EncryptingKeyPair {
    let mut csprng = OsRng;
    let secret_key = SecretKey::generate(&mut csprng);
    let signature = sign_data(signer, &secret_key.public_key().to_bytes());
    EncryptingKeyPair {
        secret: secret_key.to_bytes(),
        public: secret_key.public_key().to_bytes(),
        signature,
    }
}

mod serde_base64 {
    use base64::{prelude::BASE64_STANDARD, Engine};
    use serde::Deserialize;

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(data))
    }

    pub fn deserialize<'de, D, const T: usize>(
        deserializer: D,
    ) -> Result<[u8; T], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)?
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptingKeyPair {
    #[serde(with = "serde_base64")]
    secret: [u8; 32],
    #[serde(with = "serde_base64")]
    public: [u8; 32],
    #[serde(with = "serde_base64")]
    signature: [u8; 64],
}

#[derive(Serialize, Deserialize)]
pub struct Journalist {
    signing: SigningKeyPair,
    encrypting: EncryptingKeyPair,
}

impl Journalist {
    fn public(&self) -> PublicJournalist {
        PublicJournalist {
            signing_key: self.signing.public,
            signing_signature: self.signing.signature,
            encrypting_key: self.encrypting.public,
            encrypting_signature: self.encrypting.signature,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicJournalist {
    #[serde(with = "serde_base64")]
    pub signing_key: [u8; 32],
    #[serde(with = "serde_base64")]
    pub signing_signature: [u8; 64],
    #[serde(with = "serde_base64")]
    pub encrypting_key: [u8; 32],
    #[serde(with = "serde_base64")]
    pub encrypting_signature: [u8; 64],
}

#[derive(Serialize, Deserialize)]
pub struct PublicEphemeralKey {
    #[serde(with = "serde_base64")]
    pub key: [u8; 32],
    #[serde(with = "serde_base64")]
    pub signature: [u8; 64],
}

impl PublicEphemeralKey {
    // FIXME: this is awkward
    fn from_keypair(pair: &EncryptingKeyPair) -> Self {
        Self {
            key: pair.public,
            signature: pair.signature,
        }
    }
}

pub fn verify_ephemeral_signature(
    journalist: &PublicJournalist,
    ephemeral: &PublicEphemeralKey,
) -> Result<()> {
    VerifyingKey::from_bytes(&journalist.signing_key)?
        .verify(
            &ephemeral.key,
            &Signature::from_slice(&ephemeral.signature)?,
        )
        .context("Failed to verify ephemeral signature")
}

/// Generate keys for a journalist, which is a signing keypair and a encrypting keypair.
pub fn generate_journalist(intermediate: &SigningKeyPair) -> Journalist {
    let signing_key =
        generate_signed_keypair(&mut intermediate.as_signing_key());
    let encrypting_key =
        generate_encrypting_keypair(&mut intermediate.as_signing_key());
    Journalist {
        signing: signing_key,
        encrypting: encrypting_key,
    }
}

pub fn generate_ephemeral_keypair(
    journalist: &Journalist,
) -> EncryptingKeyPair {
    let pair =
        generate_encrypting_keypair(&mut journalist.signing.as_signing_key());
    assert!(verify_ephemeral_signature(
        &journalist.public(),
        &PublicEphemeralKey::from_keypair(&pair)
    )
    .is_ok());
    pair
}

pub fn generate_passphrase() -> [u8; 32] {
    let mut csprng = OsRng;
    let mut passphrase = [0u8; 32];
    csprng.fill(&mut passphrase);
    passphrase
}

/// this function derives an EC keypair given the passphrase
/// the prefix is useful for isolating the key. A hash/kdf is used to generate the actual seeds
fn derive_source_key(
    passphrase: &[u8; 32],
    key_isolation_prefix: &'static str,
) -> [u8; 32] {
    Blake2bParams::new()
        .hash_length(32)
        .salt(key_isolation_prefix.as_bytes())
        .hash(passphrase)
        .as_array()[0..32]
        .try_into()
        // we get 64 bytes from blake2b, take the first 32 to stick into a constant-length
        // array, which should be infallible
        .unwrap_or_else(|_| {
            unreachable!("32 bytes did not fit into a 32-length array")
        })
}

struct SourceKeys {
    // [SOURCE] LONG-TERM MESSAGE KEY
    encryption: SecretKey,
    // [SOURCE] LONG-TERM CHALLENGE KEY
    signing: SigningKey,
}

impl SourceKeys {
    fn new(passphrase: [u8; 32]) -> Self {
        Self {
            encryption: SecretKey::from(derive_source_key(
                &passphrase,
                "encryption_key-",
            )),
            signing: SigningKey::from(derive_source_key(
                &passphrase,
                "fetching_key-",
            )),
        }
    }
}
