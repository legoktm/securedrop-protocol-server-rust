use anyhow::Result;
use crypto_box::SecretKey;
use ed25519_dalek::{ed25519::signature::SignerMut, Signature, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
pub struct RootKeyPair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl RootKeyPair {
    pub fn as_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignedKeyPair {
    secret: [u8; 32],
    public: [u8; 32],
    // TODO: Make constant length, serde doesn't support arrays over 32:
    // https://stackoverflow.com/questions/48782047/how-do-i-use-serde-to-deserialize-arrays-greater-than-32-elements-such-as-u8
    signature: Vec<u8>,
}

impl SignedKeyPair {
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
pub fn generate_signed_keypair(signer: &mut SigningKey) -> SignedKeyPair {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    // sign the public key
    let signature = sign_data(signer, &signing_key.verifying_key().to_bytes());
    SignedKeyPair {
        secret: signing_key.to_bytes(),
        public: signing_key.verifying_key().to_bytes(),
        signature: signature.to_vec(),
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

fn load_intermediate_key() -> Result<SignedKeyPair> {
    // FIXME: hardcoded path
    // TODO: remove i/o from this function
    let key: SignedKeyPair =
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
    let intermediate: SignedKeyPair = serde_json::from_str(
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
        signature: signature.to_vec(),
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptingKeyPair {
    secret: [u8; 32],
    public: [u8; 32],
    // TODO: convert to constant size (see above)
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Journalist {
    signing: SignedKeyPair,
    encrypting: EncryptingKeyPair,
}

#[derive(Serialize, Deserialize)]
pub struct PublicJournalist {
    pub signing_key: [u8; 32],
    // TODO: convert to constant size
    pub signing_signature: Vec<u8>,
    pub encrypting_key: [u8; 32],
    // TODO: convert to constant size
    pub encrypting_signature: Vec<u8>,
}

/// Generate keys for a journalist, which is a signing keypair and a encrypting keypair.
// TODO: have our own type for a Journalist, that covers all the key files
pub fn generate_journalist(intermediate: &SignedKeyPair) -> Journalist {
    let signing_key =
        generate_signed_keypair(&mut intermediate.as_signing_key());
    let encrypting_key =
        generate_encrypting_keypair(&mut intermediate.as_signing_key());
    Journalist {
        signing: signing_key,
        encrypting: encrypting_key,
    }
}
