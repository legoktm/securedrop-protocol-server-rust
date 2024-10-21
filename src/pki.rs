use anyhow::Result;
use base64::prelude::*;
use crypto_box::{PublicKey, SecretKey};
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, Verifier,
    VerifyingKey,
};
use rand::rngs::OsRng;
use std::{fs, path::Path};

/// Generate a signing key pair and save it to disk. This is used for the root
/// and intermediate keys.
pub fn generate_signing_keypair(
    folder: &Path,
    name: &str,
) -> Result<SigningKey> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let secret = BASE64_STANDARD.encode(signing_key.to_bytes());
    let public = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());

    fs::write(folder.join(format!("{name}.secret")), secret)?;
    fs::write(folder.join(format!("{name}.public")), public)?;
    Ok(signing_key)
}

/// Sign a key using another key. Used to establish a chain of trust from the
/// root -> intermediate -> journalist.
// TODO: Add type level safety that we only sign public keys
pub fn sign_data(signer: &mut SigningKey, bytes: &[u8]) -> String {
    let signature = signer.sign(bytes);
    // Verify the signature we just created
    assert!(signer.verify(bytes, &signature).is_ok());
    BASE64_STANDARD.encode(signature.to_bytes())
}

fn load_verifying_key_from_file(
    folder: &Path,
    name: &str,
) -> Result<VerifyingKey> {
    let bytes = fs::read(folder.join(format!("{name}.public")))?;
    Ok(VerifyingKey::from_bytes(
        BASE64_STANDARD.decode(bytes)?.as_slice().try_into()?,
    )?)
}

pub fn load_verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
    Ok(VerifyingKey::from_bytes(
        BASE64_STANDARD.decode(bytes)?.as_slice().try_into()?,
    )?)
}

pub fn load_public_key(bytes: &[u8]) -> Result<PublicKey> {
    Ok(PublicKey::from_bytes(
        BASE64_STANDARD.decode(bytes)?.as_slice().try_into()?,
    ))
}

/// Verify a signature from the intermediate key
pub fn verify_intermediate_signature(
    contents: &[u8],
    signature: &[u8],
) -> Result<()> {
    let intermediate = load_verifying_key_from_bytes(contents)?;
    intermediate.verify(contents, &Signature::from_slice(signature)?)?;
    Ok(())
}

pub fn verify_root_intermediate(folder: &Path) -> Result<()> {
    // Load the root and intermediate keys
    let root = load_verifying_key_from_file(folder, "root")?;
    let intermediate = load_verifying_key_from_file(folder, "intermediate")?;
    let signature = fs::read(folder.join("intermediate.sig"))?;
    // Verify the signature created by the root key of the intermediate key
    root.verify(
        &intermediate.to_bytes(),
        &Signature::from_slice(&BASE64_STANDARD.decode(&signature)?)?,
    )?;
    Ok(())
}

pub(crate) fn generate_encrypting_keypair(
    folder: &Path,
    name: &str,
) -> Result<SecretKey> {
    let mut csprng = OsRng;
    let secret_key = SecretKey::generate(&mut csprng);
    let secret = BASE64_STANDARD.encode(secret_key.to_bytes());
    let public = BASE64_STANDARD.encode(secret_key.public_key().to_bytes());
    fs::write(folder.join(format!("{name}.secret")), secret)?;
    fs::write(folder.join(format!("{name}.public")), public)?;
    Ok(secret_key)
}

/// Generate keys for a journalist, which is a signing keypair and a encrypting keypair.
// TODO: have our own type for a Journalist, that covers all the key files
pub fn generate_journalist(
    folder: &Path,
    intermediate: &mut SigningKey,
    name: &str,
) -> Result<()> {
    let signing_key = generate_signing_keypair(folder, name)?;
    let signing_sig =
        sign_data(intermediate, &signing_key.verifying_key().to_bytes());
    fs::write(folder.join(format!("{name}.sig")), signing_sig)?;
    let encrypting_key =
        generate_encrypting_keypair(folder, &format!("{name}-fetching"))?;
    let encrypting_sig =
        sign_data(intermediate, &encrypting_key.public_key().to_bytes());
    fs::write(folder.join(format!("{name}-fetching.sig")), encrypting_sig)?;
    Ok(())
}
