use anyhow::Result;
use base64::prelude::*;
use crypto_box::SecretKey;
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use rand::rngs::OsRng;
use std::{fs, path::Path};

/// Generate a signing key pair and save it to disk. This is used for the root
/// and intermediate keys.
pub(crate) fn generate_signing_keypair(
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
pub(crate) fn sign_data(signer: &mut SigningKey, bytes: &[u8]) -> String {
    let signature = signer.sign(bytes);
    // Verify the signature we just created
    assert!(signer.verify(bytes, &signature).is_ok());
    BASE64_STANDARD.encode(signature.to_bytes())
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
pub(crate) fn generate_journalist(
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
