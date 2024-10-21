use anyhow::Result;
use std::{fs, path::Path};

use securedrop_protocol::pki;

const KEY_FOLDER: &str = "keys";

fn initialize_keys() -> Result<()> {
    let folder = Path::new(KEY_FOLDER);
    if !folder.exists() {
        fs::create_dir(folder)?;
    }
    println!("Storing keys in folder: {}", folder.display());
    // Create root and intermediate keys
    let mut root = pki::generate_signing_keypair(folder, "root")?;
    println!("Generated root key");
    let mut intermediate =
        pki::generate_signing_keypair(folder, "intermediate")?;
    let sig =
        pki::sign_data(&mut root, &intermediate.verifying_key().to_bytes());
    fs::write(folder.join("intermediate.sig"), sig)?;
    // Now verify the root and intermediate signatures
    pki::verify_root_intermediate(folder)?;

    println!("Generated and signed intermediate key");

    // Create a journalist
    let journo_folder = folder.join("journalist");
    if !journo_folder.exists() {
        fs::create_dir(&journo_folder)?;
    }
    for i in 1..=3 {
        pki::generate_journalist(
            &journo_folder,
            &mut intermediate,
            &format!("journalist{i}"),
        )?;
        println!("Generated and signed journalist{i} key");
    }

    println!("Done!");
    Ok(())
}

fn main() -> Result<()> {
    initialize_keys()?;
    Ok(())
}
