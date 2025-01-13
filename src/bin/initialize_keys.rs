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
    let root = pki::generate_root_keypair();
    fs::write(folder.join("root.key"), serde_json::to_string(&root)?)?;
    println!("Generated root key");
    let intermediate = pki::generate_signed_keypair(&mut root.as_signing_key());
    fs::write(
        folder.join("intermediate.key"),
        serde_json::to_string(&intermediate)?,
    )?;
    // Now verify the root and intermediate signatures
    pki::verify_root_intermediate(folder)?;

    println!("Generated and signed intermediate key");

    // Create a journalist
    for i in 1..=3 {
        let journo_folder = folder.join(format!("journalist{i}"));
        if !journo_folder.exists() {
            fs::create_dir(&journo_folder)?;
        }
        let journalist = pki::generate_journalist(&intermediate);
        fs::write(
            journo_folder.join("main.key"),
            serde_json::to_string(&journalist)?,
        )?;
        println!("[{i}] Generated and signed main key");
        for e in 1..=30 {
            let ephemeral = pki::generate_ephemeral_keypair(&journalist);
            fs::write(
                journo_folder.join(format!("ephemeral{e}.key")),
                serde_json::to_string(&ephemeral)?,
            )?;
        }
        println!("[{i}] Generated ephemerals keys");
    }

    println!("Done!");
    Ok(())
}

fn main() -> Result<()> {
    initialize_keys()?;
    Ok(())
}
