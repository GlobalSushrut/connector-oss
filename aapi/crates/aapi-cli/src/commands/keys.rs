//! Key management commands

use aapi_crypto::{KeyStore, KeyPurpose, KeyPair};

pub fn generate(purpose: String, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_purpose = match purpose.as_str() {
        "signing" | "vakya" => KeyPurpose::VakyaSigning,
        "capability" | "cap" => KeyPurpose::CapabilitySigning,
        "receipt" => KeyPurpose::ReceiptSigning,
        _ => KeyPurpose::General,
    };

    let key_pair = KeyPair::generate(key_purpose);
    let public_info = key_pair.to_public_info();

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&public_info)?);
        }
        _ => {
            println!("Generated new key pair:");
            println!("  Key ID:     {}", public_info.key_id.0);
            println!("  Algorithm:  {}", public_info.algorithm);
            println!("  Purpose:    {:?}", public_info.purpose);
            println!("  Public Key: {}", public_info.public_key);
            println!("  Created:    {}", public_info.created_at);
            println!();
            println!("⚠️  Store the private key securely! This is a one-time display.");
        }
    }

    Ok(())
}

pub fn list(format: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Note: In a real implementation, this would read from a key store file
    println!("Key listing requires a configured key store.");
    println!("Use 'aapi keys generate' to create new keys.");
    Ok(())
}

pub fn export(key_id: String, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Note: In a real implementation, this would read from a key store file
    println!("Key export requires a configured key store.");
    println!("Key ID: {}", key_id);
    Ok(())
}
