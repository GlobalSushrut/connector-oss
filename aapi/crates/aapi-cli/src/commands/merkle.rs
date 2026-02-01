//! Merkle tree commands

use aapi_sdk::{AapiClient, ClientConfig};

pub async fn root(gateway: &str, tree_type: String, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new(gateway);
    let client = AapiClient::new(config)?;

    let response = client.get_merkle_root(&tree_type).await?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        _ => {
            println!("Merkle Root ({}):", response.tree_type);
            match response.root_hash {
                Some(hash) => println!("  Hash: {}", hash),
                None => println!("  Hash: (empty tree)"),
            }
            println!("  Timestamp: {}", response.timestamp);
        }
    }

    Ok(())
}

pub async fn proof(gateway: &str, tree_type: String, index: i64, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new(gateway);
    let client = AapiClient::new(config)?;

    let response = client.get_inclusion_proof(&tree_type, index).await?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        _ => {
            println!("Inclusion Proof:");
            println!("  Leaf Hash:  {}", response.leaf_hash);
            println!("  Leaf Index: {}", response.leaf_index);
            println!("  Tree Size:  {}", response.tree_size);
            println!("  Root Hash:  {}", response.root_hash);
            println!("  Proof Path ({} nodes):", response.proof_hashes.len());
            for (i, node) in response.proof_hashes.iter().enumerate() {
                println!("    {}: {} ({})", i, node.hash, node.position);
            }
        }
    }

    Ok(())
}
