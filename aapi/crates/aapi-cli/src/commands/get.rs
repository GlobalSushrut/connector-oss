//! Get command - retrieve a VĀKYA by ID

use aapi_sdk::{AapiClient, ClientConfig};

pub async fn run(
    gateway: &str,
    vakya_id: String,
    include_effects: bool,
    include_receipt: bool,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new(gateway);
    let client = AapiClient::new(config)?;

    let vakya = client.get_vakya(&vakya_id).await?;

    match format {
        "json" => {
            let mut output = serde_json::json!({
                "vakya": vakya
            });

            if include_effects {
                let effects = client.get_effects(&vakya_id).await?;
                output["effects"] = serde_json::to_value(effects)?;
            }

            if include_receipt {
                if let Ok(receipt) = client.get_receipt(&vakya_id).await {
                    output["receipt"] = serde_json::to_value(receipt)?;
                }
            }

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            println!("VĀKYA: {}", vakya.vakya_id);
            println!("  Hash:     {}", vakya.vakya_hash);
            println!("  Actor:    {}", vakya.karta_pid);
            println!("  Resource: {}", vakya.karma_rid);
            println!("  Action:   {}", vakya.kriya_action);
            println!("  Created:  {}", vakya.created_at);

            if include_effects {
                let effects = client.get_effects(&vakya_id).await?;
                println!("\nEffects ({}):", effects.len());
                for effect in effects {
                    println!("  - {} on {} ({})", effect.effect_bucket, effect.target_rid, effect.id);
                }
            }

            if include_receipt {
                if let Ok(receipt) = client.get_receipt(&vakya_id).await {
                    println!("\nReceipt:");
                    println!("  Status:   {}", receipt.reason_code);
                    println!("  Executor: {}", receipt.executor_id);
                    if let Some(duration) = receipt.duration_ms {
                        println!("  Duration: {}ms", duration);
                    }
                }
            }
        }
    }

    Ok(())
}
