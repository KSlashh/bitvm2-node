use std::{env, fs, path::PathBuf};

const ENV_FIXED_WATCHTOWER_KEYS: &str = "FIXED_WATCHTOWER_XONLY_PUBLIC_KEYS";

fn parse_xonly_key(raw: &str) -> Result<[u8; 32], String> {
    let hex = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = hex::decode(hex).map_err(|err| format!("invalid x-only public key hex: {err}"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!("x-only public key must be 32 bytes, got {}", bytes.len())
    })
}

fn fixed_watchtower_keys_from_env() -> Vec<[u8; 32]> {
    let value = match env::var(ENV_FIXED_WATCHTOWER_KEYS) {
        Ok(value) => value,
        Err(_) => {
            println!(
                "cargo:warning={ENV_FIXED_WATCHTOWER_KEYS} is not set; building operator guest with an empty fixed watchtower list"
            );
            return Vec::new();
        }
    };
    let keys = value
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(parse_xonly_key)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|err| panic!("invalid {ENV_FIXED_WATCHTOWER_KEYS}: {err}"));

    if keys.is_empty() {
        println!(
            "cargo:warning={ENV_FIXED_WATCHTOWER_KEYS} contains no keys; building operator guest with an empty fixed watchtower list"
        );
        return Vec::new();
    }
    if keys.len() > 256 {
        panic!("{ENV_FIXED_WATCHTOWER_KEYS} contains {} keys, max 256", keys.len());
    }
    keys
}

fn main() {
    println!("cargo:rerun-if-env-changed={ENV_FIXED_WATCHTOWER_KEYS}");

    let keys = fixed_watchtower_keys_from_env();
    let mut generated = String::new();
    generated.push_str(&format!("pub const FIXED_WATCHTOWER_COUNT: usize = {};\n", keys.len()));
    generated.push_str(&format!(
        "pub const FIXED_WATCHTOWER_XONLY_PUBLIC_KEYS: [[u8; 32]; {}] = [\n",
        keys.len()
    ));
    for key in keys {
        generated.push_str("    [");
        for (index, byte) in key.iter().enumerate() {
            if index > 0 {
                generated.push_str(", ");
            }
            generated.push_str(&format!("0x{byte:02x}"));
        }
        generated.push_str("],\n");
    }
    generated.push_str("];\n");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out_dir.join("fixed_watchtowers.rs"), generated)
        .expect("failed to write fixed_watchtowers.rs");
}
