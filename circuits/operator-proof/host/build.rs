use zkm_build::build_program;

const ENV_FIXED_WATCHTOWER_KEYS: &str = "FIXED_WATCHTOWER_XONLY_PUBLIC_KEYS";

fn main() {
    println!("cargo:rerun-if-env-changed={ENV_FIXED_WATCHTOWER_KEYS}");
    if std::env::var(ENV_FIXED_WATCHTOWER_KEYS).is_err() {
        println!(
            "cargo:warning={ENV_FIXED_WATCHTOWER_KEYS} is not set; building operator guest with an empty fixed watchtower list"
        );
    }
    build_program("../guest");
}
