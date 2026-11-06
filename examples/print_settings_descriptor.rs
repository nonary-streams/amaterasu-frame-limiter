//! Print plugin-owned metadata for a target package's extension registry.
use amaterasu_frame_limiter::{Platform, settings_descriptor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let platform = match std::env::args().nth(1).as_deref() {
        Some("linux") => Platform::Linux,
        Some("windows") => Platform::Windows,
        Some("macos") => Platform::Macos,
        _ => return Err("usage: print_settings_descriptor linux|windows|macos".into()),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&settings_descriptor::descriptor(platform))?
    );
    Ok(())
}
