// Quick test to verify registry date fetching
use depsy_lsp::registries::{
    Registry, crates_io::CratesIoRegistry, npm::NpmRegistry, pypi::PyPiRegistry,
};

/// Quick async test program that fetches and prints version information from multiple package registries.
///
/// The program queries crates.io for "serde", npm for "express", and PyPI for "flask".
/// For each registry it prints a sample of the first three version strings, the total
/// count of release dates, and a sample of the first three release dates. Errors are
/// printed to standard output.
///
/// # Examples
///
/// ```text
/// # Run the compiled binary to see registry outputs:
/// cargo run --bin registry_test
/// ```
#[tokio::main]
async fn main() {
    println!("=== Testing crates.io (serde) ===");
    let registry = CratesIoRegistry::default();
    match registry.get_version_info("serde").await {
        Ok(info) => {
            println!(
                "Versions: {:?}",
                info.versions.iter().take(3).collect::<Vec<_>>()
            );
            println!("Release dates count: {}", info.release_dates.len());
            println!(
                "Sample dates: {:?}",
                info.release_dates.iter().take(3).collect::<Vec<_>>()
            );
        }
        Err(e) => println!("Error: {e}"),
    }

    println!("\n=== Testing npm (express) ===");
    let registry = NpmRegistry::default();
    match registry.get_version_info("express").await {
        Ok(info) => {
            println!(
                "Versions: {:?}",
                info.versions.iter().take(3).collect::<Vec<_>>()
            );
            println!("Release dates count: {}", info.release_dates.len());
            println!(
                "Sample dates: {:?}",
                info.release_dates.iter().take(3).collect::<Vec<_>>()
            );
        }
        Err(e) => println!("Error: {e}"),
    }

    println!("\n=== Testing PyPI (flask) ===");
    let registry = PyPiRegistry::default();
    match registry.get_version_info("flask").await {
        Ok(info) => {
            println!(
                "Versions: {:?}",
                info.versions.iter().take(3).collect::<Vec<_>>()
            );
            println!("Release dates count: {}", info.release_dates.len());
            println!(
                "Sample dates: {:?}",
                info.release_dates.iter().take(3).collect::<Vec<_>>()
            );
        }
        Err(e) => println!("Error: {e}"),
    }
}
