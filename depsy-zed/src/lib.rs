//! Zed extension for Depsy - dependency management with version hints,
//! updates, and vulnerability detection.

use sha2::{Digest, Sha256};
use zed_extension_api::{
    self as zed, LanguageServerId, Result,
    http_client::{HttpMethod, HttpRequest, RedirectPolicy},
};

/// The Depsy extension state.
struct DepsyExtension {
    /// Cached path to the LSP binary to avoid repeated lookups.
    cached_binary_path: Option<String>,
}

/// Fetches the SHA256 checksum for a release asset from GitHub.
///
/// Returns `Ok(Some(checksum))` if found, `Ok(None)` if the checksum file
/// doesn't exist (for backwards compatibility with old releases), or an
/// error if the fetch fails.
fn fetch_checksum(release_version: &str, asset_name: &str) -> Result<Option<String>> {
    let checksum_url = format!(
        "https://github.com/mpiton/zed-depsy/releases/download/{release_version}/{asset_name}.binary.sha256"
    );

    let request = HttpRequest::builder()
        .method(HttpMethod::Get)
        .url(&checksum_url)
        .redirect_policy(RedirectPolicy::FollowAll)
        .build()
        .map_err(|e| format!("Failed to build checksum request: {e}"))?;

    match request.fetch() {
        Ok(response) => {
            let body = String::from_utf8(response.body)
                .map_err(|e| format!("Invalid UTF-8 in checksum file: {e}"))?;
            let checksum = body
                .split_whitespace()
                .next()
                .ok_or("Empty checksum file")?
                .to_lowercase();
            Ok(Some(checksum))
        }
        Err(e) if e.contains("404") || e.contains("Not Found") => Ok(None),
        Err(e) => Err(format!("Failed to fetch checksum: {e}")),
    }
}

/// Computes the SHA256 hash of a file at the given path.
///
/// Returns the lowercase hex-encoded hash string.
fn compute_file_sha256(path: &str) -> Result<String> {
    let contents =
        std::fs::read(path).map_err(|e| format!("Failed to read file for checksum: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let hash = hasher.finalize();
    Ok(hash.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Verifies that a binary's SHA256 checksum matches the expected value.
///
/// Returns an error with a detailed message if verification fails,
/// indicating potential tampering.
fn verify_checksum(binary_path: &str, expected: &str) -> Result<()> {
    let actual = compute_file_sha256(binary_path)?;
    if actual != expected {
        return Err(format!(
            "Checksum verification failed!\n\
             Expected: {expected}\n\
             Actual: {actual}\n\
             \n\
             The downloaded binary may have been tampered with."
        ));
    }
    Ok(())
}

impl DepsyExtension {
    /// Returns the path to the LSP binary, downloading it if necessary.
    ///
    /// Downloads the appropriate binary for the current platform from GitHub
    /// releases, verifies its SHA256 checksum, and caches the path for
    /// subsequent calls.
    fn language_server_binary_path(
        &mut self,
        language_server_id: &LanguageServerId,
    ) -> Result<String> {
        // Return cached path if valid
        if let Some(path) = &self.cached_binary_path
            && std::fs::metadata(path)
                .map(|m| m.is_file())
                .unwrap_or(false)
        {
            return Ok(path.clone());
        }

        // Download from GitHub releases
        let (platform, arch) = zed::current_platform();
        let binary_name = match platform {
            zed::Os::Mac | zed::Os::Linux => "depsy-lsp",
            zed::Os::Windows => "depsy-lsp.exe",
        };

        let target = format!(
            "{}-{}",
            match arch {
                zed::Architecture::Aarch64 => "aarch64",
                zed::Architecture::X8664 => "x86_64",
                zed::Architecture::X86 => "x86",
            },
            match platform {
                zed::Os::Mac => "apple-darwin",
                zed::Os::Linux => "unknown-linux-gnu",
                zed::Os::Windows => "pc-windows-msvc",
            }
        );

        let (asset_name, file_type) = match platform {
            zed::Os::Windows => (
                format!("depsy-lsp-{target}.zip"),
                zed::DownloadedFileType::Zip,
            ),
            _ => (
                format!("depsy-lsp-{target}.tar.gz"),
                zed::DownloadedFileType::GzipTar,
            ),
        };

        let release = zed::latest_github_release(
            "mpiton/zed-depsy",
            zed::GithubReleaseOptions {
                require_assets: true,
                pre_release: false,
            },
        )?;

        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or_else(|| format!("No asset found matching {asset_name}"))?;

        let version_dir = format!("depsy-lsp-{}", release.version);
        let binary_path = format!("{version_dir}/{binary_name}");

        if !std::fs::metadata(&binary_path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            zed::set_language_server_installation_status(
                language_server_id,
                &zed::LanguageServerInstallationStatus::Downloading,
            );

            zed::download_file(&asset.download_url, &version_dir, file_type)
                .map_err(|e| format!("Failed to download: {e}"))?;

            let checksum_name = asset_name
                .strip_suffix(".tar.gz")
                .or_else(|| asset_name.strip_suffix(".zip"))
                .unwrap_or(&asset_name);

            if let Some(expected_checksum) = fetch_checksum(&release.version, checksum_name)? {
                verify_checksum(&binary_path, &expected_checksum)?;
            }

            zed::set_language_server_installation_status(
                language_server_id,
                &zed::LanguageServerInstallationStatus::None,
            );
        }

        self.cached_binary_path = Some(binary_path.clone());
        Ok(binary_path)
    }
}

impl zed::Extension for DepsyExtension {
    fn new() -> Self {
        Self {
            cached_binary_path: None,
        }
    }

    fn language_server_initialization_options(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        // Migration from the old `dependi` extension id: `lsp.dependi.initialization_options`
        // is used as the base, and `lsp.depsy.initialization_options` is merged over it by Zed.
        Ok(
            zed::settings::LspSettings::for_worktree("dependi", worktree)
                .ok()
                .and_then(|settings| settings.initialization_options),
        )
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        _worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let binary_path = self.language_server_binary_path(language_server_id)?;

        Ok(zed::Command {
            command: binary_path,
            args: vec![],
            env: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_lowercase_sha256() {
        let path = std::env::temp_dir().join(format!("depsy-sha256-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();

        let hash = compute_file_sha256(path.to_str().unwrap()).unwrap();

        std::fs::remove_file(path).unwrap();
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

zed::register_extension!(DepsyExtension);
