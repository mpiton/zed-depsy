//! Zed extension for Depsy - dependency management with version hints,
//! updates, and vulnerability detection.

use sha2::{Digest, Sha256};
use zed_extension_api::{
    self as zed, LanguageServerId, Result,
    http_client::{HttpMethod, HttpRequest, RedirectPolicy},
};

/// Tag of the only language-server release this extension installs.
///
/// The release whose version equals the extension's own version. The three
/// manifests (`depsy-zed/Cargo.toml`, `depsy-zed/extension.toml`,
/// `depsy-lsp/Cargo.toml`) must therefore be bumped together; a unit test
/// enforces it.
const RELEASE_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Base URL of the release assets on GitHub.
const RELEASE_URL: &str = "https://github.com/mpiton/zed-depsy/releases/download";

/// The Depsy extension.
struct DepsyExtension;

/// Fetches the SHA256 checksum for a release asset from GitHub.
///
/// Returns `Ok(Some(checksum))` if found, `Ok(None)` if the checksum file
/// doesn't exist (for backwards compatibility with old releases), or an
/// error if the fetch fails.
fn fetch_checksum(release_version: &str, asset_name: &str) -> Result<Option<String>> {
    let checksum_url = format!("{RELEASE_URL}/{release_version}/{asset_name}.binary.sha256");

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

/// Returns whether `path` exists and is a regular file.
fn is_file(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// Parses the version out of a managed binary directory name.
///
/// Managed binaries live in `depsy-lsp-vX.Y.Z` directories; any other name
/// yields `None`.
fn managed_version(dir_name: &str) -> Option<(u64, u64, u64)> {
    let mut parts = dir_name
        .strip_prefix("depsy-lsp-v")?
        .splitn(3, '.')
        .map(|part| part.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// Picks the managed binary directory with the highest version among `dirs`.
///
/// Directories for which `has_binary` is false are ignored.
fn newest_managed_dir(
    dirs: impl IntoIterator<Item = String>,
    has_binary: impl Fn(&str) -> bool,
) -> Option<String> {
    dirs.into_iter()
        .filter_map(|dir| managed_version(&dir).map(|version| (version, dir)))
        .filter(|(_, dir)| has_binary(dir))
        .max_by_key(|(version, _)| *version)
        .map(|(_, dir)| dir)
}

/// Returns the path of the newest managed binary in the extension directory.
fn newest_managed_binary(binary_name: &str) -> Option<String> {
    let dirs = std::fs::read_dir(".")
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok());
    newest_managed_dir(dirs, |dir| is_file(&format!("{dir}/{binary_name}")))
        .map(|dir| format!("{dir}/{binary_name}"))
}

/// Removes every managed binary directory except `keep`.
fn remove_other_managed_binaries(keep: &str) {
    let Ok(entries) = std::fs::read_dir(".") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name != keep && managed_version(name).is_some())
        {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Downloads the pinned release into `version_dir` and verifies its checksum.
///
/// # Errors
/// Fails when the download or the checksum fetch fails, or when the
/// checksum of the extracted binary at `binary_path` does not match.
fn download_and_verify(version_dir: &str, binary_path: &str) -> Result<()> {
    let (platform, arch) = zed::current_platform();
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

    zed::download_file(
        &format!("{RELEASE_URL}/{RELEASE_TAG}/{asset_name}"),
        version_dir,
        file_type,
    )
    .map_err(|e| format!("Failed to download: {e}"))?;

    let checksum_name = asset_name
        .strip_suffix(".tar.gz")
        .or_else(|| asset_name.strip_suffix(".zip"))
        .unwrap_or(&asset_name);

    if let Some(expected_checksum) = fetch_checksum(RELEASE_TAG, checksum_name)? {
        verify_checksum(binary_path, &expected_checksum)?;
    }
    Ok(())
}

/// Installs the pinned release into `version_dir`, reporting progress to Zed.
///
/// On success every other managed binary is removed. On failure `version_dir`
/// is removed, so an unverified download is never started at a later launch.
///
/// # Errors
/// See [`download_and_verify`].
fn install_release(
    language_server_id: &LanguageServerId,
    version_dir: &str,
    binary_path: &str,
) -> Result<()> {
    zed::set_language_server_installation_status(
        language_server_id,
        &zed::LanguageServerInstallationStatus::Downloading,
    );
    let result = download_and_verify(version_dir, binary_path);
    zed::set_language_server_installation_status(
        language_server_id,
        &zed::LanguageServerInstallationStatus::None,
    );

    if result.is_ok() {
        remove_other_managed_binaries(version_dir);
    } else {
        let _ = std::fs::remove_dir_all(version_dir);
    }
    result
}

/// Returns the path to the LSP binary, installing the pinned release if needed.
///
/// Once the pinned release is on disk no network request is made. When it
/// cannot be installed, the newest managed binary left by an earlier release
/// is started instead and a line is printed on stderr.
///
/// # Errors
/// Fails when the pinned release cannot be installed and no managed binary
/// is present.
fn language_server_binary_path(language_server_id: &LanguageServerId) -> Result<String> {
    let binary_name = match zed::current_platform().0 {
        zed::Os::Mac | zed::Os::Linux => "depsy-lsp",
        zed::Os::Windows => "depsy-lsp.exe",
    };
    let version_dir = format!("depsy-lsp-{RELEASE_TAG}");
    let binary_path = format!("{version_dir}/{binary_name}");
    if is_file(&binary_path) {
        return Ok(binary_path);
    }

    let Err(error) = install_release(language_server_id, &version_dir, &binary_path) else {
        return Ok(binary_path);
    };
    let Some(fallback) = newest_managed_binary(binary_name) else {
        return Err(format!(
            "depsy-lsp {RELEASE_TAG} could not be installed ({error}) and no earlier release \
             is installed. If github.com is unreachable, point `lsp.depsy.binary.path` in Zed \
             settings to a depsy-lsp binary you provide (see \"Offline / Air-Gapped \
             Installation\" in the README)."
        ));
    };
    eprintln!(
        "depsy: could not install depsy-lsp {RELEASE_TAG} ({error}); starting {fallback} instead"
    );
    Ok(fallback)
}

impl zed::Extension for DepsyExtension {
    fn new() -> Self {
        Self
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
        let binary_path = language_server_binary_path(language_server_id)?;

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

    #[test]
    fn picks_the_highest_version_numerically() {
        let dirs = [
            "depsy-lsp-v2.0.9",
            "depsy-lsp-v2.0.10",
            "depsy-lsp-v1.11.0",
            "depsy-lsp-v2.1",
            "html",
        ]
        .map(String::from);

        assert_eq!(
            newest_managed_dir(dirs, |_| true).as_deref(),
            Some("depsy-lsp-v2.0.10")
        );
    }

    #[test]
    fn skips_directories_without_a_binary() {
        let dirs = ["depsy-lsp-v2.0.2", "depsy-lsp-v2.0.1"].map(String::from);

        assert_eq!(
            newest_managed_dir(dirs.clone(), |dir| dir == "depsy-lsp-v2.0.1").as_deref(),
            Some("depsy-lsp-v2.0.1")
        );
        assert_eq!(newest_managed_dir(dirs, |_| false), None);
    }

    /// The extension installs the release tagged with its own version, so the
    /// three manifests must be bumped together.
    #[test]
    fn release_tag_matches_extension_and_language_server_versions() {
        let expected = format!("version = \"{}\"", env!("CARGO_PKG_VERSION"));
        for manifest in [
            include_str!("../extension.toml"),
            include_str!("../../depsy-lsp/Cargo.toml"),
        ] {
            let version_line = manifest
                .lines()
                .find(|line| line.starts_with("version = "))
                .unwrap();
            assert_eq!(version_line, expected);
        }
    }
}

zed::register_extension!(DepsyExtension);
