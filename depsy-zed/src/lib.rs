//! Zed extension for Depsy - dependency management with version hints,
//! updates, and vulnerability detection.

use std::path::Path;

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

/// Why the pinned release could not be installed.
#[derive(Debug)]
enum InstallError {
    /// The release or its checksum file could not be fetched; an earlier
    /// release on disk may be started instead.
    Unavailable(String),
    /// The download does not match its published checksum and is not started.
    ChecksumMismatch(String),
}

/// Fetches the SHA256 checksum published on GitHub for a release asset.
///
/// Every release built by `.github/workflows/release.yml` publishes one, so a
/// missing checksum file is an error.
///
/// # Errors
/// Fails when the request cannot be built or answered, or when the checksum
/// file is empty or not UTF-8.
fn fetch_checksum(release_version: &str, asset_name: &str) -> Result<String> {
    let checksum_url = format!("{RELEASE_URL}/{release_version}/{asset_name}.binary.sha256");

    let request = HttpRequest::builder()
        .method(HttpMethod::Get)
        .url(&checksum_url)
        .redirect_policy(RedirectPolicy::FollowAll)
        .build()
        .map_err(|e| format!("Failed to build checksum request: {e}"))?;
    let response = request
        .fetch()
        .map_err(|e| format!("Failed to fetch checksum: {e}"))?;
    let body = String::from_utf8(response.body)
        .map_err(|e| format!("Invalid UTF-8 in checksum file: {e}"))?;
    Ok(body
        .split_whitespace()
        .next()
        .ok_or("Empty checksum file")?
        .to_lowercase())
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
/// # Errors
/// A binary that cannot be read is [`InstallError::Unavailable`]; a digest
/// that differs is [`InstallError::ChecksumMismatch`].
fn verify_checksum(binary_path: &str, expected: &str) -> Result<(), InstallError> {
    let actual = compute_file_sha256(binary_path).map_err(InstallError::Unavailable)?;
    if actual != expected {
        return Err(InstallError::ChecksumMismatch(format!(
            "Checksum verification failed!\n\
             Expected: {expected}\n\
             Actual: {actual}\n\
             \n\
             The downloaded binary may have been tampered with."
        )));
    }
    Ok(())
}

/// Parses the version out of a managed binary directory name.
///
/// Managed binaries live in `depsy-lsp-vX.Y.Z` directories; any other name,
/// including the `.partial` staging directory of a download, yields `None`.
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

/// Names of the managed binary directories under `base`.
fn managed_dirs(base: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| managed_version(name).is_some())
        .collect()
}

/// Returns the path, relative to `base`, of the newest managed binary.
fn newest_managed_binary(base: &Path, binary_name: &str) -> Option<String> {
    newest_managed_dir(managed_dirs(base), |dir| {
        base.join(dir).join(binary_name).is_file()
    })
    .map(|dir| format!("{dir}/{binary_name}"))
}

/// Removes `dir` and its contents, printing a line on stderr when that fails.
fn remove_release_dir(dir: &Path) {
    if let Err(error) = std::fs::remove_dir_all(dir)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("depsy: failed to remove {}: {error}", dir.display());
    }
}

/// Removes every managed binary directory under `base` except `keep`.
fn remove_other_managed_binaries(base: &Path, keep: &str) {
    for dir in managed_dirs(base) {
        if dir != keep {
            remove_release_dir(&base.join(dir));
        }
    }
}

/// Downloads the pinned release into `dir` and verifies its binary's checksum.
///
/// # Errors
/// A download or checksum fetch that fails is [`InstallError::Unavailable`];
/// see [`verify_checksum`] for the binary named `binary_name` in `dir`.
fn download_and_verify(dir: &str, binary_name: &str) -> Result<(), InstallError> {
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
        dir,
        file_type,
    )
    .map_err(|e| InstallError::Unavailable(format!("Failed to download: {e}")))?;

    let checksum_name = asset_name
        .strip_suffix(".tar.gz")
        .or_else(|| asset_name.strip_suffix(".zip"))
        .unwrap_or(&asset_name);

    let expected_checksum =
        fetch_checksum(RELEASE_TAG, checksum_name).map_err(InstallError::Unavailable)?;
    verify_checksum(&format!("{dir}/{binary_name}"), &expected_checksum)
}

/// Moves a verified download into `version_dir` and prunes older releases.
///
/// The download is expected in `{version_dir}.partial` under `base`. When
/// `downloaded` is an error that staging directory is removed instead, so
/// `version_dir` never holds an unverified binary.
///
/// # Errors
/// Returns the `downloaded` error, or [`InstallError::Unavailable`] when the
/// verified download cannot be moved into place.
fn finish_install(
    base: &Path,
    version_dir: &str,
    downloaded: Result<(), InstallError>,
) -> Result<(), InstallError> {
    let staging_dir = base.join(format!("{version_dir}.partial"));
    let result = downloaded.and_then(|()| {
        // A directory left by an older extension version would make the rename fail.
        remove_release_dir(&base.join(version_dir));
        std::fs::rename(&staging_dir, base.join(version_dir)).map_err(|e| {
            InstallError::Unavailable(format!("Failed to move the download into place: {e}"))
        })
    });

    if result.is_ok() {
        remove_other_managed_binaries(base, version_dir);
    } else {
        remove_release_dir(&staging_dir);
    }
    result
}

/// Installs the pinned release into `version_dir`, reporting progress to Zed.
///
/// # Errors
/// See [`download_and_verify`] and [`finish_install`].
fn install_release(
    language_server_id: &LanguageServerId,
    version_dir: &str,
    binary_name: &str,
) -> Result<(), InstallError> {
    zed::set_language_server_installation_status(
        language_server_id,
        &zed::LanguageServerInstallationStatus::Downloading,
    );
    let downloaded = download_and_verify(&format!("{version_dir}.partial"), binary_name);
    zed::set_language_server_installation_status(
        language_server_id,
        &zed::LanguageServerInstallationStatus::None,
    );
    finish_install(Path::new("."), version_dir, downloaded)
}

/// Picks the binary to start.
///
/// `binary_path` is returned when `installed` or once `install` succeeds.
/// Otherwise the earlier release returned by `fallback` is started and a line
/// is printed on stderr.
///
/// # Errors
/// A checksum mismatch is returned as is so that Zed reports it. Fails as well
/// when the pinned release cannot be fetched and `fallback` has nothing.
fn resolve_binary(
    binary_path: String,
    installed: bool,
    install: impl FnOnce() -> Result<(), InstallError>,
    fallback: impl FnOnce() -> Option<String>,
) -> Result<String> {
    if installed {
        return Ok(binary_path);
    }
    let error = match install() {
        Ok(()) => return Ok(binary_path),
        Err(InstallError::ChecksumMismatch(error)) => return Err(error),
        Err(InstallError::Unavailable(error)) => error,
    };
    let Some(fallback) = fallback() else {
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

/// Returns the path to the LSP binary, installing the pinned release if needed.
///
/// Once the pinned release is on disk no network request is made.
///
/// # Errors
/// See [`resolve_binary`].
fn language_server_binary_path(language_server_id: &LanguageServerId) -> Result<String> {
    let binary_name = match zed::current_platform().0 {
        zed::Os::Mac | zed::Os::Linux => "depsy-lsp",
        zed::Os::Windows => "depsy-lsp.exe",
    };
    let version_dir = format!("depsy-lsp-{RELEASE_TAG}");
    let binary_path = format!("{version_dir}/{binary_name}");
    let installed = Path::new(&binary_path).is_file();
    resolve_binary(
        binary_path,
        installed,
        || install_release(language_server_id, &version_dir, binary_name),
        || newest_managed_binary(Path::new("."), binary_name),
    )
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
    use std::cell::Cell;
    use std::path::PathBuf;

    use super::*;

    /// Creates an empty scratch directory unique to the calling test.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("depsy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Creates `dir/depsy-lsp` under `base`.
    fn write_binary(base: &Path, dir: &str) {
        std::fs::create_dir_all(base.join(dir)).unwrap();
        std::fs::write(base.join(dir).join("depsy-lsp"), b"bin").unwrap();
    }

    /// Sorted names of the entries under `base`.
    fn entry_names(base: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

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
            "depsy-lsp-v2.0.11.partial",
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

    #[test]
    fn newest_managed_binary_skips_a_directory_whose_binary_is_missing() {
        let base = scratch_dir("newest");
        write_binary(&base, "depsy-lsp-v2.0.1");
        std::fs::create_dir_all(base.join("depsy-lsp-v2.0.2")).unwrap();

        let newest = newest_managed_binary(&base, "depsy-lsp");

        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(newest.as_deref(), Some("depsy-lsp-v2.0.1/depsy-lsp"));
    }

    #[test]
    fn verified_download_is_moved_into_place_and_older_releases_are_removed() {
        let base = scratch_dir("install-ok");
        write_binary(&base, "depsy-lsp-v2.0.3.partial");
        write_binary(&base, "depsy-lsp-v2.0.1");
        std::fs::create_dir_all(base.join("html")).unwrap();

        let result = finish_install(&base, "depsy-lsp-v2.0.3", Ok(()));
        let binary_in_place = base.join("depsy-lsp-v2.0.3/depsy-lsp").is_file();
        let names = entry_names(&base);

        std::fs::remove_dir_all(&base).unwrap();
        assert!(result.is_ok());
        assert!(binary_in_place);
        assert_eq!(names, ["depsy-lsp-v2.0.3", "html"]);
    }

    #[test]
    fn failed_download_removes_the_staging_directory_only() {
        let base = scratch_dir("install-failed");
        write_binary(&base, "depsy-lsp-v2.0.3.partial");
        write_binary(&base, "depsy-lsp-v2.0.1");

        let result = finish_install(
            &base,
            "depsy-lsp-v2.0.3",
            Err(InstallError::Unavailable("offline".into())),
        );
        let names = entry_names(&base);

        std::fs::remove_dir_all(&base).unwrap();
        assert!(matches!(result, Err(InstallError::Unavailable(error)) if error == "offline"));
        assert_eq!(names, ["depsy-lsp-v2.0.1"]);
    }

    #[test]
    fn installed_binary_starts_without_installing() {
        let install_called = Cell::new(false);

        let path = resolve_binary(
            "depsy-lsp-v2.0.3/depsy-lsp".into(),
            true,
            || {
                install_called.set(true);
                Ok(())
            },
            || None,
        );

        assert_eq!(path.as_deref(), Ok("depsy-lsp-v2.0.3/depsy-lsp"));
        assert!(!install_called.get());
    }

    #[test]
    fn unavailable_release_falls_back_to_an_earlier_one() {
        let path = resolve_binary(
            "depsy-lsp-v2.0.3/depsy-lsp".into(),
            false,
            || Err(InstallError::Unavailable("offline".into())),
            || Some("depsy-lsp-v2.0.1/depsy-lsp".into()),
        );

        assert_eq!(path.as_deref(), Ok("depsy-lsp-v2.0.1/depsy-lsp"));
    }

    #[test]
    fn unavailable_release_without_fallback_points_at_the_binary_path_setting() {
        let error = resolve_binary(
            "depsy-lsp-v2.0.3/depsy-lsp".into(),
            false,
            || Err(InstallError::Unavailable("offline".into())),
            || None,
        )
        .unwrap_err();

        assert!(error.contains("offline"));
        assert!(error.contains("lsp.depsy.binary.path"));
    }

    #[test]
    fn checksum_mismatch_is_reported_instead_of_falling_back() {
        let fallback_asked = Cell::new(false);

        let error = resolve_binary(
            "depsy-lsp-v2.0.3/depsy-lsp".into(),
            false,
            || Err(InstallError::ChecksumMismatch("tampered".into())),
            || {
                fallback_asked.set(true);
                Some("depsy-lsp-v2.0.1/depsy-lsp".into())
            },
        )
        .unwrap_err();

        assert_eq!(error, "tampered");
        assert!(!fallback_asked.get());
    }

    /// The install directory must be recognised by the fallback and the
    /// pruning, which reject pre-release versions.
    #[test]
    fn release_tag_names_a_managed_directory() {
        assert!(managed_version(&format!("depsy-lsp-{RELEASE_TAG}")).is_some());
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
