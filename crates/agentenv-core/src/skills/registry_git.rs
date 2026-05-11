use std::{
    cmp::Ordering,
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use crate::security::ssrf::{validate_outbound, SsrfOptions};
use semver::Version;
use url::Url;

use super::{
    compute_bundle_digest, manifest::normalize_bundle_path, validate_skill_name, FetchedSkill,
    RegistryAdapter, SkillError, SkillManifest, SkillSearchHit,
};

const MANIFEST_FILE: &str = "skill.yaml";
const SOURCE_TYPE: &str = "git";

pub(crate) trait GitCheckout: Send + Sync + std::fmt::Debug {
    fn checkout(&self, url: &str, cache_root: &Path) -> Result<PathBuf, SkillError>;
}

#[derive(Debug)]
struct CommandGitCheckout {
    runner: Arc<dyn GitCommandRunner>,
}

#[derive(Debug)]
struct RealGitCommandRunner;

trait GitCommandRunner: Send + Sync + std::fmt::Debug {
    fn run(
        &self,
        args: &[String],
        environment: &GitCommandEnvironment,
    ) -> Result<GitCommandOutput, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitCommandEnvironment {
    set: Vec<(String, String)>,
    remove: Vec<String>,
}

#[derive(Debug, Clone)]
struct GitCommandOutput {
    success: bool,
    status: String,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone)]
struct ScannedGitSkill {
    path: PathBuf,
    manifest: SkillManifest,
    digest: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GitRegistryAdapter {
    name: String,
    url: String,
    cache_root: PathBuf,
    checkout: Arc<dyn GitCheckout>,
    ssrf_options: SsrfOptions,
}

impl GitCheckout for CommandGitCheckout {
    fn checkout(&self, url: &str, cache_root: &Path) -> Result<PathBuf, SkillError> {
        ensure_directory(cache_root)?;
        let checkout = cache_root.join("checkout");
        match fs::symlink_metadata(&checkout) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                if !checkout.join(".git").is_dir() {
                    return Err(SkillError::GitRegistry {
                        url: url.to_owned(),
                        message: format!(
                            "cache checkout path `{}` exists but is not a git repository",
                            checkout.display()
                        ),
                    });
                }
            }
            Ok(_) => {
                return Err(SkillError::UnsafeBundlePath { path: checkout });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let clone_url = clone_url(url)?;
                run_git(
                    self.runner.as_ref(),
                    &[
                        "clone".to_owned(),
                        "--filter=blob:none".to_owned(),
                        "--depth=1".to_owned(),
                        clone_url,
                        path_arg(&checkout),
                    ],
                    url,
                )?;
                return Ok(checkout);
            }
            Err(source) => {
                return Err(SkillError::Io {
                    path: checkout,
                    source,
                });
            }
        }

        if checkout.join(".git").is_dir() {
            run_git(
                self.runner.as_ref(),
                &[
                    "-C".to_owned(),
                    path_arg(&checkout),
                    "fetch".to_owned(),
                    "--all".to_owned(),
                    "--tags".to_owned(),
                    "--prune".to_owned(),
                ],
                url,
            )?;
            run_git(
                self.runner.as_ref(),
                &[
                    "-C".to_owned(),
                    path_arg(&checkout),
                    "reset".to_owned(),
                    "--hard".to_owned(),
                    "origin/HEAD".to_owned(),
                ],
                url,
            )?;
            return Ok(checkout);
        }
        unreachable!("non-git checkout paths are returned above")
    }
}

impl GitRegistryAdapter {
    pub(crate) fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
        ssrf_options: SsrfOptions,
    ) -> Self {
        Self::with_checkout_and_ssrf(
            name,
            url,
            cache_root,
            Arc::new(CommandGitCheckout::new()),
            ssrf_options,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_checkout(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
        checkout: Arc<dyn GitCheckout>,
    ) -> Self {
        Self::with_checkout_and_ssrf(name, url, cache_root, checkout, SsrfOptions::default())
    }

    pub(crate) fn with_checkout_and_ssrf(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
        checkout: Arc<dyn GitCheckout>,
        ssrf_options: SsrfOptions,
    ) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            cache_root: cache_root.into(),
            checkout,
            ssrf_options,
        }
    }

    fn checkout_path(&self) -> Result<PathBuf, SkillError> {
        validate_git_registry_url(&self.url, &self.ssrf_options)?;
        self.checkout.checkout(&self.url, &self.cache_root)
    }

    fn scan(&self) -> Result<Vec<ScannedGitSkill>, SkillError> {
        let checkout_path = self.checkout_path()?;
        let mut skills = Vec::new();
        scan_directory(&checkout_path, &mut skills)?;
        reject_duplicate_manifests(&self.name, &skills)?;
        Ok(skills)
    }

    fn hit_for_manifest(&self, manifest: &SkillManifest, digest: String) -> SkillSearchHit {
        SkillSearchHit {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            description: manifest.description.clone(),
            registry: self.name.clone(),
            digest: Some(digest),
            signature_ed25519: manifest.signature_ed25519.clone(),
            public_key_ed25519: manifest.signature_public_key_ed25519.clone(),
        }
    }
}

#[async_trait::async_trait]
impl RegistryAdapter for GitRegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        let query = query.to_ascii_lowercase();
        let mut hits = self
            .scan()?
            .into_iter()
            .filter_map(|skill| {
                let description = skill.manifest.description.as_deref().unwrap_or_default();
                let matches = query.is_empty()
                    || skill.manifest.name.to_ascii_lowercase().contains(&query)
                    || description.to_ascii_lowercase().contains(&query);
                matches.then(|| self.hit_for_manifest(&skill.manifest, skill.digest))
            })
            .collect::<Vec<_>>();
        sort_hits(&mut hits);
        Ok(hits)
    }

    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        validate_skill_name(name)?;
        if let Some(version) = version {
            version
                .parse::<Version>()
                .map_err(|source| SkillError::InvalidVersion {
                    version: version.to_owned(),
                    source,
                })?;
        }

        let mut matches = self
            .scan()?
            .into_iter()
            .filter(|skill| {
                skill.manifest.name == name
                    && version
                        .map(|version| skill.manifest.version.to_string() == version)
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            compare_versions(
                &left.manifest.version.to_string(),
                &right.manifest.version.to_string(),
            )
        });
        let skill =
            matches
                .into_iter()
                .next_back()
                .ok_or_else(|| SkillError::SkillNotInstalled {
                    name: name.to_owned(),
                })?;

        let version = skill.manifest.version.to_string();
        let staging_path = staging_fetch_path(&self.cache_root, &skill.manifest.name, &version)?;
        copy_bundle_contents(&skill.path, &staging_path, &skill.manifest)?;

        Ok(FetchedSkill {
            staging_path,
            registry: self.name.clone(),
            source_type: SOURCE_TYPE.to_owned(),
            name: skill.manifest.name,
            version,
        })
    }

    async fn publish(
        &self,
        _bundle_path: &Path,
        _allow_unsigned: bool,
    ) -> Result<SkillSearchHit, SkillError> {
        Err(SkillError::UnsupportedRegistryPublish {
            registry: self.name.clone(),
            kind: SOURCE_TYPE.to_owned(),
        })
    }
}

impl CommandGitCheckout {
    fn new() -> Self {
        Self {
            runner: Arc::new(RealGitCommandRunner),
        }
    }

    #[cfg(test)]
    fn with_runner(runner: Arc<dyn GitCommandRunner>) -> Self {
        Self { runner }
    }
}

impl GitCommandRunner for RealGitCommandRunner {
    fn run(
        &self,
        args: &[String],
        environment: &GitCommandEnvironment,
    ) -> Result<GitCommandOutput, String> {
        let mut command = Command::new("git");
        command.args(args);
        for name in &environment.remove {
            command.env_remove(name);
        }
        for (name, value) in &environment.set {
            command.env(name, value);
        }
        let output = command
            .output()
            .map_err(|source| format!("failed to run git: {source}"))?;

        Ok(GitCommandOutput {
            success: output.status.success(),
            status: output.status.to_string(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

fn scan_directory(root: &Path, skills: &mut Vec<ScannedGitSkill>) -> Result<(), SkillError> {
    for entry in fs::read_dir(root).map_err(|source| SkillError::Io {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| SkillError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| SkillError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_dir() {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(".git") {
            continue;
        }

        let manifest_path = path.join(MANIFEST_FILE);
        if manifest_path_is_file(&manifest_path)? {
            let manifest = super::load_skill_manifest(&path)?;
            let digest = compute_bundle_digest(&path, &manifest)?;
            skills.push(ScannedGitSkill {
                path: path.clone(),
                manifest,
                digest,
            });
        }
        scan_directory(&path, skills)?;
    }
    Ok(())
}

fn manifest_path_is_file(path: &Path) -> Result<bool, SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_file() {
                Ok(true)
            } else {
                Err(SkillError::UnsafeBundlePath {
                    path: path.to_path_buf(),
                })
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn clone_url(url: &str) -> Result<String, SkillError> {
    let Some(stripped) = url.strip_prefix("git+") else {
        return Err(SkillError::GitRegistry {
            url: url.to_owned(),
            message: "git registry URL must use git+https".to_owned(),
        });
    };
    if !stripped.starts_with("https://") {
        return Err(SkillError::GitRegistry {
            url: url.to_owned(),
            message: "git registry URL must use git+https".to_owned(),
        });
    }
    Ok(stripped.to_owned())
}

fn validate_git_registry_url(url: &str, options: &SsrfOptions) -> Result<(), SkillError> {
    let clone_url = clone_url(url)?;
    let parsed = Url::parse(&clone_url).map_err(|source| SkillError::GitRegistry {
        url: url.to_owned(),
        message: format!("invalid git registry URL: {source}"),
    })?;
    validate_outbound(&parsed, options.clone())
        .map(|_| ())
        .map_err(|source| SkillError::RegistryUrlBlocked {
            url: url.to_owned(),
            source: Box::new(source),
        })
}

fn run_git(runner: &dyn GitCommandRunner, args: &[String], url: &str) -> Result<(), SkillError> {
    let args = isolated_git_args(args);
    let environment = isolated_git_environment();
    let output = runner
        .run(&args, &environment)
        .map_err(|message| SkillError::GitRegistry {
            url: url.to_owned(),
            message,
        })?;
    if output.success {
        return Ok(());
    }

    let message = if output.stderr.is_empty() {
        let stdout = bounded_diagnostic(&output.stdout);
        if stdout.is_empty() {
            format!("git exited with status {}", output.status)
        } else {
            format!("git exited with status {}: {stdout}", output.status)
        }
    } else {
        format!(
            "git exited with status {}: {}",
            output.status,
            bounded_diagnostic(&output.stderr)
        )
    };
    Err(SkillError::GitRegistry {
        url: url.to_owned(),
        message,
    })
}

fn isolated_git_args(args: &[String]) -> Vec<String> {
    let mut isolated = [
        "-c",
        "http.followRedirects=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    isolated.extend(args.iter().cloned());
    isolated
}

fn isolated_git_environment() -> GitCommandEnvironment {
    GitCommandEnvironment {
        set: vec![
            ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
            (
                "GIT_CONFIG_SYSTEM".to_owned(),
                git_null_config_path().to_owned(),
            ),
            (
                "GIT_CONFIG_GLOBAL".to_owned(),
                git_null_config_path().to_owned(),
            ),
            ("GIT_CONFIG_COUNT".to_owned(), "0".to_owned()),
        ],
        remove: [
            "GIT_CONFIG",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "GIT_PROXY_COMMAND",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

fn git_null_config_path() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

fn bounded_diagnostic(text: &str) -> String {
    const LIMIT: usize = 512;
    let text = text.trim();
    if text.len() <= LIMIT {
        return text.to_owned();
    }

    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn staging_fetch_path(cache_root: &Path, name: &str, version: &str) -> Result<PathBuf, SkillError> {
    let staging_root = cache_root.join("staging");
    ensure_directory(&staging_root)?;
    for _ in 0..16 {
        let candidate = staging_root.join(format!(
            "{name}-{version}-{}-{}",
            std::process::id(),
            temporary_suffix()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(SkillError::Io {
                    path: candidate,
                    source,
                });
            }
        }
    }

    Err(SkillError::GitRegistry {
        url: SOURCE_TYPE.to_owned(),
        message: "failed to allocate unique git skill staging directory".to_owned(),
    })
}

fn copy_regular_file(
    source_root: &Path,
    relative_source: &Path,
    destination: &Path,
) -> Result<(), SkillError> {
    if let Some(parent) = destination.parent() {
        ensure_directory(parent)?;
    }
    let mut source_file = open_regular_file_under_root(source_root, relative_source)?;
    let mut destination_file = fs::File::create(destination).map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    std::io::copy(&mut source_file, &mut destination_file).map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(unix)]
fn open_regular_file_under_root(root: &Path, relative_path: &Path) -> Result<fs::File, SkillError> {
    use rustix::fs::{Mode, OFlags};

    let relative_path = normalize_bundle_path(relative_path)?;
    let mut components = relative_path.components().peekable();
    let mut directory = open_directory_no_follow(root)?;

    while let Some(component) = components.next() {
        let std::path::Component::Normal(part) = component else {
            return Err(SkillError::UnsafeBundlePath {
                path: relative_path.clone(),
            });
        };
        let is_final = components.peek().is_none();
        let flags = if is_final {
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
        } else {
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW
        };
        let opened = rustix::fs::openat(&directory, part, flags, Mode::empty())
            .map(fs::File::from)
            .map_err(|source| SkillError::Io {
                path: root.join(&relative_path),
                source: std::io::Error::from(source),
            })?;
        if is_final {
            ensure_opened_regular_file(&root.join(&relative_path), &opened)?;
            return Ok(opened);
        }
        ensure_opened_directory(&root.join(&relative_path), &opened)?;
        directory = opened;
    }

    Err(SkillError::UnsafeBundlePath {
        path: relative_path,
    })
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> Result<fs::File, SkillError> {
    use rustix::fs::{Mode, OFlags};

    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::from(source),
    })?;
    ensure_opened_directory(path, &file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_file_under_root(
    _root: &Path,
    _relative_path: &Path,
) -> Result<fs::File, SkillError> {
    Err(SkillError::GitRegistry {
        url: SOURCE_TYPE.to_owned(),
        message: "git registry fetch is unsupported on this platform because safe no-follow staging is unavailable"
            .to_owned(),
    })
}

#[cfg(unix)]
fn ensure_opened_directory(path: &Path, file: &fs::File) -> Result<(), SkillError> {
    let metadata = file.metadata().map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        })
    }
}

fn ensure_opened_regular_file(path: &Path, file: &fs::File) -> Result<(), SkillError> {
    let metadata = file.metadata().map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        })
    }
}

fn copy_bundle_contents(
    source_root: &Path,
    destination_root: &Path,
    manifest: &SkillManifest,
) -> Result<(), SkillError> {
    ensure_directory(destination_root)?;
    copy_regular_file(
        source_root,
        Path::new(MANIFEST_FILE),
        &destination_root.join(MANIFEST_FILE),
    )?;
    for declared_file in &manifest.declared_files {
        copy_regular_file(
            source_root,
            declared_file,
            &destination_root.join(declared_file),
        )?;
    }
    Ok(())
}

fn sort_hits(hits: &mut [SkillSearchHit]) {
    hits.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| compare_versions(&left.version, &right.version))
            .then_with(|| left.registry.cmp(&right.registry))
    });
}

fn reject_duplicate_manifests(
    registry: &str,
    skills: &[ScannedGitSkill],
) -> Result<(), SkillError> {
    let mut seen = HashSet::new();
    for skill in skills {
        let version = skill.manifest.version.to_string();
        if !seen.insert((skill.manifest.name.clone(), version.clone())) {
            return Err(SkillError::InvalidConfig {
                message: format!(
                    "git registry `{registry}` has duplicate skill `{}` version `{version}`",
                    skill.manifest.name
                ),
            });
        }
    }
    Ok(())
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    match (left.parse::<Version>(), right.parse::<Version>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn ensure_directory(path: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)
            .map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            }),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn temporary_suffix() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ssrf::SsrfOptions;
    use std::{
        fs,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Arc, Mutex,
        },
    };

    #[derive(Debug)]
    struct StaticCheckout {
        path: PathBuf,
    }

    impl GitCheckout for StaticCheckout {
        fn checkout(&self, _url: &str, _cache_root: &Path) -> Result<PathBuf, SkillError> {
            Ok(self.path.clone())
        }
    }

    #[derive(Debug)]
    struct CountingCheckout {
        calls: AtomicUsize,
        path: PathBuf,
    }

    impl GitCheckout for CountingCheckout {
        fn checkout(&self, _url: &str, _cache_root: &Path) -> Result<PathBuf, SkillError> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(self.path.clone())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedGitCommand {
        args: Vec<String>,
        environment: GitCommandEnvironment,
    }

    #[derive(Debug)]
    struct RecordingGitCommandRunner {
        commands: Mutex<Vec<RecordedGitCommand>>,
    }

    impl RecordingGitCommandRunner {
        fn new() -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<RecordedGitCommand> {
            self.commands.lock().unwrap().clone()
        }
    }

    impl GitCommandRunner for RecordingGitCommandRunner {
        fn run(
            &self,
            args: &[String],
            environment: &GitCommandEnvironment,
        ) -> Result<GitCommandOutput, String> {
            self.commands.lock().unwrap().push(RecordedGitCommand {
                args: args.to_vec(),
                environment: environment.clone(),
            });
            Ok(GitCommandOutput {
                success: true,
                status: "exit status: 0".to_owned(),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn expected_isolated_args(args: Vec<String>) -> Vec<String> {
        isolated_git_args(&args)
    }

    fn expected_git_environment() -> GitCommandEnvironment {
        isolated_git_environment()
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn loopback_ssrf_options() -> SsrfOptions {
        SsrfOptions {
            allow_loopback: true,
            allow_private: true,
            ..SsrfOptions::default()
        }
    }

    #[tokio::test]
    async fn git_registry_search_scans_skill_directories() {
        let checkout = temp_dir("skill-git-search");
        write_file(
            &checkout.join("tools/review/skill.yaml"),
            "name: review-skill\nversion: 0.2.0\ndescription: Review helper\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("tools/review/SKILL.md"), "# Review\n");
        let adapter = GitRegistryAdapter::with_checkout_and_ssrf(
            "git-dev",
            "git+https://127.0.0.1/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
            loopback_ssrf_options(),
        );

        let hits = adapter.search("review").await.unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "review-skill");
        assert_eq!(hits[0].version, "0.2.0");
        assert_eq!(hits[0].registry, "git-dev");
    }

    #[tokio::test]
    async fn git_registry_fetch_selects_highest_semver_and_copies_bundle() {
        let checkout = temp_dir("skill-git-fetch");
        write_file(
            &checkout.join("old/skill.yaml"),
            "name: versioned-git\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("old/SKILL.md"), "# Old\n");
        write_file(
            &checkout.join("new/skill.yaml"),
            "name: versioned-git\nversion: 0.3.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("new/SKILL.md"), "# New\n");
        let adapter = GitRegistryAdapter::with_checkout_and_ssrf(
            "git-dev",
            "git+https://127.0.0.1/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
            loopback_ssrf_options(),
        );

        let fetched = adapter.fetch("versioned-git", None).await.unwrap();

        assert_eq!(fetched.source_type, "git");
        assert_eq!(fetched.version, "0.3.0");
        assert!(fetched.staging_path.join("SKILL.md").is_file());
    }

    #[tokio::test]
    async fn git_registry_fetch_exact_version_copies_selected_bundle() {
        let checkout = temp_dir("skill-git-fetch-exact");
        write_file(
            &checkout.join("old/skill.yaml"),
            "name: exact-git\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("old/SKILL.md"), "# Old\n");
        write_file(
            &checkout.join("new/skill.yaml"),
            "name: exact-git\nversion: 0.3.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("new/SKILL.md"), "# New\n");
        let adapter = GitRegistryAdapter::with_checkout_and_ssrf(
            "git-dev",
            "git+https://127.0.0.1/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
            loopback_ssrf_options(),
        );

        let fetched = adapter.fetch("exact-git", Some("0.1.0")).await.unwrap();

        assert_eq!(fetched.source_type, "git");
        assert_eq!(fetched.version, "0.1.0");
        assert_eq!(
            fs::read_to_string(fetched.staging_path.join("SKILL.md")).unwrap(),
            "# Old\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn git_bundle_copy_rejects_symlinked_declared_file_parent() {
        let source = temp_dir("skill-git-copy-symlink-parent-source");
        let destination = temp_dir("skill-git-copy-symlink-parent-destination");
        let outside = temp_dir("skill-git-copy-symlink-parent-outside");
        write_file(
            &source.join("skill.yaml"),
            "name: symlink-parent-git\nversion: 0.1.0\nentry: docs/SKILL.md\nfiles:\n  - docs/SKILL.md\n",
        );
        write_file(&outside.join("SKILL.md"), "# Outside\n");
        std::os::unix::fs::symlink(&outside, source.join("docs")).unwrap();
        let manifest = SkillManifest {
            name: "symlink-parent-git".to_owned(),
            version: Version::parse("0.1.0").unwrap(),
            description: None,
            entry: PathBuf::from("docs/SKILL.md"),
            declared_files: vec![PathBuf::from("docs/SKILL.md")],
            self_test_command: None,
            signature_ed25519: None,
            signature_public_key_ed25519: None,
            extra: std::collections::BTreeMap::new(),
        };

        let error = copy_bundle_contents(&source, &destination, &manifest)
            .expect_err("copy must not follow symlinked parents");

        assert!(matches!(
            error,
            SkillError::Io { .. } | SkillError::UnsafeBundlePath { .. }
        ));
        assert!(!destination.join("docs/SKILL.md").exists());
    }

    #[cfg(not(unix))]
    #[test]
    fn git_bundle_copy_fails_closed_without_safe_nofollow_staging() {
        let source = temp_dir("skill-git-copy-non-unix-source");
        let destination = temp_dir("skill-git-copy-non-unix-destination");
        write_file(
            &source.join("skill.yaml"),
            "name: non-unix-git\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&source.join("SKILL.md"), "# Non-Unix\n");
        let manifest = SkillManifest {
            name: "non-unix-git".to_owned(),
            version: Version::parse("0.1.0").unwrap(),
            description: None,
            entry: PathBuf::from("SKILL.md"),
            declared_files: vec![PathBuf::from("SKILL.md")],
            self_test_command: None,
            signature_ed25519: None,
            signature_public_key_ed25519: None,
            extra: std::collections::BTreeMap::new(),
        };

        let error = copy_bundle_contents(&source, &destination, &manifest)
            .expect_err("non-Unix staging must fail closed without no-follow support");

        assert!(matches!(error, SkillError::GitRegistry { .. }));
        assert!(!destination.join("SKILL.md").exists());
    }

    #[tokio::test]
    async fn git_registry_blocks_ssrf_url_before_checkout() {
        let checkout = Arc::new(CountingCheckout {
            calls: AtomicUsize::new(0),
            path: temp_dir("skill-git-ssrf-checkout"),
        });
        let adapter = GitRegistryAdapter::with_checkout(
            "git-dev",
            "git+https://127.0.0.1/acme/skills",
            temp_dir("skill-git-cache"),
            checkout.clone(),
        );

        let error = adapter
            .search("anything")
            .await
            .expect_err("blocked URL should stop before checkout");

        assert!(matches!(error, SkillError::RegistryUrlBlocked { .. }));
        assert_eq!(checkout.calls.load(AtomicOrdering::SeqCst), 0);
    }

    #[tokio::test]
    async fn git_registry_scan_rejects_duplicate_name_version_manifests() {
        let checkout = temp_dir("skill-git-duplicates");
        for directory in ["one", "two"] {
            write_file(
                &checkout.join(directory).join("skill.yaml"),
                "name: duplicate-git\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
            );
            write_file(&checkout.join(directory).join("SKILL.md"), "# Duplicate\n");
        }
        let adapter = GitRegistryAdapter::with_checkout_and_ssrf(
            "git-dev",
            "git+https://127.0.0.1/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
            loopback_ssrf_options(),
        );

        let error = adapter
            .search("duplicate")
            .await
            .expect_err("duplicate manifests must be rejected");

        assert!(matches!(error, SkillError::InvalidConfig { .. }));
    }

    #[test]
    fn command_checkout_clones_stripped_git_url_into_cache_root() {
        let cache_root = temp_dir("skill-git-command-clone");
        let runner = Arc::new(RecordingGitCommandRunner::new());
        let checkout = CommandGitCheckout::with_runner(runner.clone());

        let path = checkout
            .checkout("git+https://github.com/acme/skills", &cache_root)
            .unwrap();

        assert_eq!(path, cache_root.join("checkout"));
        assert_eq!(
            runner.commands(),
            vec![RecordedGitCommand {
                args: expected_isolated_args(vec![
                    "clone".to_owned(),
                    "--filter=blob:none".to_owned(),
                    "--depth=1".to_owned(),
                    "https://github.com/acme/skills".to_owned(),
                    path_arg(&cache_root.join("checkout")),
                ]),
                environment: expected_git_environment(),
            }]
        );
        let command = &runner.commands()[0];
        assert!(command
            .args
            .windows(2)
            .any(|pair| pair == ["-c".to_owned(), "http.followRedirects=false".to_owned()]));
        assert!(command
            .args
            .windows(2)
            .any(|pair| pair == ["-c".to_owned(), "protocol.allow=never".to_owned()]));
        assert!(command
            .environment
            .set
            .iter()
            .any(|(name, value)| { name == "GIT_TERMINAL_PROMPT" && value == "0" }));
        assert!(command
            .environment
            .set
            .iter()
            .any(|(name, value)| { name == "GIT_CONFIG_NOSYSTEM" && value == "1" }));
        assert!(command
            .environment
            .remove
            .iter()
            .any(|name| name == "HTTPS_PROXY"));
    }

    #[test]
    fn command_checkout_fetches_and_resets_existing_checkout() {
        let cache_root = temp_dir("skill-git-command-fetch");
        fs::create_dir_all(cache_root.join("checkout/.git")).unwrap();
        let runner = Arc::new(RecordingGitCommandRunner::new());
        let checkout = CommandGitCheckout::with_runner(runner.clone());

        let path = checkout
            .checkout("git+https://github.com/acme/skills", &cache_root)
            .unwrap();

        assert_eq!(path, cache_root.join("checkout"));
        assert_eq!(
            runner.commands(),
            vec![
                RecordedGitCommand {
                    args: expected_isolated_args(vec![
                        "-C".to_owned(),
                        path_arg(&cache_root.join("checkout")),
                        "fetch".to_owned(),
                        "--all".to_owned(),
                        "--tags".to_owned(),
                        "--prune".to_owned(),
                    ]),
                    environment: expected_git_environment(),
                },
                RecordedGitCommand {
                    args: expected_isolated_args(vec![
                        "-C".to_owned(),
                        path_arg(&cache_root.join("checkout")),
                        "reset".to_owned(),
                        "--hard".to_owned(),
                        "origin/HEAD".to_owned(),
                    ]),
                    environment: expected_git_environment(),
                },
            ]
        );
    }
}
