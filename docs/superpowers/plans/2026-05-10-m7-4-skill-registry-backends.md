# M7-4 Skill Registry Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the skill registry backend surface for filesystem, HTTP, OCI, and git on top of the current `agentenv-core::skills` service.

**Architecture:** Keep skills as core-managed artifacts and preserve the existing `SkillService` plus `RegistryAdapter` boundary. Add `git` as a new adapter, make filesystem and HTTP additive-compatible with the issue layouts, and keep shared manifest/digest/install/provenance handling in the existing store and service paths.

**Tech Stack:** Rust 2021, `tokio`, `async-trait`, `serde`, `serde_json`, `serde_yaml`, `reqwest` with `rustls`, `semver`, `tar`, `zstd`, std `Command` for git subprocesses.

---

## File Structure

- Modify `Cargo.toml`: add workspace dependencies for `tar` and `zstd`.
- Modify `crates/agentenv-core/Cargo.toml`: depend on workspace `tar` and `zstd`.
- Modify `crates/agentenv-core/src/skills/registry.rs`: add `RegistryKind::Git` and `RegistryConfig::git`.
- Modify `crates/agentenv-core/src/skills/config.rs`: validate `git+https://...`, parse CLI direct-source overrides, normalize git URLs.
- Modify `crates/agentenv-core/src/skills/error.rs`: add typed git and unsupported-publish errors.
- Modify `crates/agentenv-core/src/skills/mod.rs`: register the new git adapter module.
- Modify `crates/agentenv-core/src/skills/service.rs`: wire `RegistryKind::Git` to `GitRegistryAdapter`.
- Modify `crates/agentenv-core/src/skills/registry_filesystem.rs`: scan issue-compatible subdirectories when no index exists.
- Modify `crates/agentenv-core/src/skills/registry_http.rs`: prefer `index.json`, keep `index.yaml` fallback, fetch `.tar.zst` artifacts before expanded legacy bundles.
- Create `crates/agentenv-core/src/skills/registry_git.rs`: implement search/fetch/read-only publish for git registries.
- Modify `crates/agentenv-core/tests/skills.rs`: add integration tests for config, filesystem scan fallback, HTTP JSON/tarball support, service-level git publish behavior, and provenance.
- Modify `crates/agentenv/tests/cli_behavior.rs`: add CLI coverage only for behavior reachable without network or host-specific git setup.
- Modify `docs/superpowers/specs/2026-05-10-m7-4-skill-registry-backends-design.md`: already adjusted to allow small Rust archive crates.

## Task 1: Git Registry Config And Service Wiring

**Files:**
- Modify: `crates/agentenv-core/src/skills/registry.rs`
- Modify: `crates/agentenv-core/src/skills/config.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/service.rs`
- Create: `crates/agentenv-core/src/skills/registry_git.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing config tests**

Append these tests near the existing skills config tests in `crates/agentenv-core/tests/skills.rs`:

```rust
#[test]
fn skills_config_loads_git_registry_from_project_yaml() {
    let yaml = r#"
skills:
  registries:
    - name: git-dev
      type: git
      url: git+https://github.com/acme/skills
"#;

    let config = load_project_skills_config(yaml).unwrap();

    assert_eq!(config.registries[0].name, "git-dev");
    assert_eq!(config.registries[0].kind, RegistryKind::Git);
    assert_eq!(
        config.registries[0].url.as_deref(),
        Some("git+https://github.com/acme/skills")
    );
}

#[test]
fn skills_config_loads_git_registry_from_user_toml() {
    let toml = r#"
[[skills.registries]]
name = "git-dev"
type = "git"
url = "git+https://github.com/acme/skills"
"#;

    let config = load_user_skills_config(toml).unwrap();

    assert_eq!(config.registries[0].kind, RegistryKind::Git);
}

#[test]
fn cli_registry_override_parses_git_source() {
    let merged = merge_skills_config(
        SkillsConfig::default(),
        None,
        SkillsConfigOverride {
            registry: Some("git+https://github.com/acme/skills".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries[0].name, "cli");
    assert_eq!(merged.registries[0].kind, RegistryKind::Git);
    assert_eq!(merged.registry_order, vec!["cli"]);
}

#[test]
fn skills_config_rejects_unsafe_git_registry_urls() {
    for url in [
        "https://github.com/acme/skills",
        "git+ssh://github.com/acme/skills",
        "git+https://user:pass@github.com/acme/skills",
        "git+https://github.com/acme/skills?branch=main",
        "git+https://github.com/acme/skills#main",
    ] {
        let yaml = format!(
            "skills:\n  registries:\n    - name: git-dev\n      type: git\n      url: {url}\n"
        );

        let error = load_project_skills_config(&yaml)
            .expect_err("unsafe git registry URL must be rejected");

        assert!(matches!(error, SkillError::InvalidConfig { .. }));
    }
}
```

- [ ] **Step 2: Run the config tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills git
```

Expected: fail to compile because `RegistryKind::Git` does not exist.

- [ ] **Step 3: Add git registry config types**

In `crates/agentenv-core/src/skills/registry.rs`, add the constructor and enum variant:

```rust
    pub fn git(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Git,
            url: Some(url.into()),
            path: None,
            auth: None,
        }
    }
```

```rust
pub enum RegistryKind {
    Filesystem,
    Http,
    Oci,
    Git,
}
```

- [ ] **Step 4: Add git URL parsing and validation**

In `crates/agentenv-core/src/skills/config.rs`, add git direct-source parsing:

```rust
        "git+https" => Ok(Some(RegistryConfig::git(
            CLI_REGISTRY_NAME,
            normalize_git_url(url.as_str())?,
        ))),
```

Update `normalize_registry_values`:

```rust
            RegistryKind::Git => {
                if let Some(url) = registry.url.as_mut() {
                    *url = normalize_git_url(url)?;
                }
            }
```

Update `validate_registry_required_fields`:

```rust
        RegistryKind::Git => {
            let Some(url) = registry
                .url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty())
            else {
                return Err(invalid_config(format!(
                    "git registry `{}` requires url",
                    registry.name
                )));
            };
            normalize_git_url(url)?;
        }
```

Add helper:

```rust
fn normalize_git_url(value: &str) -> Result<String, SkillError> {
    let value = value.trim();
    let url = Url::parse(value).map_err(|source| {
        invalid_config(format!("invalid git registry URL `{value}`: {source}"))
    })?;
    validate_git_url(&url)?;
    Ok(url.to_string())
}

fn validate_git_url(url: &Url) -> Result<(), SkillError> {
    if url.scheme() != "git+https" {
        return Err(invalid_config(format!(
            "git registry URL uses unsupported scheme `{}`",
            url.scheme()
        )));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid_config("git registry URL must include a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_config("git registry URL must not include user info"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_config(
            "git registry URL must not include query or fragment",
        ));
    }
    if url.path() == "/" || url.path().trim_matches('/').is_empty() {
        return Err(invalid_config("git registry URL must include a repository path"));
    }
    Ok(())
}
```

- [ ] **Step 5: Add a compiling git adapter stub and service wiring**

In `crates/agentenv-core/src/skills/mod.rs`:

```rust
mod registry_git;
```

Create `crates/agentenv-core/src/skills/registry_git.rs`:

```rust
use std::path::Path;

use super::{FetchedSkill, RegistryAdapter, SkillError, SkillSearchHit};

const SOURCE_TYPE: &str = "git";

#[derive(Debug, Clone)]
pub(crate) struct GitRegistryAdapter {
    name: String,
    url: String,
}

impl GitRegistryAdapter {
    pub(crate) fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
        }
    }
}

#[async_trait::async_trait]
impl RegistryAdapter for GitRegistryAdapter {
    async fn search(&self, _query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        Err(SkillError::InvalidConfig {
            message: format!("git registry `{}` is not implemented yet", self.name),
        })
    }

    async fn fetch(&self, name: &str, _version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        Err(SkillError::SkillNotInstalled {
            name: name.to_owned(),
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
```

In `SkillError`, add:

```rust
    #[error("registry `{registry}` of type `{kind}` does not support publishing")]
    UnsupportedRegistryPublish { registry: String, kind: String },
    #[error("git registry `{url}` failed: {message}")]
    GitRegistry { url: String, message: String },
```

In `SkillService::adapter_for`, add:

```rust
            RegistryKind::Git => {
                let url = registry
                    .url
                    .clone()
                    .ok_or_else(|| SkillError::InvalidConfig {
                        message: format!("git registry `{}` requires url", registry.name),
                    })?;
                Ok(Box::new(registry_git::GitRegistryAdapter::new(
                    registry.name.clone(),
                    url,
                )))
            }
```

- [ ] **Step 6: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills git
```

Expected: all four tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv-core/src/skills/registry.rs crates/agentenv-core/src/skills/config.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/src/skills/service.rs crates/agentenv-core/src/skills/registry_git.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: add git skill registry config"
```

## Task 2: Filesystem Registry Indexless Scan

**Files:**
- Modify: `crates/agentenv-core/src/skills/registry_filesystem.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing filesystem scan tests**

Append near existing filesystem registry tests:

```rust
#[tokio::test]
async fn filesystem_registry_search_scans_skill_subdirectories_without_index() {
    let home = temp_dir("skill-fs-scan-home");
    let registry = temp_dir("skill-fs-scan-registry");
    write_file(
        &registry.join("scan-skill/skill.yaml"),
        "name: scan-skill\nversion: 0.2.0\ndescription: Scan demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(&registry.join("scan-skill/SKILL.md"), "# Scan demo\n");
    let service = filesystem_skill_service(&home, &registry);

    let hits = service.search("scan").await.expect("search should scan");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "scan-skill");
    assert_eq!(hits[0].version, "0.2.0");
    assert_eq!(hits[0].registry, "local-dev");
}

#[tokio::test]
async fn filesystem_registry_add_uses_scanned_subdirectory_without_index() {
    let home = temp_dir("skill-fs-scan-add-home");
    let registry = temp_dir("skill-fs-scan-add-registry");
    write_file(
        &registry.join("scan-add/skill.yaml"),
        "name: scan-add\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(&registry.join("scan-add/SKILL.md"), "# Scan add\n");
    let service = filesystem_skill_service(&home, &registry);

    let installed = service
        .add(SkillAddRequest {
            handle: "scan-add".to_owned(),
            registry: None,
            allow_unsigned: true,
        })
        .await
        .expect("add should use scanned directory");

    assert_eq!(installed.name, "scan-add");
    assert_eq!(installed.source_label, "filesystem:local-dev:scan-add@0.1.0");
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_registry
```

Expected: fail because `read_index` returns an empty index when `index.yaml` is absent.

- [ ] **Step 3: Implement scan fallback**

In `registry_filesystem.rs`, change `read_index` missing-file behavior to call a scanner:

```rust
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return self.scan_index();
            }
```

Add these helpers:

```rust
    fn scan_index(&self) -> Result<FilesystemRegistryIndex, SkillError> {
        let mut skills = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|source| SkillError::Io {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| SkillError::Io {
                path: self.root.clone(),
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
            if path.file_name().and_then(|name| name.to_str()) == Some(BUNDLES_DIR) {
                continue;
            }
            let manifest_path = path.join(MANIFEST_FILE);
            if !manifest_path.is_file() {
                continue;
            }
            let manifest = super::load_skill_manifest(&path)?;
            let digest = compute_bundle_digest(&path, &manifest)?;
            skills.push(self.hit_for_manifest(&manifest, digest));
        }
        sort_hits(&mut skills);
        Ok(FilesystemRegistryIndex { skills })
    }
```

Update `fetch` to use a helper that can resolve either indexed `bundles/<name>/<version>` or scanned root subdirectories:

```rust
        let bundle_path = self.bundle_path_for_hit(&hit)?.ok_or_else(|| {
            SkillError::SkillNotInstalled {
                name: hit.name.clone(),
            }
        })?;
```

Add:

```rust
    fn bundle_path_for_hit(&self, hit: &SkillSearchHit) -> Result<Option<PathBuf>, SkillError> {
        if let Some(path) = existing_child_directory(&self.root, &[BUNDLES_DIR, &hit.name, &hit.version])? {
            return Ok(Some(path));
        }
        for entry in fs::read_dir(&self.root).map_err(|source| SkillError::Io {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| SkillError::Io {
                path: self.root.clone(),
                source,
            })?;
            let path = entry.path();
            if !fs::symlink_metadata(&path)
                .map_err(|source| SkillError::Io {
                    path: path.clone(),
                    source,
                })?
                .file_type()
                .is_dir()
            {
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) == Some(BUNDLES_DIR) {
                continue;
            }
            if !path.join(MANIFEST_FILE).is_file() {
                continue;
            }
            let manifest = super::load_skill_manifest(&path)?;
            if manifest.name == hit.name && manifest.version.to_string() == hit.version {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
```

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_registry
```

Expected: both tests pass.

- [ ] **Step 5: Run existing filesystem tests**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_registry
```

Expected: existing filesystem registry tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/src/skills/registry_filesystem.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: scan filesystem skill registries"
```

## Task 3: HTTP `index.json` And Tarball Fetch Compatibility

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv-core/Cargo.toml`
- Modify: `crates/agentenv-core/src/skills/registry_http.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing HTTP JSON index test**

Append near HTTP registry tests:

```rust
#[tokio::test]
async fn http_registry_search_prefers_index_json() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response(
            "GET",
            "/index.json",
            r#"{"skills":[{"name":"json-demo","version":"0.1.0","description":"JSON demo","registry":"ignored","digest":null,"signature_ed25519":null,"public_key_ed25519":null}]}"#,
        )
        .await;
    server
        .add_response(
            "GET",
            "/index.yaml",
            "skills:\n  - name: yaml-demo\n    version: 0.1.0\n    registry: ignored\n",
        )
        .await;
    let home = temp_dir("skill-http-json-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let hits = service.search("demo").await.expect("search should use JSON");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "json-demo");
    assert_eq!(hits[0].registry, "http-dev");
}
```

- [ ] **Step 2: Write failing HTTP tarball fetch test**

Add helper functions to `crates/agentenv-core/tests/skills.rs`:

```rust
fn tar_zst_bundle_bytes(bundle_path: &Path) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        builder
            .append_path_with_name(bundle_path.join("skill.yaml"), "skill.yaml")
            .unwrap();
        builder
            .append_path_with_name(bundle_path.join("SKILL.md"), "SKILL.md")
            .unwrap();
        builder.finish().unwrap();
    }
    zstd::stream::encode_all(tar_bytes.as_slice(), 0).unwrap()
}

async fn add_binary_response(server: &TestHttpRegistry, method: &str, path: &str, body: Vec<u8>) {
    server.add_binary_response(method, path, body).await;
}
```

Extend `TestHttpRegistry` with `add_binary_response` in the test harness:

```rust
    async fn add_binary_response(&self, method: &str, path: &str, body: Vec<u8>) {
        self.state
            .lock()
            .unwrap()
            .responses
            .insert((method.to_owned(), path.to_owned()), body);
    }
```

Then add the test:

```rust
#[tokio::test]
async fn http_registry_add_downloads_tar_zst_skill_artifact() {
    let server = TestHttpRegistry::start().await;
    let bundle = skill_bundle("tarball-skill", "0.1.0", "Tarball skill");
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    let index = format!(
        r#"{{"skills":[{{"name":"tarball-skill","version":"0.1.0","description":null,"registry":"ignored","digest":"{digest}","signature_ed25519":null,"public_key_ed25519":null}}]}}"#
    );
    server.add_response("GET", "/index.json", &index).await;
    add_binary_response(
        &server,
        "GET",
        "/skills/tarball-skill/0.1.0.tar.zst",
        tar_zst_bundle_bytes(&bundle),
    )
    .await;
    let home = temp_dir("skill-http-tarball-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let installed = service
        .add(SkillAddRequest {
            handle: "tarball-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
        })
        .await
        .expect("add should unpack tar.zst artifact");

    assert_eq!(installed.name, "tarball-skill");
    assert_eq!(installed.source_label, "http:http-dev:tarball-skill@0.1.0");
}
```

- [ ] **Step 3: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills http_registry
```

Expected: first fails because HTTP reads `index.yaml`; second fails to compile until `tar` and `zstd` dependencies are added.

- [ ] **Step 4: Add archive dependencies**

In workspace `Cargo.toml`:

```toml
tar = "0.4"
zstd = "0.13"
```

In `crates/agentenv-core/Cargo.toml`:

```toml
tar.workspace = true
zstd.workspace = true
```

- [ ] **Step 5: Implement JSON index preference**

In `registry_http.rs`, replace `const INDEX_FILE` with:

```rust
const INDEX_JSON_FILE: &str = "index.json";
const INDEX_YAML_FILE: &str = "index.yaml";
```

Add:

```rust
fn index_json_url(&self) -> Result<Url, SkillError> {
    self.url_for(&[INDEX_JSON_FILE])
}

fn index_yaml_url(&self) -> Result<Url, SkillError> {
    self.url_for(&[INDEX_YAML_FILE])
}
```

Update `read_index`:

```rust
    async fn read_index(&self) -> Result<HttpRegistryIndex, SkillError> {
        if let Some(content) = self.get_optional_text(self.index_json_url()?).await? {
            let mut index: HttpRegistryIndex =
                serde_json::from_str(&content).map_err(|source| SkillError::InvalidConfig {
                    message: format!("failed to parse HTTP registry index.json: {source}"),
                })?;
            for hit in &mut index.skills {
                self.validate_hit(hit)?;
            }
            return Ok(index);
        }

        let Some(content) = self.get_optional_text(self.index_yaml_url()?).await? else {
            return Ok(HttpRegistryIndex::default());
        };
        let mut index: HttpRegistryIndex =
            serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml {
                path: PathBuf::from(INDEX_YAML_FILE),
                source,
            })?;
        for hit in &mut index.skills {
            self.validate_hit(hit)?;
        }
        Ok(index)
    }
```

Keep `write_index` on YAML fallback for existing publish tests, or write both JSON and YAML if the test harness makes that cheap.

- [ ] **Step 6: Implement tarball fetch before legacy expanded fetch**

Add URL helper:

```rust
fn tarball_url(&self, name: &str, version: &str) -> Result<Url, SkillError> {
    self.url_for(&["skills", name, &format!("{version}.tar.zst")])
}
```

Add unpack helper:

```rust
fn unpack_tar_zst(bytes: &[u8], destination: &Path) -> Result<(), SkillError> {
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|source| {
        SkillError::InvalidConfig {
            message: format!("failed to decode skill tar.zst: {source}"),
        }
    })?;
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().map_err(|source| SkillError::InvalidConfig {
        message: format!("failed to read skill tar entries: {source}"),
    })? {
        let mut entry = entry.map_err(|source| SkillError::InvalidConfig {
            message: format!("failed to read skill tar entry: {source}"),
        })?;
        let path = entry.path().map_err(|source| SkillError::InvalidConfig {
            message: format!("failed to read skill tar path: {source}"),
        })?;
        let relative = super::manifest::normalize_bundle_path(&path)?;
        entry
            .unpack(destination.join(relative))
            .map_err(|source| SkillError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
    }
    Ok(())
}
```

In `fetch`, before legacy manifest/content downloads:

```rust
        let tarball_url = self.tarball_url(&hit.name, &hit.version)?;
        match self.get_optional_bytes(tarball_url).await? {
            Some(bytes) => {
                unpack_tar_zst(&bytes, &staging_path)?;
            }
            None => {
                self.fetch_expanded_bundle(&hit, &staging_path).await?;
            }
        }
```

Extract the existing expanded fetch body into:

```rust
async fn fetch_expanded_bundle(
    &self,
    hit: &SkillSearchHit,
    staging_path: &Path,
) -> Result<(), SkillError> {
    let manifest_url = self.manifest_url(&hit.name, &hit.version)?;
    let manifest_content = self.get_text(manifest_url).await?;
    let remote_manifest = load_remote_skill_manifest(&manifest_content, Path::new(MANIFEST_FILE))?;
    if remote_manifest.name != hit.name || remote_manifest.version.to_string() != hit.version {
        return Err(SkillError::InvalidConfig {
            message: format!(
                "HTTP registry index selected `{}` version `{}`, but manifest is `{}` version `{}`",
                hit.name, hit.version, remote_manifest.name, remote_manifest.version
            ),
        });
    }
    write_file(&staging_path.join(MANIFEST_FILE), manifest_content.as_bytes())?;
    for declared_file in &remote_manifest.declared_files {
        let content = self
            .get_bytes(self.content_url(&hit.name, &hit.version, declared_file)?)
            .await?;
        write_file(&staging_path.join(declared_file), &content)?;
    }
    Ok(())
}
```

Add `get_optional_bytes` matching `get_optional_text`.

- [ ] **Step 7: Run HTTP tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills http_registry
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock crates/agentenv-core/Cargo.toml crates/agentenv-core/src/skills/registry_http.rs crates/agentenv-core/tests/skills.rs docs/superpowers/specs/2026-05-10-m7-4-skill-registry-backends-design.md
git commit -m "feat: support http skill registry artifacts"
```

## Task 4: Git Registry Adapter Search And Fetch

**Files:**
- Modify: `crates/agentenv-core/src/skills/registry_git.rs`
- Modify: `crates/agentenv-core/src/skills/service.rs`
- Test: `crates/agentenv-core/src/skills/registry_git.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Add unit tests with a fake checkout**

Inside `registry_git.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::Arc};

    #[derive(Debug)]
    struct StaticCheckout {
        path: PathBuf,
    }

    impl GitCheckout for StaticCheckout {
        fn checkout(&self, _url: &str, _cache_root: &Path) -> Result<PathBuf, SkillError> {
            Ok(self.path.clone())
        }
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

    #[tokio::test]
    async fn git_registry_search_scans_skill_directories() {
        let checkout = temp_dir("skill-git-search");
        write_file(
            &checkout.join("tools/review/skill.yaml"),
            "name: review-skill\nversion: 0.2.0\ndescription: Review helper\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("tools/review/SKILL.md"), "# Review\n");
        let adapter = GitRegistryAdapter::with_checkout(
            "git-dev",
            "git+https://github.com/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
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
        let adapter = GitRegistryAdapter::with_checkout(
            "git-dev",
            "git+https://github.com/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
        );

        let fetched = adapter.fetch("versioned-git", None).await.unwrap();

        assert_eq!(fetched.source_type, "git");
        assert_eq!(fetched.version, "0.3.0");
        assert!(fetched.staging_path.join("SKILL.md").is_file());
    }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core registry_git
```

Expected: fail to compile because `GitCheckout`, `with_checkout`, and real scanning are missing.

- [ ] **Step 3: Implement checkout seam and scanning**

Replace the stub in `registry_git.rs` with:

```rust
use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use semver::Version;

use super::{
    compute_bundle_digest, manifest::validated_bundle_file, validate_skill_name, FetchedSkill,
    RegistryAdapter, SkillError, SkillManifest, SkillSearchHit,
};

const MANIFEST_FILE: &str = "skill.yaml";
const SOURCE_TYPE: &str = "git";

pub(crate) trait GitCheckout: Send + Sync + std::fmt::Debug {
    fn checkout(&self, url: &str, cache_root: &Path) -> Result<PathBuf, SkillError>;
}

#[derive(Debug)]
struct CommandGitCheckout;

impl GitCheckout for CommandGitCheckout {
    fn checkout(&self, url: &str, cache_root: &Path) -> Result<PathBuf, SkillError> {
        fs::create_dir_all(cache_root).map_err(|source| SkillError::Io {
            path: cache_root.to_path_buf(),
            source,
        })?;
        let checkout = cache_root.join("checkout");
        if checkout.join(".git").is_dir() {
            run_git(
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
                &[
                    "-C".to_owned(),
                    path_arg(&checkout),
                    "reset".to_owned(),
                    "--hard".to_owned(),
                    "origin/HEAD".to_owned(),
                ],
                url,
            )?;
        } else {
            let clone_url = clone_url(url)?;
            run_git(
                &[
                    "clone".to_owned(),
                    "--filter=blob:none".to_owned(),
                    "--depth=1".to_owned(),
                    clone_url,
                    path_arg(&checkout),
                ],
                url,
            )?;
        }
        Ok(checkout)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GitRegistryAdapter {
    name: String,
    url: String,
    cache_root: PathBuf,
    checkout: Arc<dyn GitCheckout>,
}

impl GitRegistryAdapter {
    pub(crate) fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
    ) -> Self {
        Self::with_checkout(name, url, cache_root, Arc::new(CommandGitCheckout))
    }

    pub(crate) fn with_checkout(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
        checkout: Arc<dyn GitCheckout>,
    ) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            cache_root: cache_root.into(),
            checkout,
        }
    }

    fn checkout_path(&self) -> Result<PathBuf, SkillError> {
        self.checkout.checkout(&self.url, &self.cache_root)
    }

    fn scan(&self, root: &Path) -> Result<Vec<(SkillManifest, PathBuf, String)>, SkillError> {
        let mut found = Vec::new();
        scan_dir(root, &mut found)?;
        found.sort_by(|left, right| {
            left.0
                .name
                .cmp(&right.0.name)
                .then_with(|| left.0.version.cmp(&right.0.version))
                .then_with(|| left.1.cmp(&right.1))
        });
        Ok(found)
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
```

Add helpers:

```rust
fn scan_dir(dir: &Path, found: &mut Vec<(SkillManifest, PathBuf, String)>) -> Result<(), SkillError> {
    for entry in fs::read_dir(dir).map_err(|source| SkillError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| SkillError::Io {
            path: dir.to_path_buf(),
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
        if path.join(MANIFEST_FILE).is_file() {
            let manifest = super::load_skill_manifest(&path)?;
            let digest = compute_bundle_digest(&path, &manifest)?;
            found.push((manifest, path, digest));
            continue;
        }
        scan_dir(&path, found)?;
    }
    Ok(())
}

fn copy_bundle_contents(
    source_root: &Path,
    destination_root: &Path,
    manifest: &SkillManifest,
) -> Result<(), SkillError> {
    fs::create_dir_all(destination_root).map_err(|source| SkillError::Io {
        path: destination_root.to_path_buf(),
        source,
    })?;
    copy_regular_file(
        &source_root.join(MANIFEST_FILE),
        &destination_root.join(MANIFEST_FILE),
    )?;
    for declared_file in &manifest.declared_files {
        let source = validated_bundle_file(source_root, declared_file)?;
        copy_regular_file(&source, &destination_root.join(declared_file))?;
    }
    Ok(())
}
```

Implement `RegistryAdapter`:

```rust
#[async_trait::async_trait]
impl RegistryAdapter for GitRegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        let checkout = self.checkout_path()?;
        let query = query.to_ascii_lowercase();
        let mut hits = self
            .scan(&checkout)?
            .into_iter()
            .filter_map(|(manifest, _path, digest)| {
                let description = manifest.description.as_deref().unwrap_or_default();
                let matches = query.is_empty()
                    || manifest.name.to_ascii_lowercase().contains(&query)
                    || description.to_ascii_lowercase().contains(&query);
                matches.then(|| self.hit_for_manifest(&manifest, digest))
            })
            .collect::<Vec<_>>();
        sort_hits(&mut hits);
        Ok(hits)
    }

    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        validate_skill_name(name)?;
        if let Some(version) = version {
            version.parse::<Version>().map_err(|source| SkillError::InvalidVersion {
                version: version.to_owned(),
                source,
            })?;
        }
        let checkout = self.checkout_path()?;
        let mut matches = self
            .scan(&checkout)?
            .into_iter()
            .filter(|(manifest, _path, _digest)| manifest.name == name)
            .collect::<Vec<_>>();
        if let Some(version) = version {
            matches.retain(|(manifest, _path, _digest)| manifest.version.to_string() == version);
        }
        let (manifest, source_path, _digest) = matches
            .into_iter()
            .max_by(|left, right| left.0.version.cmp(&right.0.version))
            .ok_or_else(|| SkillError::SkillNotInstalled {
                name: name.to_owned(),
            })?;
        let staging_path = staging_fetch_path(&manifest.name, &manifest.version.to_string());
        remove_directory_if_exists(&staging_path)?;
        copy_bundle_contents(&source_path, &staging_path, &manifest)?;
        Ok(FetchedSkill {
            staging_path,
            registry: self.name.clone(),
            source_type: SOURCE_TYPE.to_owned(),
            name: manifest.name,
            version: manifest.version.to_string(),
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
```

Add these private helpers in `registry_git.rs`; they keep git execution non-interactive and avoid shell interpolation:

```rust
fn clone_url(url: &str) -> Result<String, SkillError> {
    url.strip_prefix("git+")
        .filter(|value| value.starts_with("https://"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| SkillError::InvalidConfig {
            message: format!("invalid git registry URL `{url}`"),
        })
}

fn run_git(args: &[String], url: &str) -> Result<(), SkillError> {
    let output = Command::new("git")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|source| SkillError::GitRegistry {
            url: url.to_owned(),
            message: format!("failed to start git: {source}"),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(SkillError::GitRegistry {
        url: url.to_owned(),
        message: stderr.trim().to_owned(),
    })
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn staging_fetch_path(name: &str, version: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "agentenv-git-skill-fetch-{name}-{version}-{}",
        std::process::id()
    ));
    path
}

fn remove_directory_if_exists(path: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir_all(path).map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), SkillError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| SkillError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: source.to_path_buf(),
        });
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|source_error| SkillError::Io {
            path: parent.to_path_buf(),
            source: source_error,
        })?;
    }
    fs::copy(source, destination).map_err(|source_error| SkillError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
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

fn compare_versions(left: &str, right: &str) -> Ordering {
    match (left.parse::<Version>(), right.parse::<Version>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}
```

- [ ] **Step 4: Wire cache root in service**

Update `SkillService::adapter_for` git arm:

```rust
Ok(Box::new(registry_git::GitRegistryAdapter::new(
    registry.name.clone(),
    url,
    self.root.join("cache").join("skill-git").join(&registry.name),
)))
```

- [ ] **Step 5: Add integration test for unsupported publish**

In `crates/agentenv-core/tests/skills.rs`:

```rust
#[tokio::test]
async fn git_registry_publish_is_reported_as_unsupported() {
    let home = temp_dir("skill-git-publish-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::git(
                "git-dev",
                "git+https://github.com/acme/skills",
            )],
            registry_order: vec!["git-dev".to_owned()],
        },
    );

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("git-publish", "0.1.0", "Git publish"),
            registry: Some("git-dev".to_owned()),
            allow_unsigned: true,
        })
        .await
        .expect_err("git publish should be read-only");

    assert!(matches!(
        error,
        SkillError::UnsupportedRegistryPublish { registry, kind }
            if registry == "git-dev" && kind == "git"
    ));
}
```

- [ ] **Step 6: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core registry_git
cargo test -p agentenv-core --test skills git_registry_publish_is_reported_as_unsupported
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv-core/src/skills/registry_git.rs crates/agentenv-core/src/skills/service.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: add git skill registry backend"
```

## Task 5: CLI Coverage And Documentation Polish

**Files:**
- Modify: `crates/agentenv/tests/cli_behavior.rs`
- Modify: `docs/ARCHITECTURE.md` if registry backend text is missing git or index layouts
- Modify: `docs/superpowers/specs/2026-05-10-m7-4-skill-registry-backends-design.md` only for implementation-discovered clarifications

- [ ] **Step 1: Find existing skills CLI tests**

Run:

```bash
rg -n "skills|Skills" crates/agentenv/tests/cli_behavior.rs
```

Expected: existing command inventory and skills lifecycle tests are listed.

- [ ] **Step 2: Add CLI test for git registry override validation**

In `crates/agentenv/tests/cli_behavior.rs`, add a test near other skills CLI tests:

```rust
#[test]
fn skills_search_accepts_git_registry_override_syntax() {
    let home = temp_dir("skills-cli-git-override-home");
    let output = agentenv_cmd()
        .env("HOME", &home)
        .args([
            "skills",
            "search",
            "anything",
            "--registry",
            "git+https://github.com/acme/skills",
            "--json",
        ])
        .output()
        .expect("command should run");

    assert!(
        !output.status.success(),
        "search may fail because fixture repo is not reachable, but CLI/config parsing must accept the git override"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unsupported registry URL scheme"),
        "git+https should be parsed as a git registry override: {stderr}"
    );
}
```

If the test harness has a stricter stderr style, adapt the assertion to its helpers but keep the behavioral check: the failure must not be config parsing.

- [ ] **Step 3: Update docs only if needed**

Run:

```bash
rg -n "Skills as a core-managed resource|registry adapters|git\\+https|index.json|tar.zst" docs/ARCHITECTURE.md docs/ROADMAP.md README.md
```

If `docs/ARCHITECTURE.md` lacks git registry wording, add one sentence under "Skills as a core-managed resource":

```markdown
Supported registry adapters are filesystem, HTTP static indexes, OCI artifacts, and git repositories; all are resolved by core before sandbox creation.
```

- [ ] **Step 4: Run CLI tests and verify GREEN**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills
```

Expected: skills-related CLI tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/tests/cli_behavior.rs docs/ARCHITECTURE.md docs/superpowers/specs/2026-05-10-m7-4-skill-registry-backends-design.md
git commit -m "test: cover skill registry cli behavior"
```

## Task 6: Final Verification And Cleanup

**Files:**
- Review all touched files.

- [ ] **Step 1: Check for accidental broad changes**

Run:

```bash
git diff --stat origin/main..HEAD
git diff --name-only origin/main..HEAD
```

Expected: changes are limited to skill registry implementation, tests, and docs.

- [ ] **Step 2: Format**

Run:

```bash
cargo fmt --all --check
```

Expected: pass. If it fails, run `cargo fmt --all`, inspect the diff, and commit formatting with the relevant task commit or a final `style:` commit.

- [ ] **Step 3: Clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: pass with no warnings.

- [ ] **Step 4: Workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: pass. If host git is unavailable and a test depends on it, gate only that subprocess-dependent test with a clear skip and keep pure validation tests active.

- [ ] **Step 5: Final commit if needed**

If verification fixes changed files:

```bash
git add <changed-files>
git commit -m "fix: stabilize skill registry backends"
```

- [ ] **Step 6: Summarize PR scope**

Prepare this PR summary:

```markdown
Summary:
- added git skill registry config, search/fetch support, and read-only publish diagnostics
- completed filesystem indexless scan and HTTP index.json/tar.zst compatibility
- preserved existing filesystem/HTTP/OCI behavior and provenance shape

Affected crates:
- agentenv-core
- agentenv

Protocol:
- no agentenv-proto schema changes

Verification:
- cargo fmt --all --check
- cargo clippy --workspace --all-targets -- -D warnings
- cargo test --workspace
```
