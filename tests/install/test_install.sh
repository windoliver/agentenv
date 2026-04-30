#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)

AGENTENV_INSTALLER_SOURCE_ONLY=1 . "${REPO_ROOT}/install.sh"
AGENTENV_UNINSTALLER_SOURCE_ONLY=1 . "${REPO_ROOT}/uninstall.sh"
unset AGENTENV_UNINSTALLER_SOURCE_ONLY

ORIGINAL_PATH=${PATH}
TEST_COUNT=0

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    TEST_COUNT=$((TEST_COUNT + 1))
}

assert_eq() {
    expected=$1
    actual=$2
    context=$3
    if [ "${expected}" != "${actual}" ]; then
        fail "${context}: expected '${expected}', got '${actual}'"
    fi
}

assert_contains() {
    needle=$1
    haystack_file=$2
    context=$3
    if ! grep -F "${needle}" "${haystack_file}" >/dev/null 2>&1; then
        fail "${context}: did not find '${needle}' in ${haystack_file}"
    fi
}

assert_not_exists() {
    path=$1
    context=$2
    if [ -e "${path}" ]; then
        fail "${context}: ${path} should not exist"
    fi
}

assert_exists() {
    path=$1
    context=$2
    if [ ! -e "${path}" ]; then
        fail "${context}: ${path} should exist"
    fi
}

make_stub_cmd() {
    command_dir=$1
    name=$2
    content=$3
    mkdir -p "${command_dir}"
    cat > "${command_dir}/${name}" <<EOF
#!/bin/sh
${content}
EOF
    chmod +x "${command_dir}/${name}"
}

make_stub_python3_for_driver_install() {
    command_dir=$1
    mkdir -p "${command_dir}"
    cat > "${command_dir}/python3" <<'EOF'
#!/bin/sh
set -eu

if [ "$#" -ge 3 ] && [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
    venv_dir=$3
    mkdir -p "${venv_dir}/bin"
    cat > "${venv_dir}/bin/python" <<'PYEOF'
#!/bin/sh
set -eu

if [ "$#" -ge 3 ] && [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
    exit 0
fi

printf 'unexpected venv python invocation: %s\n' "$*" >&2
exit 1
PYEOF
    chmod +x "${venv_dir}/bin/python"
    exit 0
fi

if [ "$#" -ge 3 ] && [ "$1" = "-" ]; then
    cat >/dev/null
    src=$2
    dst=$3
    rm -f "${dst}"
    mv "${src}" "${dst}"
    exit 0
fi

printf 'unexpected python3 invocation: %s\n' "$*" >&2
exit 1
EOF
    chmod +x "${command_dir}/python3"
}

test_detect_target_linux_gnu() {
    tmp_root=$(mktemp -d)

    make_stub_cmd "${tmp_root}/bin" uname 'case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac'
    make_stub_cmd "${tmp_root}/bin" ldd 'echo "ldd (GNU libc) 2.39"'

    PATH="${tmp_root}/bin:${ORIGINAL_PATH}"
    TARGET_TRIPLE=""
    detect_target_triple
    assert_eq "x86_64-unknown-linux-gnu" "${TARGET_TRIPLE}" "linux gnu target detection"

    PATH=${ORIGINAL_PATH}
    rm -rf "${tmp_root}"
    pass
}

test_detect_target_linux_musl() {
    tmp_root=$(mktemp -d)

    make_stub_cmd "${tmp_root}/bin" uname 'case "$1" in -s) echo Linux ;; -m) echo aarch64 ;; *) exit 1 ;; esac'
    make_stub_cmd "${tmp_root}/bin" ldd 'echo "musl libc (aarch64)"'

    PATH="${tmp_root}/bin:${ORIGINAL_PATH}"
    TARGET_TRIPLE=""
    detect_target_triple
    assert_eq "aarch64-unknown-linux-musl" "${TARGET_TRIPLE}" "linux musl target detection"

    PATH=${ORIGINAL_PATH}
    rm -rf "${tmp_root}"
    pass
}

test_detect_target_macos() {
    tmp_root=$(mktemp -d)

    make_stub_cmd "${tmp_root}/bin" uname 'case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) exit 1 ;; esac'

    PATH="${tmp_root}/bin:${ORIGINAL_PATH}"
    TARGET_TRIPLE=""
    detect_target_triple
    assert_eq "aarch64-apple-darwin" "${TARGET_TRIPLE}" "macOS target detection"

    PATH=${ORIGINAL_PATH}
    rm -rf "${tmp_root}"
    pass
}

test_verify_sha256_value() {
    tmp_root=$(mktemp -d)

    sample_file="${tmp_root}/sample.txt"
    printf 'agentenv\n' > "${sample_file}"
    expected_hash=$(sha256_file "${sample_file}")
    verify_sha256_value "${sample_file}" "${expected_hash}"

    rm -rf "${tmp_root}"
    pass
}

test_archive_name_candidates_cover_legacy_and_dist_formats() {
    RESOLVED_VERSION="v0.1.0"
    RESOLVED_VERSION_NOPREFIX="0.1.0"
    TARGET_TRIPLE="x86_64-unknown-linux-gnu"

    candidates=$(archive_name_candidates)
    tmp_file=$(mktemp)
    printf '%s\n' "${candidates}" > "${tmp_file}"
    assert_contains "agentenv-0.1.0-x86_64-unknown-linux-gnu.tar.gz" "${tmp_file}" "legacy tar.gz candidate"
    assert_contains "agentenv-v0.1.0-x86_64-unknown-linux-gnu.tar.gz" "${tmp_file}" "v-prefixed tar.gz candidate"
    assert_contains "agentenv-x86_64-unknown-linux-gnu.tar.xz" "${tmp_file}" "cargo-dist tar.xz candidate"
    rm -f "${tmp_file}"
    pass
}

test_write_path_exports_is_idempotent() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    mkdir -p "${HOME}"
    TMP_ROOT="${tmp_root}/tmp"
    mkdir -p "${TMP_ROOT}"
    INSTALL_DIR="${HOME}/.agentenv/bin"

    printf 'export FOO=bar\n' > "${HOME}/.zshrc"

    write_path_exports
    write_path_exports

    assert_contains "${INSTALLER_SENTINEL}" "${HOME}/.zshrc" "rc file should contain installer sentinel"
    sentinel_count=$(grep -c "${INSTALLER_SENTINEL}" "${HOME}/.zshrc")
    assert_eq "1" "${sentinel_count}" "rc file should not duplicate installer block"

    backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "1" "${backup_count}" "rc file backup count"

    rm -rf "${tmp_root}"
    pass
}

test_configure_shell_path_persists_when_current_shell_has_path() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    mkdir -p "${HOME}"
    TMP_ROOT="${tmp_root}/tmp"
    mkdir -p "${TMP_ROOT}"
    INSTALL_DIR="${HOME}/.agentenv/bin"
    PATH="${INSTALL_DIR}:${ORIGINAL_PATH}"
    NON_INTERACTIVE=1
    PATH_STATUS="unchanged"

    configure_shell_path

    assert_contains "${INSTALLER_SENTINEL}" "${HOME}/.profile" "configure_shell_path should persist PATH"
    assert_contains "${INSTALL_DIR}" "${HOME}/.profile" "configure_shell_path should write install dir"
    assert_eq "updated ${HOME}/.profile " "${PATH_STATUS}" "configure_shell_path status"

    PATH=${ORIGINAL_PATH}
    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_preserves_existing_driver_on_extract_failure() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/home/.agentenv/drivers/context-nexus-py"
    printf '{"old":true}\n' > "${tmp_root}/home/.agentenv/drivers/context-nexus-py/manifest.json"
    mkdir -p "${tmp_root}/index" "${tmp_root}/releases"
    printf 'not a tarball\n' > "${tmp_root}/releases/bad.tar.gz"

    expected_hash=$(sha256_file "${tmp_root}/releases/bad.tar.gz")
    printf 'context-nexus-py|file://%s/releases/bad.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/index/drivers.index"

    set +e
    sh -c '
        tmp_root=$1
        repo_root=$2
        AGENTENV_INSTALLER_SOURCE_ONLY=1 . "$repo_root/install.sh"
        TMP_ROOT="$tmp_root/tmp"
        mkdir -p "$TMP_ROOT"
        AGENTENV_HOME="$tmp_root/home/.agentenv"
        WITH_PYTHON_DRIVERS=1
        PYTHON_DRIVERS_INDEX_URL="file://$tmp_root/index/drivers.index"
        install_python_drivers
    ' sh "${tmp_root}" "${REPO_ROOT}" > "${tmp_root}/python-drivers.log" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "install_python_drivers should fail for an invalid tarball"
    assert_contains '{"old":true}' "${tmp_root}/home/.agentenv/drivers/context-nexus-py/manifest.json" "existing driver manifest should survive a failed upgrade"

    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_installs_context_nexus_bundle() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/bundle/context-nexus/bin" "${tmp_root}/bundle/context-nexus/venv"
    printf '{"name":"nexus","kind":"context"}\n' > "${tmp_root}/bundle/context-nexus/manifest.json"
    printf '#!/bin/sh\n' > "${tmp_root}/bundle/context-nexus/bin/agentenv-driver-nexus"
    chmod +x "${tmp_root}/bundle/context-nexus/bin/agentenv-driver-nexus"
    (cd "${tmp_root}/bundle" && tar -czf "${tmp_root}/context-nexus.tar.gz" context-nexus)

    expected_hash=$(sha256_file "${tmp_root}/context-nexus.tar.gz")
    printf 'context-nexus|file://%s/context-nexus.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/drivers.index"

    TMP_ROOT="${tmp_root}/tmp"
    mkdir -p "${TMP_ROOT}"
    AGENTENV_HOME="${tmp_root}/home/.agentenv"
    WITH_PYTHON_DRIVERS=1
    PYTHON_DRIVERS_INDEX_URL="file://${tmp_root}/drivers.index"

    install_python_drivers

    test -f "${AGENTENV_HOME}/drivers/context-nexus/manifest.json" || fail "context-nexus manifest missing"
    test -x "${AGENTENV_HOME}/drivers/context-nexus/bin/agentenv-driver-nexus" || fail "context-nexus launcher missing"
    assert_eq "installed 1 bundle(s)" "${PYTHON_DRIVER_STATUS}" "python driver install status"

    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_runs_bundle_install_hook() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/bundle/bin" "${tmp_root}/bundle/wheels" "${tmp_root}/index" "${tmp_root}/releases"
    printf '{"schema_version":"1.0","name":"hermes","kind":"agent","version":"0.1.0","binary":"./bin/agentenv-driver-hermes"}\n' > "${tmp_root}/bundle/manifest.json"
    printf '#!/bin/sh\nset -eu\nprintf hook-ran > hook.txt\n' > "${tmp_root}/bundle/install-driver.sh"
    chmod +x "${tmp_root}/bundle/install-driver.sh"
    tar -C "${tmp_root}/bundle" -czf "${tmp_root}/releases/agent-hermes.tar.gz" .

    expected_hash=$(sha256_file "${tmp_root}/releases/agent-hermes.tar.gz")
    printf 'agent-hermes|file://%s/releases/agent-hermes.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/index/drivers.index"

    sh -c '
        tmp_root=$1
        repo_root=$2
        AGENTENV_INSTALLER_SOURCE_ONLY=1 . "$repo_root/install.sh"
        TMP_ROOT="$tmp_root/tmp"
        mkdir -p "$TMP_ROOT"
        AGENTENV_HOME="$tmp_root/home/.agentenv"
        WITH_PYTHON_DRIVERS=1
        PYTHON_DRIVERS_INDEX_URL="file://$tmp_root/index/drivers.index"
        install_python_drivers
    ' sh "${tmp_root}" "${REPO_ROOT}"

    assert_contains "hook-ran" "${tmp_root}/home/.agentenv/drivers/agent-hermes/hook.txt" "bundle install hook should run before replacement"

    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_preserves_existing_driver_on_hook_failure() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/home/.agentenv/drivers/agent-hermes"
    printf '{"old":true}\n' > "${tmp_root}/home/.agentenv/drivers/agent-hermes/manifest.json"
    mkdir -p "${tmp_root}/bundle/bin" "${tmp_root}/index" "${tmp_root}/releases"
    printf '{"schema_version":"1.0","name":"hermes","kind":"agent","version":"0.1.0","binary":"./bin/agentenv-driver-hermes"}\n' > "${tmp_root}/bundle/manifest.json"
    printf '#!/bin/sh\nset -eu\nexit 7\n' > "${tmp_root}/bundle/install-driver.sh"
    chmod +x "${tmp_root}/bundle/install-driver.sh"
    tar -C "${tmp_root}/bundle" -czf "${tmp_root}/releases/agent-hermes.tar.gz" .

    expected_hash=$(sha256_file "${tmp_root}/releases/agent-hermes.tar.gz")
    printf 'agent-hermes|file://%s/releases/agent-hermes.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/index/drivers.index"

    set +e
    sh -c '
        tmp_root=$1
        repo_root=$2
        AGENTENV_INSTALLER_SOURCE_ONLY=1 . "$repo_root/install.sh"
        TMP_ROOT="$tmp_root/tmp"
        mkdir -p "$TMP_ROOT"
        AGENTENV_HOME="$tmp_root/home/.agentenv"
        WITH_PYTHON_DRIVERS=1
        PYTHON_DRIVERS_INDEX_URL="file://$tmp_root/index/drivers.index"
        install_python_drivers
    ' sh "${tmp_root}" "${REPO_ROOT}" > "${tmp_root}/hook-failure.log" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "install_python_drivers should fail when bundle hook fails"
    assert_contains '{"old":true}' "${tmp_root}/home/.agentenv/drivers/agent-hermes/manifest.json" "existing driver manifest should survive a failed hook"

    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_installs_source_context_nexus_bundle_with_venv() {
    tmp_root=$(mktemp -d)

    make_stub_python3_for_driver_install "${tmp_root}/bin"
    bundle_path=$(cd "${REPO_ROOT}/external-drivers/context-nexus-py" && ./scripts/build-bundle.sh "${tmp_root}/dist")

    expected_hash=$(sha256_file "${bundle_path}")
    printf 'context-nexus|file://%s|%s\n' "${bundle_path}" "${expected_hash}" > "${tmp_root}/drivers.index"

    TMP_ROOT="${tmp_root}/tmp"
    mkdir -p "${TMP_ROOT}"
    AGENTENV_HOME="${tmp_root}/home/.agentenv"
    WITH_PYTHON_DRIVERS=1
    PYTHON_DRIVERS_INDEX_URL="file://${tmp_root}/drivers.index"
    PATH="${tmp_root}/bin:${ORIGINAL_PATH}"

    install_python_drivers

    PATH=${ORIGINAL_PATH}
    test -f "${AGENTENV_HOME}/drivers/context-nexus/manifest.json" || fail "source context-nexus manifest missing"
    test -x "${AGENTENV_HOME}/drivers/context-nexus/bin/agentenv-driver-nexus" || fail "source context-nexus launcher missing"
    test -x "${AGENTENV_HOME}/drivers/context-nexus/venv/bin/python" || fail "source context-nexus venv python missing"
    assert_eq "installed 1 bundle(s)" "${PYTHON_DRIVER_STATUS}" "source python driver install status"

    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_upgrades_directory_context_nexus_to_source_bundle() {
    tmp_root=$(mktemp -d)

    make_stub_python3_for_driver_install "${tmp_root}/bin"
    bundle_path=$(cd "${REPO_ROOT}/external-drivers/context-nexus-py" && ./scripts/build-bundle.sh "${tmp_root}/dist")

    expected_hash=$(sha256_file "${bundle_path}")
    printf 'context-nexus|file://%s|%s\n' "${bundle_path}" "${expected_hash}" > "${tmp_root}/drivers.index"

    AGENTENV_HOME="${tmp_root}/home/.agentenv"
    mkdir -p "${AGENTENV_HOME}/drivers/context-nexus/bin"
    printf '{"old":true}\n' > "${AGENTENV_HOME}/drivers/context-nexus/manifest.json"
    printf '#!/bin/sh\n' > "${AGENTENV_HOME}/drivers/context-nexus/bin/agentenv-driver-nexus"
    chmod +x "${AGENTENV_HOME}/drivers/context-nexus/bin/agentenv-driver-nexus"

    TMP_ROOT="${tmp_root}/tmp"
    mkdir -p "${TMP_ROOT}"
    WITH_PYTHON_DRIVERS=1
    PYTHON_DRIVERS_INDEX_URL="file://${tmp_root}/drivers.index"
    PATH="${tmp_root}/bin:${ORIGINAL_PATH}"

    install_python_drivers

    PATH=${ORIGINAL_PATH}
    driver_dir="${AGENTENV_HOME}/drivers/context-nexus"
    if [ ! -L "${driver_dir}" ] && [ ! -x "${driver_dir}/venv/bin/python" ]; then
        fail "context-nexus should be upgraded to a symlink install or contain venv/bin/python"
    fi
    test -f "${driver_dir}/manifest.json" || fail "upgraded context-nexus manifest missing"
    test -x "${driver_dir}/bin/agentenv-driver-nexus" || fail "upgraded context-nexus launcher missing"
    test -x "${driver_dir}/venv/bin/python" || fail "upgraded context-nexus venv python missing"
    if grep -F '{"old":true}' "${driver_dir}/manifest.json" >/dev/null 2>&1; then
        fail "upgraded context-nexus manifest still contains old manifest"
    fi
    assert_eq "installed 1 bundle(s)" "${PYTHON_DRIVER_STATUS}" "upgraded source python driver install status"

    rm -rf "${tmp_root}"
    pass
}

test_install_driver_launcher_prepends_venv_bin_to_path() {
    tmp_root=$(mktemp -d)

    make_stub_python3_for_driver_install "${tmp_root}/bin"
    PATH="${tmp_root}/bin:${ORIGINAL_PATH}"
    AGENTENV_HOME="${tmp_root}/home/.agentenv"
    (cd "${REPO_ROOT}/external-drivers/context-nexus-py" && AGENTENV_HOME="${AGENTENV_HOME}" ./scripts/install-driver.sh > "${tmp_root}/install-driver.out")
    PATH=${ORIGINAL_PATH}

    launcher="${AGENTENV_HOME}/drivers/context-nexus/bin/agentenv-driver-nexus"
    test -x "${launcher}" || fail "context-nexus launcher missing after install-driver.sh"
    assert_contains 'PATH="${SCRIPT_DIR}/../venv/bin${PATH:+:$PATH}"' "${launcher}" "launcher should prepend venv bin to PATH"
    assert_contains 'export PATH' "${launcher}" "launcher should export PATH"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_dry_run_prints_plan_without_removing() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}" "${AGENTENV_HOME}/envs/demo" "${AGENTENV_HOME}/drivers/context-nexus"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf '{"values":{"TOKEN":"secret"}}\n' > "${AGENTENV_HOME}/credentials.json"
    printf '# agentenv installer\nexport PATH="%s:$PATH"\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"
    project_dir="${tmp_root}/project"
    mkdir -p "${project_dir}"
    printf 'user work\n' > "${project_dir}/README.md"

    output_file="${tmp_root}/dry-run.out"
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --dry-run > "${output_file}"

    assert_contains "Uninstall plan" "${output_file}" "dry-run should print a plan"
    assert_contains "${INSTALL_DIR}/agentenv" "${output_file}" "plan should include binary"
    assert_contains "${AGENTENV_HOME}/drivers" "${output_file}" "plan should include drivers"
    assert_exists "${INSTALL_DIR}/agentenv" "dry-run should not remove binary"
    assert_exists "${AGENTENV_HOME}/credentials.json" "dry-run should not remove credentials"
    assert_exists "${project_dir}/README.md" "dry-run should not touch project directories"

    rm -rf "${tmp_root}"
    pass
}

test_choose_rc_targets_creates_profile_when_missing() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    mkdir -p "${HOME}"
    choose_rc_targets
    expected="${HOME}/.profile"
    actual=$(printf '%s' "${RC_TARGETS}" | sed '/^$/d')
    assert_eq "${expected}" "${actual}" "fallback rc target"

    rm -rf "${tmp_root}"
    pass
}

main() {
    test_detect_target_linux_gnu
    test_detect_target_linux_musl
    test_detect_target_macos
    test_verify_sha256_value
    test_archive_name_candidates_cover_legacy_and_dist_formats
    test_uninstall_dry_run_prints_plan_without_removing
    test_write_path_exports_is_idempotent
    test_configure_shell_path_persists_when_current_shell_has_path
    test_install_python_drivers_preserves_existing_driver_on_extract_failure
    test_install_python_drivers_installs_context_nexus_bundle
    test_install_python_drivers_runs_bundle_install_hook
    test_install_python_drivers_preserves_existing_driver_on_hook_failure
    test_install_python_drivers_installs_source_context_nexus_bundle_with_venv
    test_install_python_drivers_upgrades_directory_context_nexus_to_source_bundle
    test_install_driver_launcher_prepends_venv_bin_to_path
    test_choose_rc_targets_creates_profile_when_missing
    printf 'PASS: %s installer tests\n' "${TEST_COUNT}"
}

main "$@"
