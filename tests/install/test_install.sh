#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)

AGENTENV_INSTALLER_SOURCE_ONLY=1 . "${REPO_ROOT}/install.sh"
AGENTENV_UNINSTALLER_SOURCE_ONLY=1 . "${REPO_ROOT}/uninstall.sh"
unset AGENTENV_UNINSTALLER_SOURCE_ONLY

ORIGINAL_PATH=${PATH}
TEST_TMPDIR="${REPO_ROOT}/target/install-test-tmp"
mkdir -p "${TEST_TMPDIR}"
TMPDIR="${TEST_TMPDIR}"
export TMPDIR
TEST_COUNT=0

mktemp() {
    case "$#" in
        0)
            command mktemp "${TMPDIR}/tmp.XXXXXX"
            ;;
        1)
            if [ "$1" = "-d" ]; then
                command mktemp -d "${TMPDIR}/tmp.XXXXXX"
            else
                command mktemp "$@"
            fi
            ;;
        *)
            command mktemp "$@"
            ;;
    esac
}

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

assert_not_contains() {
    needle=$1
    haystack_file=$2
    context=$3
    if grep -F "${needle}" "${haystack_file}" >/dev/null 2>&1; then
        fail "${context}: found '${needle}' in ${haystack_file}"
    fi
}

assert_not_exists() {
    path=$1
    context=$2
    if [ -e "${path}" ] || [ -L "${path}" ]; then
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

file_mode() {
    path=$1
    if stat -f %Lp "${path}" >/dev/null 2>&1; then
        stat -f %Lp "${path}"
        return 0
    fi
    stat -c %a "${path}"
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

test_uninstall_attempts_env_destroy_and_writes_diagnostics_on_failure() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    diagnostics_dir="${tmp_root}/diagnostics"
    mkdir -p "${INSTALL_DIR}" "${AGENTENV_HOME}/envs/demo" "${AGENTENV_HOME}/envs/bad" "${diagnostics_dir}"
    cat > "${INSTALL_DIR}/agentenv" <<'STUB'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$AGENTENV_STUB_CALLS"
if [ "$1" = "destroy" ] && [ "$2" = "bad" ]; then
    printf 'destroy failed for bad\n' >&2
    exit 7
fi
exit 0
STUB
    chmod +x "${INSTALL_DIR}/agentenv"
    printf '{"name":"demo"}\n' > "${AGENTENV_HOME}/envs/demo/state.json"
    printf '{"name":"bad"}\n' > "${AGENTENV_HOME}/envs/bad/state.json"
    calls_file="${tmp_root}/calls.log"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        AGENTENV_STUB_CALLS="${calls_file}" AGENTENV_UNINSTALL_DIAGNOSTICS_DIR="${diagnostics_dir}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2> "${tmp_root}/uninstall.err"
    rc=$?
    set -e

    assert_eq "1" "${rc}" "partial destroy failure should make uninstall exit non-zero"
    assert_contains "destroy demo --yes" "${calls_file}" "uninstall should destroy demo through CLI"
    assert_contains "destroy bad --yes" "${calls_file}" "uninstall should continue to bad env"
    assert_contains "destroy failed for bad" "${diagnostics_dir}/errors.log" "diagnostics should contain destroy failure"
    assert_contains "Uninstall plan" "${diagnostics_dir}/plan.txt" "diagnostics should include plan"
    assert_contains "Diagnostics:" "${tmp_root}/uninstall.err" "stderr should print diagnostic path"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_removes_owned_files_and_shell_block() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}" "${AGENTENV_HOME}/envs/demo" "${AGENTENV_HOME}/drivers/context-nexus"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf 'global events\n' > "${AGENTENV_HOME}/events.db"
    printf '{"values":{"TOKEN":"secret"}}\n' > "${AGENTENV_HOME}/credentials.json"
    printf 'before\n# agentenv installer\nexport PATH="%s:$PATH"\nafter\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"
    project_dir="${tmp_root}/project"
    mkdir -p "${project_dir}"
    printf 'user work\n' > "${project_dir}/README.md"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out"

    assert_not_exists "${INSTALL_DIR}/agentenv" "uninstall should remove binary"
    assert_not_exists "${AGENTENV_HOME}/drivers" "uninstall should remove drivers by default"
    assert_not_exists "${AGENTENV_HOME}/credentials.json" "uninstall should remove credentials json by default"
    assert_not_contains "# agentenv installer" "${HOME}/.zshrc" "uninstall should remove installer sentinel"
    assert_contains "before" "${HOME}/.zshrc" "uninstall should keep preexisting rc content"
    assert_contains "after" "${HOME}/.zshrc" "uninstall should keep trailing rc content"
    backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "1" "${backup_count}" "uninstall should back up changed rc file"
    assert_exists "${project_dir}/README.md" "uninstall should not touch project directories"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_keep_flags_preserve_selected_state() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}" "${AGENTENV_HOME}/envs/demo" "${AGENTENV_HOME}/drivers/context-nexus"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf '{"values":{"TOKEN":"secret"}}\n' > "${AGENTENV_HOME}/credentials.json"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes --keep-data --keep-drivers --keep-credentials > "${tmp_root}/uninstall.out"

    assert_not_exists "${INSTALL_DIR}/agentenv" "keep flags should not preserve agentenv binary"
    assert_exists "${AGENTENV_HOME}/envs/demo" "--keep-data should preserve env registry"
    assert_exists "${AGENTENV_HOME}/drivers/context-nexus" "--keep-drivers should preserve drivers"
    assert_exists "${AGENTENV_HOME}/credentials.json" "--keep-credentials should preserve credentials json"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_removes_binary_from_custom_install_dir() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}" "${AGENTENV_HOME}/envs/demo" "${AGENTENV_HOME}/drivers/context-nexus"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf 'global events\n' > "${AGENTENV_HOME}/events.db"
    printf '{"values":{"TOKEN":"secret"}}\n' > "${AGENTENV_HOME}/credentials.json"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1

    assert_not_contains "unsafe path" "${tmp_root}/uninstall.out" "custom install dir should not be rejected"
    assert_not_exists "${INSTALL_DIR}/agentenv" "custom install dir binary should be removed"
    assert_exists "${INSTALL_DIR}" "custom install dir should not be removed when empty"
    assert_not_exists "${AGENTENV_HOME}/envs" "custom install dir should still remove env registry by default"
    assert_not_exists "${AGENTENV_HOME}/drivers" "custom install dir should still remove drivers by default"
    assert_not_exists "${AGENTENV_HOME}/credentials.json" "custom install dir should still remove credentials by default"
    assert_not_exists "${AGENTENV_HOME}/events.db" "custom install dir should still remove events db"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_removes_symlinked_agentenv_binary_only() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    target_file="${tmp_root}/target-agentenv"
    mkdir -p "${INSTALL_DIR}"
    printf 'target\n' > "${target_file}"
    ln -s "${target_file}" "${INSTALL_DIR}/agentenv"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1

    assert_not_contains "unsafe path" "${tmp_root}/uninstall.out" "symlinked agentenv binary should not be rejected"
    assert_not_exists "${INSTALL_DIR}/agentenv" "uninstall should remove symlinked agentenv binary"
    assert_exists "${target_file}" "uninstall should not remove symlink target"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_second_run_is_noop() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/first.out"
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/second.out"

    assert_contains "already absent" "${tmp_root}/second.out" "second uninstall should report absent files"
    assert_not_exists "${INSTALL_DIR}/agentenv" "second uninstall should leave binary absent"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_preserves_unconfirmed_shell_sentinel_lines() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf 'before\n# agentenv installer\nafter\n' > "${HOME}/.zshrc"
    printf '# agentenv installer\nexport PATH="/other/bin:$PATH"\n' > "${HOME}/.bashrc"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out"

    assert_contains "# agentenv installer" "${HOME}/.zshrc" "standalone sentinel should be preserved"
    assert_contains "after" "${HOME}/.zshrc" "line after standalone sentinel should be preserved"
    assert_contains "# agentenv installer" "${HOME}/.bashrc" "sentinel before unrelated export should be preserved"
    assert_contains 'export PATH="/other/bin:$PATH"' "${HOME}/.bashrc" "unrelated PATH export should be preserved"

    zsh_backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    bash_backup_count=$(find "${HOME}" -name '.bashrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "0" "${zsh_backup_count}" "unchanged standalone sentinel rc should not be backed up"
    assert_eq "0" "${bash_backup_count}" "unchanged unrelated export rc should not be backed up"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_removes_only_confirmed_shell_path_block() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf 'before\n# agentenv installer\nexport PATH="%s:$PATH"\nafter\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out"

    assert_not_contains "# agentenv installer" "${HOME}/.zshrc" "confirmed installer sentinel should be removed"
    assert_not_contains "${INSTALL_DIR}" "${HOME}/.zshrc" "confirmed installer PATH export should be removed"
    assert_contains "before" "${HOME}/.zshrc" "confirmed block cleanup should keep preexisting rc content"
    assert_contains "after" "${HOME}/.zshrc" "confirmed block cleanup should keep trailing rc content"
    backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "1" "${backup_count}" "confirmed block cleanup should back up changed rc file"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_preserves_rc_file_mode() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf 'before\n# agentenv installer\nexport PATH="%s:$PATH"\nafter\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"
    chmod 600 "${HOME}/.zshrc"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh -c 'umask 022; sh "$1" --yes' sh "${REPO_ROOT}/uninstall.sh" > "${tmp_root}/uninstall.out"

    assert_eq "600" "$(file_mode "${HOME}/.zshrc")" "uninstall should preserve rc file mode"
    assert_not_contains "# agentenv installer" "${HOME}/.zshrc" "mode-preserving cleanup should remove installer sentinel"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_home_as_agentenv_home() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}" "${HOME}/envs/demo" "${HOME}/drivers/context-nexus" "${HOME}/work"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    printf 'user work\n' > "${HOME}/work/README.md"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "unsafe AGENTENV_HOME should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "unsafe AGENTENV_HOME should report unsafe path"
    assert_exists "${HOME}" "unsafe AGENTENV_HOME should not delete HOME"
    assert_exists "${HOME}/work/README.md" "unsafe AGENTENV_HOME should not delete unrelated home files"
    assert_exists "${HOME}/envs/demo" "unsafe AGENTENV_HOME should not delete home envs directory"
    assert_exists "${INSTALL_DIR}/agentenv" "unsafe AGENTENV_HOME should not delete derived binary"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_agentenv_bin_outside_install_dir() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    unsafe_bin="${tmp_root}/outside/agentenv"
    mkdir -p "${INSTALL_DIR}" "$(dirname "${unsafe_bin}")"
    printf '#!/bin/sh\n' > "${unsafe_bin}"
    chmod +x "${unsafe_bin}"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" AGENTENV_BIN="${unsafe_bin}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "unsafe AGENTENV_BIN should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "unsafe AGENTENV_BIN should report unsafe path"
    assert_exists "${unsafe_bin}" "unsafe AGENTENV_BIN should not be deleted"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_agentenv_bin_under_home_outside_install_dir() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    unsafe_bin="${AGENTENV_HOME}/not-bin/agentenv"
    mkdir -p "${INSTALL_DIR}" "$(dirname "${unsafe_bin}")"
    printf '#!/bin/sh\n' > "${unsafe_bin}"
    chmod +x "${unsafe_bin}"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" AGENTENV_BIN="${unsafe_bin}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "AGENTENV_BIN outside install dir should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "AGENTENV_BIN outside install dir should report unsafe path"
    assert_exists "${unsafe_bin}" "AGENTENV_BIN outside install dir should not be deleted"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_parent_directory_components() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv/.."
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${HOME}/envs" "${HOME}/.agentenv" "${HOME}/bin"
    printf 'keep\n' > "${HOME}/envs/keep.txt"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "parent directory component in AGENTENV_HOME should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "parent directory component should report unsafe path"
    assert_exists "${HOME}/envs/keep.txt" "parent directory component should not delete files outside agentenv home"
    assert_exists "${HOME}/bin" "parent directory component should not remove unrelated empty bin directory"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_root_install_dir() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    mkdir -p "${AGENTENV_HOME}"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="/" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "root install dir should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "root install dir should report unsafe path"
    assert_contains "AGENTENV_INSTALL_DIR" "${tmp_root}/uninstall.out" "root install dir should be rejected as configured root"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_home_as_agentenv_home_before_shell_cleanup() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '# agentenv installer\nexport PATH="%s:$PATH"\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "unsafe AGENTENV_HOME should fail before shell cleanup"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "unsafe AGENTENV_HOME should report unsafe path"
    assert_contains "# agentenv installer" "${HOME}/.zshrc" "unsafe AGENTENV_HOME should preserve shell sentinel"
    assert_contains "export PATH=\"${INSTALL_DIR}:\$PATH\"" "${HOME}/.zshrc" "unsafe AGENTENV_HOME should preserve shell PATH export"
    backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "0" "${backup_count}" "unsafe AGENTENV_HOME should not back up rc file"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_root_install_dir_before_shell_cleanup() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="/"
    mkdir -p "${HOME}" "${AGENTENV_HOME}"
    printf '# agentenv installer\nexport PATH="/:$PATH"\n' > "${HOME}/.zshrc"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "unsafe AGENTENV_INSTALL_DIR should fail before shell cleanup"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "unsafe AGENTENV_INSTALL_DIR should report unsafe path"
    assert_contains "# agentenv installer" "${HOME}/.zshrc" "unsafe AGENTENV_INSTALL_DIR should preserve shell sentinel"
    assert_contains 'export PATH="/:$PATH"' "${HOME}/.zshrc" "unsafe AGENTENV_INSTALL_DIR should preserve shell PATH export"
    backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "0" "${backup_count}" "unsafe AGENTENV_INSTALL_DIR should not back up rc file"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_agentenv_bin_relationship_before_shell_cleanup() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    unsafe_bin="${AGENTENV_HOME}/not-bin/agentenv"
    mkdir -p "${INSTALL_DIR}" "$(dirname "${unsafe_bin}")"
    printf '#!/bin/sh\n' > "${unsafe_bin}"
    chmod +x "${unsafe_bin}"
    printf '# agentenv installer\nexport PATH="%s:$PATH"\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" AGENTENV_BIN="${unsafe_bin}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "unsafe AGENTENV_BIN relationship should fail before shell cleanup"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "unsafe AGENTENV_BIN relationship should report unsafe path"
    assert_exists "${unsafe_bin}" "unsafe AGENTENV_BIN relationship should not delete binary"
    assert_contains "# agentenv installer" "${HOME}/.zshrc" "unsafe AGENTENV_BIN relationship should preserve shell sentinel"
    assert_contains "export PATH=\"${INSTALL_DIR}:\$PATH\"" "${HOME}/.zshrc" "unsafe AGENTENV_BIN relationship should preserve shell PATH export"
    backup_count=$(find "${HOME}" -name '.zshrc.agentenv.bak.*' | wc -l | awk '{print $1}')
    assert_eq "0" "${backup_count}" "unsafe AGENTENV_BIN relationship should not back up rc file"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_relative_agentenv_home() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    work_dir="${tmp_root}/work"
    mkdir -p "${work_dir}/agentenv-rel/envs"
    printf 'keep\n' > "${work_dir}/agentenv-rel/envs/keep.txt"

    set +e
    (cd "${work_dir}" && AGENTENV_HOME="agentenv-rel" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1)
    rc=$?
    set -e

    assert_eq "1" "${rc}" "relative AGENTENV_HOME should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "relative AGENTENV_HOME should report unsafe path"
    assert_exists "${work_dir}/agentenv-rel/envs/keep.txt" "relative AGENTENV_HOME should not delete cwd files"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_relative_install_dir() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    work_dir="${tmp_root}/work"
    AGENTENV_HOME="${HOME}/.agentenv"
    mkdir -p "${work_dir}/relative-bin" "${AGENTENV_HOME}"
    printf '#!/bin/sh\n' > "${work_dir}/relative-bin/agentenv"
    chmod +x "${work_dir}/relative-bin/agentenv"

    set +e
    (cd "${work_dir}" && AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="relative-bin" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1)
    rc=$?
    set -e

    assert_eq "1" "${rc}" "relative AGENTENV_INSTALL_DIR should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "relative AGENTENV_INSTALL_DIR should report unsafe path"
    assert_exists "${work_dir}/relative-bin/agentenv" "relative AGENTENV_INSTALL_DIR should not delete cwd files"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_symlink_agentenv_home() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    project_dir="${tmp_root}/project"
    mkdir -p "${HOME}" "${project_dir}/envs"
    printf 'keep\n' > "${project_dir}/envs/keep.txt"
    ln -s "${project_dir}" "${HOME}/.agentenv"

    set +e
    HOME="${HOME}" sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "symlink AGENTENV_HOME should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "symlink AGENTENV_HOME should report unsafe path"
    assert_exists "${project_dir}/envs/keep.txt" "symlink AGENTENV_HOME should not delete project data"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_symlink_ancestor_in_agentenv_home() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    project_dir="${tmp_root}/project"
    mkdir -p "${HOME}" "${project_dir}/.agentenv/envs"
    printf 'keep\n' > "${project_dir}/.agentenv/envs/keep.txt"
    ln -s "${project_dir}" "${HOME}/link"

    set +e
    AGENTENV_HOME="${HOME}/link/.agentenv" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "symlink ancestor in AGENTENV_HOME should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "symlink ancestor in AGENTENV_HOME should report unsafe path"
    assert_exists "${project_dir}/.agentenv/envs/keep.txt" "symlink ancestor in AGENTENV_HOME should not delete project data"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_symlink_home_prefix() {
    tmp_root=$(mktemp -d)

    real_home="${tmp_root}/real-home"
    link_home="${tmp_root}/home-link"
    mkdir -p "${real_home}/.agentenv/envs"
    printf 'keep\n' > "${real_home}/.agentenv/envs/keep.txt"
    ln -s "${real_home}" "${link_home}"

    set +e
    HOME="${link_home}" sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "symlink HOME prefix should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "symlink HOME prefix should report unsafe path"
    assert_exists "${real_home}/.agentenv/envs/keep.txt" "symlink HOME prefix should not delete real home data"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_dry_run_rejects_symlink_home_ancestor_before_plan() {
    tmp_root=$(mktemp -d)

    real_parent="${tmp_root}/real-parent"
    link_parent="${tmp_root}/link-parent"
    HOME="${link_parent}/home"
    mkdir -p "${real_parent}/home/.agentenv/envs"
    printf 'keep\n' > "${real_parent}/home/.agentenv/envs/keep.txt"
    ln -s "${real_parent}" "${link_parent}"

    set +e
    HOME="${HOME}" sh "${REPO_ROOT}/uninstall.sh" --dry-run > "${tmp_root}/dry-run.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "symlink HOME ancestor should make dry-run fail"
    assert_contains "unsafe path" "${tmp_root}/dry-run.out" "symlink HOME ancestor should report unsafe path"
    assert_not_contains "Uninstall plan" "${tmp_root}/dry-run.out" "symlink HOME ancestor should not print dry-run plan"
    assert_exists "${real_parent}/home/.agentenv/envs/keep.txt" "symlink HOME ancestor should not delete real data"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_rejects_dot_path_components() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/."
    mkdir -p "${HOME}/envs"
    printf 'keep\n' > "${HOME}/envs/keep.txt"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "dot component in AGENTENV_HOME should make uninstall fail"
    assert_contains "unsafe path" "${tmp_root}/uninstall.out" "dot component in AGENTENV_HOME should report unsafe path"
    assert_exists "${HOME}/envs/keep.txt" "dot component in AGENTENV_HOME should not delete home envs"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_dry_run_preserves_unconfirmed_shell_sentinel_plan() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf 'before\n# agentenv installer\nafter\n' > "${HOME}/.zshrc"
    printf '# agentenv installer\nexport PATH="/other/bin:$PATH"\n' > "${HOME}/.bashrc"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --dry-run > "${tmp_root}/dry-run.out"

    assert_not_contains "remove installer PATH block" "${tmp_root}/dry-run.out" "dry-run should not plan unconfirmed shell cleanup"
    assert_contains "no installer PATH blocks found" "${tmp_root}/dry-run.out" "dry-run should report no confirmed shell blocks"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_dry_run_rejects_unsafe_roots_before_plan() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '# agentenv installer\nexport PATH="%s:$PATH"\n' "${INSTALL_DIR}" > "${HOME}/.zshrc"

    set +e
    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --dry-run > "${tmp_root}/dry-run.out" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "dry-run with unsafe AGENTENV_HOME should fail"
    assert_contains "unsafe path" "${tmp_root}/dry-run.out" "dry-run with unsafe AGENTENV_HOME should report unsafe path"
    assert_not_contains "Uninstall plan" "${tmp_root}/dry-run.out" "dry-run with unsafe AGENTENV_HOME should not print plan"

    rm -rf "${tmp_root}"
    pass
}

test_uninstall_dry_run_plans_broken_symlink_removal() {
    tmp_root=$(mktemp -d)

    HOME="${tmp_root}/home"
    AGENTENV_HOME="${HOME}/.agentenv"
    INSTALL_DIR="${AGENTENV_HOME}/bin"
    mkdir -p "${INSTALL_DIR}"
    printf '#!/bin/sh\n' > "${INSTALL_DIR}/agentenv"
    chmod +x "${INSTALL_DIR}/agentenv"
    ln -s "${AGENTENV_HOME}/missing-target" "${AGENTENV_HOME}/drivers"

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --dry-run > "${tmp_root}/dry-run.out"

    assert_contains "remove ${AGENTENV_HOME}/drivers" "${tmp_root}/dry-run.out" "dry-run should plan broken symlink removal"
    assert_not_contains "already absent ${AGENTENV_HOME}/drivers" "${tmp_root}/dry-run.out" "dry-run should not treat broken symlink as absent"
    if [ ! -L "${AGENTENV_HOME}/drivers" ]; then
        fail "dry-run should not remove broken symlink"
    fi

    AGENTENV_HOME="${AGENTENV_HOME}" AGENTENV_INSTALL_DIR="${INSTALL_DIR}" HOME="${HOME}" \
        sh "${REPO_ROOT}/uninstall.sh" --yes > "${tmp_root}/uninstall.out"
    assert_not_exists "${AGENTENV_HOME}/drivers" "real uninstall should remove broken symlink"

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
    test_uninstall_attempts_env_destroy_and_writes_diagnostics_on_failure
    test_uninstall_removes_owned_files_and_shell_block
    test_uninstall_keep_flags_preserve_selected_state
    test_uninstall_removes_binary_from_custom_install_dir
    test_uninstall_removes_symlinked_agentenv_binary_only
    test_uninstall_second_run_is_noop
    test_uninstall_preserves_unconfirmed_shell_sentinel_lines
    test_uninstall_removes_only_confirmed_shell_path_block
    test_uninstall_preserves_rc_file_mode
    test_uninstall_rejects_home_as_agentenv_home
    test_uninstall_rejects_agentenv_bin_outside_install_dir
    test_uninstall_rejects_agentenv_bin_under_home_outside_install_dir
    test_uninstall_rejects_parent_directory_components
    test_uninstall_rejects_root_install_dir
    test_uninstall_rejects_home_as_agentenv_home_before_shell_cleanup
    test_uninstall_rejects_root_install_dir_before_shell_cleanup
    test_uninstall_rejects_agentenv_bin_relationship_before_shell_cleanup
    test_uninstall_rejects_relative_agentenv_home
    test_uninstall_rejects_relative_install_dir
    test_uninstall_rejects_symlink_agentenv_home
    test_uninstall_rejects_symlink_ancestor_in_agentenv_home
    test_uninstall_rejects_symlink_home_prefix
    test_uninstall_dry_run_rejects_symlink_home_ancestor_before_plan
    test_uninstall_rejects_dot_path_components
    test_uninstall_dry_run_preserves_unconfirmed_shell_sentinel_plan
    test_uninstall_dry_run_rejects_unsafe_roots_before_plan
    test_uninstall_dry_run_plans_broken_symlink_removal
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
