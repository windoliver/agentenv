#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)

AGENTENV_INSTALLER_SOURCE_ONLY=1 . "${REPO_ROOT}/install.sh"

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
    test_write_path_exports_is_idempotent
    test_configure_shell_path_persists_when_current_shell_has_path
    test_install_python_drivers_preserves_existing_driver_on_extract_failure
    test_choose_rc_targets_creates_profile_when_missing
    printf 'PASS: %s installer tests\n' "${TEST_COUNT}"
}

main "$@"
