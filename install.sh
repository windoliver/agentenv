#!/bin/sh

set -eu

APP_NAME="agentenv"
REPO_OWNER="windoliver"
REPO_NAME="agentenv"
REPO_FULL_NAME="${AGENTENV_REPO:-${REPO_OWNER}/${REPO_NAME}}"
INSTALLER_SENTINEL="# agentenv installer"

: "${HOME:?HOME must be set}"

STEP_INDEX=0
NON_INTERACTIVE=0
INSTALL_MODE="full"
WITH_PYTHON_DRIVERS="auto"
INSTALL_DIR="${AGENTENV_INSTALL_DIR:-$HOME/.agentenv/bin}"
AGENTENV_HOME="${AGENTENV_HOME:-$HOME/.agentenv}"
RELEASES_API_URL="${AGENTENV_RELEASES_API_URL:-https://api.github.com/repos/${REPO_FULL_NAME}/releases/latest}"
RELEASE_BASE_URL="${AGENTENV_RELEASE_BASE_URL:-https://github.com/${REPO_FULL_NAME}/releases/download}"
PYTHON_DRIVERS_INDEX_URL="${AGENTENV_PYTHON_DRIVERS_INDEX_URL:-}"
RESOLVED_VERSION=""
RESOLVED_VERSION_NOPREFIX=""
TARGET_TRIPLE=""
DOWNLOADED_ARCHIVE_BASENAME=""
TMP_ROOT=""
COLOR_ENABLED=0
SPINNER_ENABLED=0
PATH_STATUS="unchanged"
PYTHON_DRIVER_STATUS="not requested"

usage() {
    cat <<EOF
Usage: install.sh [options]

Installs ${APP_NAME} from GitHub Releases into ${INSTALL_DIR} by default.

Options:
  --non-interactive        Do not prompt; use the default path setup behavior.
  --binary-only            Install only the ${APP_NAME} binary.
  --with-python-drivers    Install external Python drivers if a driver index is available.
  --without-python-drivers Skip external Python drivers.
  --install-dir DIR        Override the destination directory for the ${APP_NAME} binary.
  -h, --help               Show this help text.

Environment:
  AGENTENV_VERSION                 Install a specific tag, for example v0.1.0.
  AGENTENV_TARGET                  Override auto-detected target triple.
  AGENTENV_INSTALL_DIR             Destination for the ${APP_NAME} binary.
  AGENTENV_HOME                    Root directory for agentenv state (default: ~/.agentenv).
  AGENTENV_RELEASES_API_URL        Override the GitHub Releases API endpoint.
  AGENTENV_RELEASE_BASE_URL        Override the GitHub release asset base URL.
  AGENTENV_PYTHON_DRIVERS_INDEX_URL
                                   Optional newline-delimited driver index:
                                   name|archive_url|sha256
  AGENTENV_NO_COLOR, NO_COLOR      Disable ANSI colors.
EOF
}

cleanup() {
    if [ -n "${TMP_ROOT}" ] && [ -d "${TMP_ROOT}" ]; then
        rm -rf "${TMP_ROOT}"
    fi
}

trap cleanup EXIT INT TERM

enable_colors() {
    if [ -n "${AGENTENV_NO_COLOR:-}" ] || [ -n "${NO_COLOR:-}" ]; then
        COLOR_ENABLED=0
    elif [ -t 1 ]; then
        COLOR_ENABLED=1
    else
        COLOR_ENABLED=0
    fi

    if [ -t 1 ] && [ "${NON_INTERACTIVE}" -eq 0 ]; then
        SPINNER_ENABLED=1
    else
        SPINNER_ENABLED=0
    fi
}

color_wrap() {
    color_code=$1
    shift
    if [ "${COLOR_ENABLED}" -eq 1 ]; then
        printf '\033[%sm%s\033[0m' "${color_code}" "$*"
    else
        printf '%s' "$*"
    fi
}

log_info() {
    printf '%s\n' "$*"
}

log_warn() {
    printf '%s %s\n' "$(color_wrap '33' 'WARN')" "$*" >&2
}

die() {
    printf '%s %s\n' "$(color_wrap '31' 'ERROR')" "$*" >&2
    exit 1
}

start_step() {
    STEP_INDEX=$((STEP_INDEX + 1))
    printf '%s %s\n' "$(color_wrap '36' "${STEP_INDEX}.")" "$1"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --non-interactive)
                NON_INTERACTIVE=1
                ;;
            --binary-only)
                INSTALL_MODE="binary-only"
                ;;
            --with-python-drivers)
                WITH_PYTHON_DRIVERS="1"
                ;;
            --without-python-drivers)
                WITH_PYTHON_DRIVERS="0"
                ;;
            --install-dir)
                shift
                [ "$#" -gt 0 ] || die "--install-dir requires a value"
                INSTALL_DIR=$1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
        shift
    done

    if [ "${WITH_PYTHON_DRIVERS}" = "auto" ]; then
        if [ "${INSTALL_MODE}" = "binary-only" ]; then
            WITH_PYTHON_DRIVERS="0"
        else
            WITH_PYTHON_DRIVERS="1"
        fi
    fi
}

normalize_version_tag() {
    version=$1
    version=${version#refs/tags/}
    printf '%s' "${version}"
}

try_download() {
    url=$1
    dest=$2

    if command -v curl >/dev/null 2>&1; then
        curl -fLsS "$url" -o "$dest"
        return $?
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
        return $?
    fi

    return 127
}

spinner_wait() {
    pid=$1
    label=$2

    frame_index=0
    while kill -0 "${pid}" 2>/dev/null; do
        case "${frame_index}" in
            0) frame='-' ;;
            1) frame='\\' ;;
            2) frame='|' ;;
            *) frame='/' ;;
        esac
        printf '\r%s %s' "${frame}" "${label}"
        sleep 0.1
        frame_index=$((frame_index + 1))
        if [ "${frame_index}" -ge 4 ]; then
            frame_index=0
        fi
    done

    wait "${pid}"
    rc=$?
    if [ "${rc}" -eq 0 ]; then
        printf '\r%s %s\n' "$(color_wrap '32' 'OK')" "${label}"
    else
        printf '\r%s %s\n' "$(color_wrap '31' 'ERR')" "${label}"
    fi
    return "${rc}"
}

download_with_feedback() {
    label=$1
    url=$2
    dest=$3
    log_file=$4

    if [ "${SPINNER_ENABLED}" -eq 1 ]; then
        (
            try_download "${url}" "${dest}"
        ) >"${log_file}" 2>&1 &
        pid=$!
        if ! spinner_wait "${pid}" "${label}"; then
            cat "${log_file}" >&2
            return 1
        fi
        return 0
    fi

    printf '%s\n' "${label}"
    if ! try_download "${url}" "${dest}" >"${log_file}" 2>&1; then
        cat "${log_file}" >&2
        return 1
    fi
}

detect_linux_libc() {
    if command -v ldd >/dev/null 2>&1; then
        ldd_output=$(ldd --version 2>&1 || true)
        lower_output=$(printf '%s' "${ldd_output}" | tr '[:upper:]' '[:lower:]')
        case "${lower_output}" in
            *musl*)
                printf '%s' "musl"
                return 0
                ;;
            *glibc*|*gnu*|*gnu/libc*)
                printf '%s' "gnu"
                return 0
                ;;
        esac
    fi

    if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1 || ls /usr/glibc-compat/lib/ld-musl-*.so.1 >/dev/null 2>&1; then
        printf '%s' "musl"
        return 0
    fi

    printf '%s' "gnu"
}

detect_target_triple() {
    if [ -n "${AGENTENV_TARGET:-}" ]; then
        TARGET_TRIPLE=${AGENTENV_TARGET}
        return 0
    fi

    os_name=$(uname -s)
    arch_name=$(uname -m)

    case "${arch_name}" in
        x86_64|amd64)
            rust_arch="x86_64"
            ;;
        arm64|aarch64)
            rust_arch="aarch64"
            ;;
        *)
            die "Unsupported CPU architecture: ${arch_name}"
            ;;
    esac

    case "${os_name}" in
        Darwin)
            TARGET_TRIPLE="${rust_arch}-apple-darwin"
            ;;
        Linux)
            libc=$(detect_linux_libc)
            TARGET_TRIPLE="${rust_arch}-unknown-linux-${libc}"
            ;;
        *)
            die "Unsupported operating system: ${os_name}"
            ;;
    esac
}

resolve_version() {
    requested_version=${AGENTENV_VERSION:-}
    if [ -n "${requested_version}" ] && [ "${requested_version}" != "latest" ]; then
        RESOLVED_VERSION=$(normalize_version_tag "${requested_version}")
    else
        version_json="${TMP_ROOT}/latest-release.json"
        download_with_feedback "Resolving latest stable release" "${RELEASES_API_URL}" "${version_json}" "${TMP_ROOT}/latest-release.log" || \
            die "Could not determine the latest stable release from ${RELEASES_API_URL}"
        RESOLVED_VERSION=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${version_json}" | head -n 1)
    fi

    [ -n "${RESOLVED_VERSION}" ] || die "Could not resolve an agentenv release version"
    RESOLVED_VERSION_NOPREFIX=${RESOLVED_VERSION#v}
}

archive_name_candidates() {
    # Support both legacy versioned archives and cargo-dist naming.
    for extension in tar.gz tar.xz; do
        printf '%s\n' "${APP_NAME}-${RESOLVED_VERSION_NOPREFIX}-${TARGET_TRIPLE}.${extension}"
        if [ "${RESOLVED_VERSION}" != "${RESOLVED_VERSION_NOPREFIX}" ]; then
            printf '%s\n' "${APP_NAME}-${RESOLVED_VERSION}-${TARGET_TRIPLE}.${extension}"
        fi
        printf '%s\n' "${APP_NAME}-${TARGET_TRIPLE}.${extension}"
    done
}

download_release_bundle() {
    archive_dest="${TMP_ROOT}/release-archive"
    checksum_dest="${TMP_ROOT}/release-archive.sha256"
    archive_log="${TMP_ROOT}/release-download.log"
    checksum_log="${TMP_ROOT}/checksum-download.log"

    for archive_basename in $(archive_name_candidates); do
        archive_url="${RELEASE_BASE_URL}/${RESOLVED_VERSION}/${archive_basename}"
        checksum_url="${archive_url}.sha256"

        if download_with_feedback "Downloading ${archive_basename}" "${archive_url}" "${archive_dest}" "${archive_log}"; then
            if download_with_feedback "Downloading ${archive_basename}.sha256" "${checksum_url}" "${checksum_dest}" "${checksum_log}"; then
                DOWNLOADED_ARCHIVE_BASENAME=${archive_basename}
                return 0
            fi
        fi
    done

    die "Could not download a release archive for ${TARGET_TRIPLE} at tag ${RESOLVED_VERSION}"
}

sha256_file() {
    file_path=$1

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file_path}" | awk '{print $1}'
        return 0
    fi

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${file_path}" | awk '{print $1}'
        return 0
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "${file_path}" | sed 's/^.*= //'
        return 0
    fi

    die "No SHA256 tool found. Install sha256sum, shasum, or openssl and retry."
}

verify_sha256_value() {
    file_path=$1
    expected_hash=$2
    actual_hash=$(sha256_file "${file_path}")

    if [ "${actual_hash}" != "${expected_hash}" ]; then
        die "Checksum verification failed for $(basename "${file_path}")"
    fi
}

verify_download_checksum() {
    archive_dest="${TMP_ROOT}/release-archive"
    checksum_dest="${TMP_ROOT}/release-archive.sha256"
    expected_hash=$(awk 'NR == 1 { print $1 }' "${checksum_dest}")

    [ -n "${expected_hash}" ] || die "Downloaded checksum file is empty"
    verify_sha256_value "${archive_dest}" "${expected_hash}"
}

extract_release_archive() {
    archive_dest=$1
    extract_dir=$2

    case "${DOWNLOADED_ARCHIVE_BASENAME}" in
        *.tar.gz)
            tar -xzf "${archive_dest}" -C "${extract_dir}" || die "Could not extract ${DOWNLOADED_ARCHIVE_BASENAME}"
            ;;
        *.tar.xz)
            if ! tar -xJf "${archive_dest}" -C "${extract_dir}" 2>/dev/null; then
                tar -xf "${archive_dest}" -C "${extract_dir}" || die "Could not extract ${DOWNLOADED_ARCHIVE_BASENAME}"
            fi
            ;;
        *)
            tar -xf "${archive_dest}" -C "${extract_dir}" || die "Could not extract ${DOWNLOADED_ARCHIVE_BASENAME}"
            ;;
    esac
}

install_binary() {
    archive_dest="${TMP_ROOT}/release-archive"
    extract_dir="${TMP_ROOT}/extract"
    mkdir -p "${extract_dir}"
    extract_release_archive "${archive_dest}" "${extract_dir}"

    binary_path=$(find "${extract_dir}" -type f -name "${APP_NAME}" | head -n 1 || true)
    [ -n "${binary_path}" ] || die "Release archive ${DOWNLOADED_ARCHIVE_BASENAME} does not contain ${APP_NAME}"

    mkdir -p "${INSTALL_DIR}"
    destination="${INSTALL_DIR}/${APP_NAME}"

    if command -v install >/dev/null 2>&1; then
        install -m 0755 "${binary_path}" "${destination}"
    else
        cp "${binary_path}" "${destination}"
        chmod 0755 "${destination}"
    fi
}

confirm() {
    prompt=$1
    default_answer=$2

    if [ "${NON_INTERACTIVE}" -eq 1 ] || [ ! -r /dev/tty ]; then
        [ "${default_answer}" = "yes" ]
        return $?
    fi

    if [ "${default_answer}" = "yes" ]; then
        suffix="[Y/n]"
    else
        suffix="[y/N]"
    fi

    while true; do
        printf '%s %s ' "${prompt}" "${suffix}" > /dev/tty
        IFS= read -r answer < /dev/tty || return 1
        case "${answer}" in
            "")
                [ "${default_answer}" = "yes" ]
                return $?
                ;;
            y|Y|yes|YES)
                return 0
                ;;
            n|N|no|NO)
                return 1
                ;;
        esac
    done
}

path_contains_dir() {
    check_dir=$1
    old_ifs=$IFS
    IFS=:
    for entry in ${PATH}; do
        if [ "${entry}" = "${check_dir}" ]; then
            IFS=${old_ifs}
            return 0
        fi
    done
    IFS=${old_ifs}
    return 1
}

shell_path_already_configured() {
    choose_rc_targets
    old_ifs=$IFS
    IFS='
'
    for rc_file in ${RC_TARGETS}; do
        [ -f "${rc_file}" ] || continue

        if grep -F "${INSTALLER_SENTINEL}" "${rc_file}" >/dev/null 2>&1; then
            IFS=${old_ifs}
            return 0
        fi

        if grep -F "${INSTALL_DIR}" "${rc_file}" >/dev/null 2>&1; then
            IFS=${old_ifs}
            return 0
        fi
    done
    IFS=${old_ifs}
    return 1
}

backup_file() {
    file_path=$1
    [ -f "${file_path}" ] || return 0
    timestamp=$(date -u '+%Y%m%d%H%M%S')
    cp "${file_path}" "${file_path}.agentenv.bak.${timestamp}"
}

choose_rc_targets() {
    RC_TARGETS=""
    for candidate in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [ -f "${candidate}" ]; then
            RC_TARGETS="${RC_TARGETS}${candidate}
"
        fi
    done

    if [ -z "${RC_TARGETS}" ]; then
        RC_TARGETS="$HOME/.profile
"
    fi
}

write_path_exports() {
    choose_rc_targets
    UPDATED_RC_FILES=""
    old_ifs=$IFS
    IFS='
'
    for rc_file in ${RC_TARGETS}; do
        [ -n "${rc_file}" ] || continue

        if [ -f "${rc_file}" ] && grep -F "${INSTALLER_SENTINEL}" "${rc_file}" >/dev/null 2>&1; then
            continue
        fi

        if [ -f "${rc_file}" ] && grep -F "${INSTALL_DIR}" "${rc_file}" >/dev/null 2>&1; then
            continue
        fi

        if [ -f "${rc_file}" ]; then
            backup_file "${rc_file}"
        else
            mkdir -p "$(dirname "${rc_file}")"
            : > "${rc_file}"
        fi

        tmp_file="${TMP_ROOT}/$(basename "${rc_file}").tmp"
        cat "${rc_file}" > "${tmp_file}"
        if [ -s "${tmp_file}" ]; then
            printf '\n' >> "${tmp_file}"
        fi
        printf '%s\n' "${INSTALLER_SENTINEL}" >> "${tmp_file}"
        printf 'export PATH="%s:$PATH"\n' "${INSTALL_DIR}" >> "${tmp_file}"
        mv "${tmp_file}" "${rc_file}"
        UPDATED_RC_FILES="${UPDATED_RC_FILES}${rc_file} "
    done
    IFS=${old_ifs}

    if [ -n "${UPDATED_RC_FILES}" ]; then
        PATH_STATUS="updated ${UPDATED_RC_FILES}"
    else
        PATH_STATUS="already configured"
    fi
}

configure_shell_path() {
    path_in_current_shell=0
    if path_contains_dir "${INSTALL_DIR}"; then
        path_in_current_shell=1
    fi

    if shell_path_already_configured; then
        if [ "${path_in_current_shell}" -eq 1 ]; then
            PATH_STATUS="already on PATH"
        else
            PATH_STATUS="already configured"
        fi
        return 0
    fi

    if confirm "Add ${INSTALL_DIR} to your shell startup files?" "yes"; then
        write_path_exports
        return 0
    fi

    if [ "${path_in_current_shell}" -eq 1 ]; then
        PATH_STATUS="skipped (startup files unchanged; install dir is only in the current shell)"
    else
        PATH_STATUS="skipped (install dir is not on PATH)"
    fi
}

replace_driver_dir() {
    staged_dir=$1
    driver_dir=$2

    backup_dir="${driver_dir}.backup.$$"
    rm -rf "${backup_dir}"

    if [ -e "${driver_dir}" ]; then
        mv "${driver_dir}" "${backup_dir}" || die "Could not back up the existing driver at ${driver_dir}"
    fi

    if mv "${staged_dir}" "${driver_dir}"; then
        rm -rf "${backup_dir}"
        return 0
    fi

    rm -rf "${driver_dir}"
    if [ -e "${backup_dir}" ]; then
        mv "${backup_dir}" "${driver_dir}" || die "Could not restore the previous driver at ${driver_dir}"
    fi
    die "Could not install the updated driver at ${driver_dir}"
}

install_python_drivers() {
    if [ "${WITH_PYTHON_DRIVERS}" != "1" ]; then
        PYTHON_DRIVER_STATUS="skipped"
        return 0
    fi

    if [ -z "${PYTHON_DRIVERS_INDEX_URL}" ]; then
        PYTHON_DRIVER_STATUS="skipped (no driver index published yet)"
        log_warn "Skipping Python drivers: set AGENTENV_PYTHON_DRIVERS_INDEX_URL to a newline-delimited index once bundles exist."
        return 0
    fi

    if ! command -v tar >/dev/null 2>&1; then
        die "tar is required to install Python driver bundles"
    fi

    index_path="${TMP_ROOT}/python-drivers.index"
    download_with_feedback "Downloading Python driver index" "${PYTHON_DRIVERS_INDEX_URL}" "${index_path}" "${TMP_ROOT}/python-drivers-index.log" || \
        die "Could not download the Python driver index from ${PYTHON_DRIVERS_INDEX_URL}"

    mkdir -p "${AGENTENV_HOME}/drivers"
    installed_count=0

    while IFS='|' read -r driver_name archive_url expected_hash; do
        [ -n "${driver_name}" ] || continue
        [ -n "${archive_url}" ] || die "Python driver index entry for ${driver_name} is missing an archive URL"
        [ -n "${expected_hash}" ] || die "Python driver index entry for ${driver_name} is missing a SHA256 hash"

        archive_path="${TMP_ROOT}/${driver_name}.tar.gz"
        archive_log="${TMP_ROOT}/${driver_name}.download.log"
        download_with_feedback "Downloading Python driver ${driver_name}" "${archive_url}" "${archive_path}" "${archive_log}" || \
            die "Could not download Python driver bundle for ${driver_name}"
        verify_sha256_value "${archive_path}" "${expected_hash}"

        driver_dir="${AGENTENV_HOME}/drivers/${driver_name}"
        staged_driver_dir="${TMP_ROOT}/${driver_name}.staged"
        rm -rf "${staged_driver_dir}"
        mkdir -p "${staged_driver_dir}"
        tar -xzf "${archive_path}" -C "${staged_driver_dir}" || die "Could not extract Python driver bundle for ${driver_name}"
        [ -f "${staged_driver_dir}/manifest.json" ] || die "Python driver ${driver_name} did not contain manifest.json"
        replace_driver_dir "${staged_driver_dir}" "${driver_dir}"
        installed_count=$((installed_count + 1))
    done < "${index_path}"

    PYTHON_DRIVER_STATUS="installed ${installed_count} bundle(s)"
}

print_summary() {
    printf '\n'
    log_info "$(color_wrap '32' 'Installed') ${APP_NAME} ${RESOLVED_VERSION} for ${TARGET_TRIPLE}"
    log_info "Binary: ${INSTALL_DIR}/${APP_NAME}"
    log_info "PATH: ${PATH_STATUS}"
    log_info "Python drivers: ${PYTHON_DRIVER_STATUS}"
    printf '\n'
    log_info "Next:"
    log_info "  ${INSTALL_DIR}/${APP_NAME} --version"
    log_info "  exec ${SHELL:-/bin/sh} -l"
}

main() {
    parse_args "$@"
    enable_colors

    TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/${APP_NAME}-install.XXXXXX")

    start_step "Detecting platform"
    detect_target_triple
    log_info "   target: ${TARGET_TRIPLE}"

    start_step "Resolving release version"
    resolve_version
    log_info "   version: ${RESOLVED_VERSION}"

    start_step "Downloading release artifacts"
    download_release_bundle

    start_step "Verifying SHA256"
    verify_download_checksum

    start_step "Installing ${APP_NAME}"
    install_binary

    start_step "Installing Python drivers"
    install_python_drivers

    start_step "Configuring shell PATH"
    configure_shell_path

    print_summary
}

if [ "${AGENTENV_INSTALLER_SOURCE_ONLY:-0}" != "1" ]; then
    main "$@"
fi
