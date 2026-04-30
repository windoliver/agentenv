#!/bin/sh

set -eu

APP_NAME="agentenv"
REPO_OWNER="windoliver"
REPO_NAME="agentenv"
REPO_FULL_NAME="${AGENTENV_REPO:-${REPO_OWNER}/${REPO_NAME}}"
INSTALLER_SENTINEL="# agentenv installer"

: "${HOME:?HOME must be set}"

YES=0
DRY_RUN=0
KEEP_OPENSHELL=0
KEEP_DRIVERS=0
KEEP_CREDENTIALS=0
KEEP_DATA=0
DELETE_MODELS=0
INSTALL_DIR="${AGENTENV_INSTALL_DIR:-$HOME/.agentenv/bin}"
AGENTENV_HOME="${AGENTENV_HOME:-$HOME/.agentenv}"
AGENTENV_BIN="${AGENTENV_BIN:-$INSTALL_DIR/$APP_NAME}"
TMP_ROOT=""
PLAN_FILE=""
ACTIONS_LOG=""
ERRORS_LOG=""
FAILURE_COUNT=0

usage() {
    cat <<EOF
Usage: uninstall.sh [options]

Removes ${APP_NAME} user-level files and shell PATH entries.

Options:
  -y, --yes              Skip confirmation.
  --keep-openshell       Preserve OpenShell binary and state. This is the default.
  --keep-drivers         Preserve subprocess drivers under ~/.agentenv/drivers.
  --keep-credentials     Preserve credentials.json.
  --keep-data            Preserve env registry data under ~/.agentenv/envs.
  --delete-models        Remove agentenv-owned local model cache under ~/.agentenv/models.
  --dry-run              Print the plan without deleting anything.
  -h, --help             Show this help text.
EOF
}

log_action() {
    printf '%s\n' "$*" >> "${ACTIONS_LOG}"
    printf '%s\n' "$*"
}

record_error() {
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
    printf '%s\n' "$*" >> "${ERRORS_LOG}"
}

parse_uninstall_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -y|--yes)
                YES=1
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --keep-openshell)
                KEEP_OPENSHELL=1
                ;;
            --keep-drivers)
                KEEP_DRIVERS=1
                ;;
            --keep-credentials)
                KEEP_CREDENTIALS=1
                ;;
            --keep-data)
                KEEP_DATA=1
                ;;
            --delete-models)
                DELETE_MODELS=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                printf 'ERROR unknown option: %s\n' "$1" >&2
                exit 2
                ;;
        esac
        shift
    done
}

path_size_kib() {
    path=$1
    if [ ! -e "${path}" ] && [ ! -L "${path}" ]; then
        printf '0'
        return 0
    fi
    du -sk "${path}" 2>/dev/null | awk '{print $1}' || printf '0'
}

plan_remove_path() {
    path=$1
    if [ -e "${path}" ] || [ -L "${path}" ]; then
        size=$(path_size_kib "${path}")
        printf '  remove %s (%s KiB)\n' "${path}" "${size}" >> "${PLAN_FILE}"
    else
        printf '  already absent %s\n' "${path}" >> "${PLAN_FILE}"
    fi
}

plan_preserve_path() {
    path=$1
    reason=$2
    printf '  preserve %s (%s)\n' "${path}" "${reason}" >> "${PLAN_FILE}"
}

append_shell_plan() {
    found=0
    for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [ -f "${rc_file}" ] && has_installer_block "${rc_file}"; then
            printf '  remove installer PATH block from %s (backup first)\n' "${rc_file}" >> "${PLAN_FILE}"
            found=1
        fi
    done
    if [ "${found}" -eq 0 ]; then
        printf '  no installer PATH blocks found\n' >> "${PLAN_FILE}"
    fi
}

build_uninstall_plan() {
    : > "${PLAN_FILE}"
    printf 'Uninstall plan\n' >> "${PLAN_FILE}"
    printf '\nRemove:\n' >> "${PLAN_FILE}"
    plan_remove_path "${AGENTENV_BIN}"
    if [ "${KEEP_DATA}" -eq 0 ]; then
        plan_remove_path "${AGENTENV_HOME}/envs"
    fi
    if [ "${KEEP_DRIVERS}" -eq 0 ]; then
        plan_remove_path "${AGENTENV_HOME}/drivers"
    fi
    if [ "${KEEP_CREDENTIALS}" -eq 0 ]; then
        plan_remove_path "${AGENTENV_HOME}/credentials.json"
    fi
    plan_remove_path "${AGENTENV_HOME}/events.db"
    plan_remove_path "${AGENTENV_HOME}/audit.key"
    plan_remove_path "${AGENTENV_HOME}/audit-signing-key"
    if [ "${DELETE_MODELS}" -eq 1 ]; then
        plan_remove_path "${AGENTENV_HOME}/models"
    fi
    printf '\nShell startup files:\n' >> "${PLAN_FILE}"
    append_shell_plan
    printf '\nPreserve:\n' >> "${PLAN_FILE}"
    plan_preserve_path "openshell" "not owned by agentenv"
    if [ "${KEEP_DATA}" -eq 1 ]; then
        plan_preserve_path "${AGENTENV_HOME}/envs" "--keep-data"
    fi
    if [ "${KEEP_DRIVERS}" -eq 1 ]; then
        plan_preserve_path "${AGENTENV_HOME}/drivers" "--keep-drivers"
    fi
    if [ "${KEEP_CREDENTIALS}" -eq 1 ]; then
        plan_preserve_path "${AGENTENV_HOME}/credentials.json" "--keep-credentials"
    fi
}

confirm_uninstall() {
    if [ "${YES}" -eq 1 ]; then
        return 0
    fi
    if [ ! -r /dev/tty ]; then
        printf 'ERROR confirmation required; rerun with --yes to uninstall non-interactively\n' >&2
        return 1
    fi
    printf 'Proceed with agentenv uninstall? [y/N] ' > /dev/tty
    IFS= read -r answer < /dev/tty || return 1
    case "${answer}" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

backup_uninstall_file() {
    file_path=$1
    [ -f "${file_path}" ] || return 0
    timestamp=$(date -u '+%Y%m%d%H%M%S')
    backup_path="${file_path}.agentenv.bak.${timestamp}"
    if cp "${file_path}" "${backup_path}"; then
        log_action "backed up ${file_path} to ${backup_path}"
    else
        record_error "failed to back up ${file_path}"
        return 1
    fi
}

installer_path_export_line() {
    printf 'export PATH="%s:$PATH"' "${INSTALL_DIR}"
}

has_installer_block() {
    rc_file=$1
    expected_export=$(installer_path_export_line)
    awk -v sentinel="${INSTALLER_SENTINEL}" -v expected_export="${expected_export}" '
        pending == 1 {
            if ($0 == expected_export) {
                found = 1
            }
            pending = 0
        }
        $0 == sentinel {
            pending = 1
            next
        }
        END {
            exit found ? 0 : 1
        }
    ' "${rc_file}"
}

remove_installer_block() {
    rc_file=$1
    [ -f "${rc_file}" ] || return 0
    if ! grep -F "${INSTALLER_SENTINEL}" "${rc_file}" >/dev/null 2>&1; then
        return 0
    fi
    if ! has_installer_block "${rc_file}"; then
        return 0
    fi

    backup_uninstall_file "${rc_file}" || return 1
    tmp_file="${TMP_ROOT}/$(basename "${rc_file}").uninstall.$$"
    expected_export=$(installer_path_export_line)
    awk -v sentinel="${INSTALLER_SENTINEL}" -v expected_export="${expected_export}" '
        pending == 1 {
            if ($0 == expected_export) {
                pending = 0
                next
            }
            print sentinel
            pending = 0
        }
        $0 == sentinel {
            pending = 1
            next
        }
        { print }
        END {
            if (pending == 1) {
                print sentinel
            }
        }
    ' "${rc_file}" > "${tmp_file}" || {
        record_error "failed to rewrite ${rc_file}"
        rm -f "${tmp_file}"
        return 1
    }

    if mv "${tmp_file}" "${rc_file}"; then
        log_action "removed installer PATH block from ${rc_file}"
    else
        record_error "failed to update ${rc_file}"
        rm -f "${tmp_file}"
        return 1
    fi
}

path_is_under_dir() {
    child_path=$1
    parent_dir=$2
    case "${child_path}" in
        "${parent_dir}"/*) return 0 ;;
        *) return 1 ;;
    esac
}

path_is_agentenv_bin() {
    agentenv_bin_path=$1
    [ "${agentenv_bin_path}" = "${AGENTENV_BIN}" ] || return 1
    [ "${agentenv_bin_path}" = "${INSTALL_DIR}/${APP_NAME}" ] || return 1
    path_is_under_dir "${agentenv_bin_path}" "${INSTALL_DIR}"
}

path_has_parent_component() {
    component_path=$1
    case "${component_path}" in
        ".."|../*|*/..|*/../*) return 0 ;;
        *) return 1 ;;
    esac
}

path_has_current_component() {
    component_path=$1
    case "${component_path}" in
        "."|./*|*/.|*/./*) return 0 ;;
        *) return 1 ;;
    esac
}

path_has_symlink_component() {
    checked_path=$1
    current_path=""
    old_ifs=$IFS
    IFS=/
    for component in ${checked_path}; do
        [ -n "${component}" ] || continue
        current_path="${current_path}/${component}"
        if [ -L "${current_path}" ]; then
            IFS=${old_ifs}
            return 0
        fi
    done
    IFS=${old_ifs}
    return 1
}

validate_configured_path() {
    label=$1
    configured_path=$2
    case "${configured_path}" in
        ""|"/"|".")
            record_error "unsafe path ${configured_path}: ${label} is unsafe (${configured_path})"
            return 1
            ;;
    esac
    case "${configured_path}" in
        /*)
            ;;
        *)
            record_error "unsafe path ${configured_path}: ${label} must be absolute"
            return 1
            ;;
    esac
    if [ "${configured_path}" = "${HOME}" ]; then
        record_error "unsafe path ${configured_path}: ${label} must not be HOME"
        return 1
    fi
    if path_has_parent_component "${configured_path}"; then
        record_error "unsafe path ${configured_path}: ${label} contains parent directory component"
        return 1
    fi
    if path_has_current_component "${configured_path}"; then
        record_error "unsafe path ${configured_path}: ${label} contains current directory component"
        return 1
    fi
    if [ -L "${configured_path}" ]; then
        record_error "unsafe path ${configured_path}: ${label} must not be a symlink"
        return 1
    fi
    if path_has_symlink_component "${configured_path}"; then
        record_error "unsafe path ${configured_path}: ${label} must not contain symlink components"
        return 1
    fi
    return 0
}

validate_configured_roots() {
    validate_configured_path "AGENTENV_HOME" "${AGENTENV_HOME}" || return 1
    validate_configured_path "AGENTENV_INSTALL_DIR" "${INSTALL_DIR}" || return 1
    validate_configured_path "AGENTENV_BIN" "${AGENTENV_BIN}" || return 1
    if ! path_is_agentenv_bin "${AGENTENV_BIN}"; then
        record_error "unsafe path ${AGENTENV_BIN}: AGENTENV_BIN must be under ${INSTALL_DIR}"
        return 1
    fi
    return 0
}

validate_remove_path() {
    path=$1
    validate_configured_roots || return 1

    case "${path}" in
        ""|"/"|".")
            record_error "unsafe path ${path}"
            return 1
            ;;
    esac
    if path_has_parent_component "${path}"; then
        record_error "unsafe path ${path}: contains parent directory component"
        return 1
    fi
    if path_has_current_component "${path}"; then
        record_error "unsafe path ${path}: contains current directory component"
        return 1
    fi
    if [ "${path}" = "${HOME}" ]; then
        record_error "unsafe path ${path}: refusing to remove HOME"
        return 1
    fi

    if [ "${path}" = "${AGENTENV_HOME}" ]; then
        return 0
    fi
    if [ "${path}" = "${INSTALL_DIR}" ]; then
        return 0
    fi
    if [ "${path}" = "${AGENTENV_BIN}" ]; then
        if path_is_agentenv_bin "${path}"; then
            return 0
        fi
        record_error "unsafe path ${path}: AGENTENV_BIN must be under ${INSTALL_DIR}"
        return 1
    fi
    if path_is_under_dir "${path}" "${AGENTENV_HOME}"; then
        return 0
    fi

    record_error "unsafe path ${path}: outside ${AGENTENV_HOME}"
    return 1
}

remove_path_if_present() {
    path=$1
    if ! validate_remove_path "${path}"; then
        return 1
    fi
    if [ ! -e "${path}" ] && [ ! -L "${path}" ]; then
        log_action "already absent ${path}"
        return 0
    fi

    if rm -rf "${path}"; then
        log_action "removed ${path}"
    else
        record_error "failed to remove ${path}"
        return 1
    fi
}

remove_empty_dir_if_safe() {
    directory=$1
    if ! validate_remove_path "${directory}"; then
        return 1
    fi
    if [ -d "${directory}" ]; then
        if rmdir "${directory}" 2>/dev/null; then
            log_action "removed empty directory ${directory}"
        fi
    fi
}

remove_shell_path_blocks() {
    for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        remove_installer_block "${rc_file}" || true
    done
}

remove_selected_paths() {
    remove_path_if_present "${AGENTENV_BIN}" || true
    if [ "${KEEP_DATA}" -eq 0 ]; then
        remove_path_if_present "${AGENTENV_HOME}/envs" || true
    fi
    if [ "${KEEP_DRIVERS}" -eq 0 ]; then
        remove_path_if_present "${AGENTENV_HOME}/drivers" || true
    fi
    if [ "${KEEP_CREDENTIALS}" -eq 0 ]; then
        remove_path_if_present "${AGENTENV_HOME}/credentials.json" || true
    fi
    remove_path_if_present "${AGENTENV_HOME}/events.db" || true
    remove_path_if_present "${AGENTENV_HOME}/audit.key" || true
    remove_path_if_present "${AGENTENV_HOME}/audit-signing-key" || true
    if [ "${DELETE_MODELS}" -eq 1 ]; then
        remove_path_if_present "${AGENTENV_HOME}/models" || true
    fi

    if path_is_under_dir "${INSTALL_DIR}" "${AGENTENV_HOME}"; then
        remove_empty_dir_if_safe "${INSTALL_DIR}" || true
    fi
    remove_empty_dir_if_safe "${AGENTENV_HOME}" || true
}

execute_uninstall() {
    validate_configured_roots || return 1
    remove_shell_path_blocks
    remove_selected_paths
}

cleanup_uninstall_tmp() {
    if [ -n "${TMP_ROOT}" ] && [ -d "${TMP_ROOT}" ] && [ "${FAILURE_COUNT}" -eq 0 ]; then
        rm -rf "${TMP_ROOT}"
    fi
}

report_uninstall_failures() {
    cat "${ERRORS_LOG}" >&2
    printf 'Uninstall completed with %s failure(s). Diagnostics: %s\n' "${FAILURE_COUNT}" "${TMP_ROOT}" >&2
}

main() {
    parse_uninstall_args "$@"
    TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/${APP_NAME}-uninstall.XXXXXX")
    PLAN_FILE="${TMP_ROOT}/plan.txt"
    ACTIONS_LOG="${TMP_ROOT}/actions.log"
    ERRORS_LOG="${TMP_ROOT}/errors.log"
    : > "${ACTIONS_LOG}"
    : > "${ERRORS_LOG}"
    trap cleanup_uninstall_tmp EXIT INT TERM

    if ! validate_configured_roots; then
        report_uninstall_failures
        return 1
    fi
    build_uninstall_plan
    cat "${PLAN_FILE}"
    if [ "${DRY_RUN}" -eq 1 ]; then
        return 0
    fi
    confirm_uninstall || return 1
    execute_uninstall || true
    if [ "${FAILURE_COUNT}" -gt 0 ]; then
        report_uninstall_failures
        return 1
    fi
    printf 'Uninstall complete\n'
}

if [ "${AGENTENV_UNINSTALLER_SOURCE_ONLY:-0}" != "1" ]; then
    main "$@"
fi
