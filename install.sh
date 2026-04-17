#!/bin/sh
set -eu

REPO="${AGENTENV_REPO:-windoliver/agentenv}"
VERSION="${AGENTENV_VERSION:-}"
BIN_NAME="agentenv"

if [ -n "${CARGO_HOME:-}" ]; then
    DEFAULT_INSTALL_DIR="${CARGO_HOME%/}/bin"
else
    DEFAULT_INSTALL_DIR="${HOME}/.cargo/bin"
fi

INSTALL_DIR="${AGENTENV_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

need_cmd curl
need_cmd tar
need_cmd mktemp
need_cmd uname

resolve_version() {
    releases_url="https://api.github.com/repos/${REPO}/releases?per_page=1"
    resolved_version="$(
        curl --fail --silent --location --proto '=https' --tlsv1.2 "${releases_url}" \
            | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -n 1
    )"

    if [ -z "${resolved_version}" ]; then
        echo "unable to resolve the latest published release from ${releases_url}" >&2
        exit 1
    fi

    printf '%s\n' "${resolved_version}"
}

platform="$(uname -s)"
arch="$(uname -m)"

if [ -n "${AGENTENV_TARGET:-}" ]; then
    target="$AGENTENV_TARGET"
else
    case "$platform" in
        Darwin)
            case "$arch" in
                arm64|aarch64) target="aarch64-apple-darwin" ;;
                x86_64) target="x86_64-apple-darwin" ;;
                *)
                    echo "unsupported macOS architecture: $arch" >&2
                    exit 1
                    ;;
            esac
            ;;
        Linux)
            libc="gnu"
            if command -v ldd >/dev/null 2>&1; then
                if ldd --version 2>&1 | grep -qi musl; then
                    libc="musl"
                fi
            fi

            case "$arch" in
                arm64|aarch64) target="aarch64-unknown-linux-${libc}" ;;
                x86_64) target="x86_64-unknown-linux-${libc}" ;;
                *)
                    echo "unsupported Linux architecture: $arch" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "unsupported platform: $platform" >&2
            exit 1
            ;;
    esac
fi

archive="${BIN_NAME}-${target}.tar.xz"

if [ -z "${VERSION}" ]; then
    VERSION="$(resolve_version)"
fi

if [ "${VERSION}" = "latest" ]; then
    download_url="https://github.com/${REPO}/releases/latest/download/${archive}"
else
    download_url="https://github.com/${REPO}/releases/download/${VERSION}/${archive}"
fi

tmpdir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT INT HUP TERM

echo "Downloading ${download_url}"
curl --fail --location --proto '=https' --tlsv1.2 --output "${tmpdir}/${archive}" "${download_url}"

tar -xJf "${tmpdir}/${archive}" -C "$tmpdir"

binary_path="$(find "$tmpdir" -type f -name "$BIN_NAME" | head -n 1)"
if [ -z "$binary_path" ]; then
    echo "unable to find ${BIN_NAME} in ${archive}" >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 755 "$binary_path" "${INSTALL_DIR}/${BIN_NAME}"

echo "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
