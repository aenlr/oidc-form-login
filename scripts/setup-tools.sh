#!/usr/bin/env bash

uv_version=0.11.21
uv_linux=uv-x86_64-unknown-linux-gnu
uv_linux_tar="$uv_linux.tar.gz"
uv_linux_sha256=8c88519b0ef0af9801fcdee419bbb12116bd9e6b18e162ae093c932d8b264050
uv_win=uv-x86_64-pc-windows-msvc
uv_win_zip="$uv_win.zip"
uv_win_sha256=ace861f360c6de2babedc1607d0f454b6b09a820dbc8182dc15af927e4df9589

set -euo pipefail

if [ -e /.dockerenv ] && ! wine --version >/dev/null 2>&1; then
    # Install packages
    if apt-get --version >/dev/null 2>&1; then
        apt-get update
        apt-get install --no-install-recommends --assume-yes curl make binutils unzip wine
    elif zypper --version >/dev/null 2>&1; then
        zypper -n in --no-recommends curl make binutils unzip wine
    else
        echo "$0: unsupported environment" >&2
        cat /etc/os-release 2>/dev/null
        exit 1
    fi
fi

# Install uv
if [[ -z "${UV_INSTALLER_GITHUB_BASE_URL-}" && -n "${GITHUB_URL-}" ]]; then
    UV_INSTALLER_GITHUB_BASE_URL="${GITHUB_URL}"
fi
if ! [[ -e /tmp/$uv_linux/uv && -r /tmp/$uv_win/uv.exe ]]; then
    cd /tmp
    if [ -n "${UV_INSTALLER_GITHUB_BASE_URL:-}" ]; then
        urls=("${UV_INSTALLER_GITHUB_BASE_URL}/astral-sh/uv/releases/download/$uv_version")
    else
        urls=(
            "https://releases.astral.sh/github/uv/releases/download/$uv_version"
            "https://github.com/astral-sh/uv/releases/download/$uv_version"
        )
    fi

    ok=0
    cat >uv.sha256 <<EOF
$uv_linux_sha256  $uv_linux_tar
$uv_win_sha256  $uv_win_zip
EOF
    for url in "${urls[@]}"; do
        for f in "$uv_linux_tar" "$uv_win_zip"; do
            if [ ! -e "$f" ]; then
                echo "Downloading $url/$f..."
                curl --fail-with-body -ksSLO "$url/$f"
            fi
            if sha256sum --check uv.sha256; then
                ok=1
                break
            fi
        done
    done

    if [ "$ok" = 0 ] && ! sha256sum --check uv.sha256; then
        echo "$0: uv download failed" >&2
        exit 1
    fi

    rm -rf "$uv_linux" "$uv_win"
    tar xzf "$uv_linux_tar"
    rm -rf "$uv_win"
    unzip -d "$uv_win" "$uv_win_zip"
    ln -svf "/tmp/$uv_linux"/* /usr/bin/
fi
