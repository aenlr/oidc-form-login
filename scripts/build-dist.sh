#!/usr/bin/env bash

set -euo pipefail
SCRIPT_DIR="$(readlink -f "$(dirname "$0")")"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export UV_PROJECT_ENVIRONMENT=.venvl

clean=1
while [ $# -gt 0 ]; do
    case "$1" in
        --no-clean)
            clean=0
            ;;
        *)
            echo "$0: invalid option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

cd "$BASE_DIR"
version=$(sed -rn 's|^version\s*=\s*"([^"]+)"|\1|p' <pyproject.toml)
if [ -z "$version" ]; then
    echo "$0: version not found in pyproject.toml" >&2
    exit 1
fi

"$SCRIPT_DIR/setup-tools.sh"

mkdir -p "dist-$version"
if [ -n "${HOST_UID-}" ]; then
    chown "$HOST_UID:${HOST_GID:?}" "dist-$version"
fi

if ! "$SCRIPT_DIR/build-linux.sh" "$version"; then
    [ "$clean" = 0 ] || make reallyclean
    exit 1
fi

if ! wine cmd.exe /C scripts/build-win.bat "$version"; then
    [ "$clean" = 0 ] || make reallyclean
    exit 1
fi

# Cleanup
if [ -n "${HOST_UID-}" ]; then
    chown -R "$HOST_UID:$HOST_GID" "dist-$version"
fi

[ "$clean" = 0 ] || make reallyclean
