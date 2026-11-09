#!/bin/sh

set -e

if [ $# -eq 0 ]; then
    set -- /work/scripts/build-dist.sh
fi

if [ -z "${PYTHON_IMAGE-}" ]; then
    python_version=$(sed -rn 's/^requires-python\s*=\s*"(<=|>=|==)?\s*([^ ,"]+).*"$/\2/p' <pyproject.toml)
    if [ -z "$python_version" ]; then
        echo "$0: python version not detected" >&2
        exit 1
    fi
    PYTHON_IMAGE="${DOCKER_HUB_PROXY-}python:$python_version-slim"
fi

export MSYS_NO_PATHCONV=1
docker run -it --rm \
    -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
    -e GITHUB_URL \
    -e UV_INSTALLER_GITHUB_BASE_URL \
    -e UV_DEFAULT_INDEX \
    -e UV_LINK_MODE=copy \
    -v "$PWD:/work" -w /work \
    "$PYTHON_IMAGE" "$@"
