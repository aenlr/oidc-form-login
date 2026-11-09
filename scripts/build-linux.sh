#!/usr/bin/env bash

set -euo pipefail
version="${1:?}"

# Build linux version
echo "Building version $version for linux"
make check build PYINST_PREFIX=standalone-linux UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-.venvl}"

mkdir -p "dist-$version/"
cp -uv dist/*.whl "dist-$version/"
for f in standalone-linux/standalone/*; do
    cp -uv "$f" "dist-$version/$(basename "$f")-$version-linux-amd64"
done
