#!/bin/sh
set -e

rm -rf src/*.egg-info src/oidc_form_login/__pycache__ .*_cache \
    build build-linux build-win \
    standalone standalone-linux standalone-win \
    *.spec

case "$1" in
    really* | dist*) rm -rf .venvw .venvl dist dist-linux dist-win
esac
case "$1" in
    dist*) rm -rf .venv dist-*/
esac
