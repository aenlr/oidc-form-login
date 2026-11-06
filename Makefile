#################################################
# Variables
#################################################
# Override python version when not using uv (i.e make PYTHON3=python3.8)
PYTHON3 = python3.13

# Add venv to PATH
export PATH := $(PWD)/.venv/bin:$(PWD)/.venv/Scripts:$(PATH)

SOURCES = $(wildcard src/oidc_form_login/*.py)
#TEST_SOURCES = $(wildcard src/tests/*.py)
PYINST_FLAGS = --distpath standalone

#################################################
# Main targets
#################################################
.PHONY: all build

all: check build
build: dist standalone
dev: venv hooks

#################################################
# Environment
#################################################
venv: .venv
.venv:
	@uv venv --allow-existing || $(PYTHON3) -m venv --prompt oidc-form-login .venv
	@if ! uv sync --dev; then \
		python -m pip install --upgrade pip; \
		pip install --group dev -e .; \
	fi

hooks: .git/hooks/pre-commit
.git/hooks/pre-commit: .venv
	@pre-commit install

#################################################
# Build and package
#################################################
dist: $(SOURCES) pyproject.toml src/oidc_form_login .venv
	@if ! uv build --wheel; then \
		pip wheel --no-deps -w dist . ; \
	fi

standalone: standalone/gangway-login standalone/oidc-form-login
standalone/oidc-form-login: src/oidc_form_login/login.py src/oidc_form_login/__init__.py .venv
	pyinstaller $(PYINST_FLAGS) --name oidc-form-login --onefile src/oidc_form_login/login.py
standalone/gangway-login: $(SOURCES) src/oidc_form_login .venv
	pyinstaller $(PYINST_FLAGS) --name gangway-login --onefile src/oidc_form_login/gangway.py

#################################################
# QA
#################################################
check: test typecheck
typecheck: mypy
lint: ruff-check
test: $(SOURCES) $(TEST_SOURCES) src/oidc_form_login .venv
	pytest

mypy: .venv
	mypy src

ruff-check: .venv
	ruff check --fix

ruff-check-unsafe: .venv
	ruff check --fix --unsafe-fixes
	ruff format

pylint: .venv
	pylint src

format: .venv
	ruff format

#################################################
# Cleaning
#################################################
clean:
	rm -rf dist standalone standalone-build src/*.egg-info src/oidc_form_login/__pycache__ .*_cache

distclean: clean
	rm -rf .venv uv.lock
