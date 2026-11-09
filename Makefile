#################################################
# Variables
#################################################
# Override python version (i.e make UV_PYTHON=3.14)
export UV_PYTHON := 3.13
PYTHON3 := python$(UV_PYTHON)

# Add venv to PATH
export UV_PROJECT_ENVIRONMENT := .venv
export PATH := $(PWD)/$(UV_PROJECT_ENVIRONMENT)/bin:$(PWD)/$(UV_PROJECT_ENVIRONMENT)/Scripts:$(PATH)

SOURCES = $(wildcard src/oidc_form_login/*.py)
#TEST_SOURCES = $(wildcard src/tests/*.py)
PYINST_PREFIX = .
PYINST_DIST_PATH = $(PYINST_PREFIX)/standalone
PYINST_WORK_PATH = $(PYINST_PREFIX)/build
PYINST_SPEC_PATH = $(PYINST_WORK_PATH)
PYINST_FLAGS = --distpath $(PYINST_DIST_PATH) --specpath $(PYINST_SPEC_PATH) --workpath $(PYINST_WORK_PATH)

#################################################
# Main targets
#################################################
.PHONY: all build dev

all: build
build: dist standalone

#################################################
# Environment
#################################################
venv: $(UV_PROJECT_ENVIRONMENT)
$(UV_PROJECT_ENVIRONMENT):
	@if ! uv sync --extra packaging $(EXTRA_UV_SYNC_ARGS); then \
		$(PYTHON3) -m venv --prompt oidc-form-login $(UV_PROJECT_ENVIRONMENT) && \
		python -m pip install --upgrade pip && \
		pip install -e .[packaging]; \
	fi

dev: venv
	if ! uv sync --extra packaging --extra dev $(EXTRA_UV_SYNC_ARGS); then \
		pip install -e .[dev,packaging]; \
	fi
	pre-commit install

#################################################
# Build and package
#################################################
dist: $(SOURCES) pyproject.toml src/oidc_form_login $(UV_PROJECT_ENVIRONMENT)
	@if ! uv build --wheel; then \
		pip wheel --no-deps -w dist . ; \
	fi

standalone: $(PYINST_DIST_PATH)/gangway-login $(PYINST_DIST_PATH)/oidc-form-login
$(PYINST_DIST_PATH)/oidc-form-login: src/oidc_form_login/login.py src/oidc_form_login/__init__.py $(UV_PROJECT_ENVIRONMENT)
	pyinstaller $(PYINST_FLAGS) --name oidc-form-login --onefile src/oidc_form_login/login.py
$(PYINST_DIST_PATH)/gangway-login: $(SOURCES) src/oidc_form_login $(UV_PROJECT_ENVIRONMENT)
	pyinstaller $(PYINST_FLAGS) --name gangway-login --onefile src/oidc_form_login/gangway.py

#################################################
# QA
#################################################
check: test typecheck
typecheck: mypy
lint: ruff-check
test: $(SOURCES) $(TEST_SOURCES) src/oidc_form_login venv
	pytest

mypy: venv
	mypy src

ruff-check: venv
	ruff check --fix

ruff-check-unsafe: venv
	ruff check --fix --unsafe-fixes
	ruff format

pylint: venv
	pylint src

format: venv
	ruff format

#################################################
# Cleaning
#################################################
clean:
	./scripts/clean.sh

reallyclean:
	./scripts/clean.sh really

distclean:
	./scripts/clean.sh dist
