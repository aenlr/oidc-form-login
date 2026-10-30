export PATH := $(PWD)/.venv/bin:$(PWD)/.venv/Scripts:$(PATH)

# Override python version when not using uv (i.e make PYTHON3=python3.8)
PYTHON3 = python3.13

all: check dist standalone
dev: venv hooks

dist: .venv pyproject.toml src/oidc_form_login/*.py
	@if ! uv build --wheel; then \
		pip wheel --no-deps -w dist . ; \
	fi

venv: .venv
.venv:
	@uv venv --allow-existing || $(PYTHON3) -m venv --prompt venv .venv
	@if ! uv sync --extra dev; then \
		python -m pip install --upgrade pip; \
		pip install -e .[dev]; \
	fi


hooks: .git/hooks/pre-commit
.git/hooks/pre-commit: .venv
	@pre-commit install

check: test typecheck
typecheck: mypy
lint: ruff-check

PYINSTALLER_ARGS = --distpath standalone
standalone: standalone/gangway-login standalone/oidc-form-login
standalone/oidc-form-login: src/oidc_form_login/login.py src/oidc_form_login/__init__.py .venv
	pyinstaller $(PYINSTALLER_ARGS) --name oidc-form-login --onefile src/oidc_form_login/login.py
standalone/gangway-login: src/oidc_form_login/*.py .venv
	pyinstaller $(PYINSTALLER_ARGS) --name gangway-login --onefile src/oidc_form_login/gangway.py

test: .venv src/oidc_form_login/*.py #src/tests/*.py
	pytest

format: .venv
	ruff format

mypy: .venv
	mypy src

ruff-check: .venv
	ruff check --fix

ruff-check-unsafe: .venv
	ruff check --fix --unsafe-fixes
	ruff format

pylint: .venv
	pylint src

clean:
	rm -rf dist standalone standalone-build src/*.egg-info src/oidc_form_login/__pycache__

distclean: clean
	rm -rf .venv uv.lock
