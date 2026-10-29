PYTHON3 = python3.13
export PATH := $(PWD)/venv/bin:$(PWD)/venv/Scripts:$(PATH)

all: dev check dist

venv:
	echo "venv: $$PATH"
	$(PYTHON3) -m venv venv

dev: venv
	echo "PATH=$$PATH"
	python -m pip install --upgrade pip
	pip install -e .[dev]
	pre-commit install

check: test typecheck
typecheck: mypy
lint: ruff-check

dist: dist/gangway-login dist/oidc-form-login
dist/oidc-form-login: src/oidc_form_login/login.py src/oidc_form_login/__init__.py
	pyinstaller --name oidc-form-login --onefile src/oidc_form_login/login.py
dist/gangway-login: src/oidc_form_login/*.py
	pyinstaller --name gangway-login --onefile src/oidc_form_login/gangway.py

test:
	pytest

format:
	ruff format
#black src

mypy:
	mypy src

ruff-check:
	ruff check --fix

ruff-check-unsafe:
	ruff check --fix --unsafe-fixes
	ruff format

pylint:
	pylint src

clean:
	rm -rf dist build src/*.egg-info *.spec
distclean: clean
	rm -rf venv
