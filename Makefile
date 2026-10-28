PYTHON3 = python3.13

venv:
	$(PYTHON3) -m venv venv

dev: venv
	venv/bin/python3 -m pip install --upgrade pip
	venv/bin/pip install -e .[dev]

dist/gangway-login: src/oidc_form_login/*.py
	venv/bin/pyinstaller --name gangway-login --onefile src/oidc_form_login/gangway.py

dist: dist/gangway-login

test check:
	venv/bin/pytest

clean:
	rm -rf dist build src/*.egg-info *.spec

distclean: clean
	rm -rf venv

