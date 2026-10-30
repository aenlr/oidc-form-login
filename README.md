# OIDC form login via terminal

Utility that attempts to login via an OIDC username/password form.

Comes with a [Gangway](https://github.com/vmware-archive/gangway) integration to
automate updating kubernetes user credentials from the command line.

## Install

This section is only for installing and running on the local system
without packaging. See Development for creating a portable executable.

Install globally or in active virtual environment

    pip install .
    gangway-login

Or per user

    pip install --user .
    gangway-login

## Development

Simply run `make` do everything covered below.
`uv` is preferred if installed, otherwise plain pip is used.

### Using uv (any platform)

    uv sync --extra dev
    uv run pre-commit install
    uv run pyinstaller --distpath standalone --name gangway-login --onefile src/oidc_form_login/gangway.py

### Using virtual environment and pip

#### Create virtual environment (bash)
    $ python3 -m venv --prompt oidc-form-login .venv
    $ . .venv/bin/activate

#### Create virtual environment (Windows cmd.exe)
    C:\> python -m venv --prompt oidc-form-login ,venv
    C:\> .venv/Scripts/activate

#### Create virtual environment (Windows PowerShell)
    PS1> python -m venv venv
    PS1> ./venv/Scripts/activate.ps1

#### Install dependencies
    (oidc-form-login) $ pip install -e .[dev]
    (oidc-form-login) $ pre-commit install

#### Package executable
    (oidc-form-login) $ pyinstaller --distpath standalone --name gangway-login --onefile src/oidc_form_login/gangway.py
