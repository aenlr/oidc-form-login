# OIDC form login via terminal

Utility that attempts to login via an OIDC username/password form.

Comes with a [Gangway](https://github.com/vmware-archive/gangway) integration to
automate updating kubernetes user credentials from the command line.

## Install

### Global installation

Install globally or in active virtual environment

    pip install .
    gangway-login

### Per-user installation

    pip install --user .
    gangway-login

## Development

### Create and activate virtual environment

#### Create virtual environment (un*x)
    $ python3 -m venv venv
    $ . venv/bin/activate

#### Create virtual environment (Windows cmd.exe)
    C:\> python3 -m venv venv
    C:\> venv/Scripts/activate

#### Create virtual environment (Windows PowerShell)
    PS1> python3 -m venv venv
    PS1> ./venv/Scripts/activate.ps1

### Install dependencies
    (venv) $ pip install -e .[dev]

### Package executable

    (venv) $ pyinstaller --name gangway-login --onefile src/oidc_form_login/gangway.py
    
