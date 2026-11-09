# OIDC form login via terminal

Utility that attempts to login via an OIDC username/password form.

## Tools

### gangway-login

Comes with a [Gangway](https://github.com/vmware-archive/gangway) integration to
automate updating kubernetes user credentials from the command line.

Authenticate for the first time, creating kubectl contexts
```bash
gangway-login --all https://gangway.example.com/
```

Leave out `--all` to re-authenticate and only update credentials
```bash
gangway-login https://gangway.example.com/
```

Specify multiple clusters to authenticate using multiple credentials.
```bash
gangway-login \
  https://gangway.cluster1.example.com/ \
  https://gangway.cluster2.example.com/
```

Add `--single-credential` to login with the same user and password for all clusters
```bash
gangway-login --single-credential \
  https://gangway.cluster1.example.com/ \
  https://gangway.cluster2.example.com/
```

Pass credentials through environment variables (ignores keyring)
```bash
#export OIDC_USERNAME=my-username
#export OIDC_PASSWORD=sekret
gangway-login https://gangway.example.com/
```

With `-d` gangway-login downloads and fully replaces kubeconfig rather patching
```bash
gangway-login -d --kubeconfig ~/.kube/example.conf https://gangway.example.com/
```

### oidc-form-login

Mostly a tool for testing the library.

```bash
oidc-form-login --user myuser --pass - \
  --click-before '#login' --username-field 'uname' --password-field '#pword' \
  https://example.com/login
```

### Keyring

By default, the tools will try to access the keyring of the system to safely store
credentials.

Supports Secret Service and KWallet on Linux, Keychain on macOS and
Windows Credential Locker on Windows.

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

Install [uv](https://docs.astral.sh/uv/getting-started/installation/).

Simply run `make` do everything covered below.

`uv` is preferred if installed, otherwise plain pip is used.

### Using uv (any platform)

    # omit --extra dev and pre-commit if only packaging
    uv sync --extra dev --extra packaging
    uv run pre-commit install
    uv run pyinstaller --distpath standalone --name gangway-login --onefile src/oidc_form_login/gangway.py

### Using virtual environment and pip

#### Create virtual environment (bash)
```console
    $ python3 -m venv --prompt oidc-form-login .venv
    $ . .venv/bin/activate
```

#### Create virtual environment (Windows cmd.exe)
```bat
    C:\> python -m venv --prompt oidc-form-login ,venv
    C:\> .venv/Scripts/activate
```

#### Create virtual environment (Windows PowerShell)
```PowerShell
    PS1> python -m venv venv
    PS1> ./venv/Scripts/activate.ps1
```

#### Install dependencies and git hooks

Run in the virtual environment.

    pip install -e .[dev,packaging]
    pre-commit install

#### Package executable

Run in the virtual environment.

    pyinstaller --distpath standalone --name gangway-login --onefile src/oidc_form_login/gangway.py
