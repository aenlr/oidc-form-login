# Changelog

All notable changes to this project will be documented in this file.

## [0.3] - 2026-11-08

### Added
- Keyring integration. Supports Secret Service (D-Bus), KWallet, Keychain (macOS) and Windows
  Credential Manager. Use `--no-keyring` to disable.  
  Keyring enables stored credentials for individual sites, and therefore a single credential
  is no longer assumed for multi-site logins. Specify credentials explicitly on the command line
  or using environment variables to reuse credentials for all sites.  
  The option `--single-credential` also enables credential reuse between sites even when prompted.

- Migration to `uv` for dependency management and building.
- `pre-commit` hooks for automated quality checks.

### Changed
- Refactored core login logic to support response_mode=form_post and auto-submitted forms.
- Improved control over returned results in the login process.
- Backup of kubeconfig is no longer enabled by default.

### Fixed
- Fixed `gangway-login` where `-o/--kubeconfig` option consumed all subsequent arguments.
- Resolved various bugs and linter warnings identified during tooling setup.
