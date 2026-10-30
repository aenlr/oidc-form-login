#!/usr/bin/env python3
"""Integration of login with gangway for Kubernetes."""

try:
    # For PyInstaller
    import pip_system_certs.wrapt_requests

    pip_system_certs.wrapt_requests.inject_truststore()
except ImportError:
    pass

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from argparse import ArgumentParser, Namespace
from collections.abc import Iterable
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests import Response

from oidc_form_login.login import login, parse_content_type, request_user_and_password


def confirm(prompt, default="y") -> str:
    """Ask for yes/no/quit confirmation with a prompt."""
    while True:
        print(prompt, flush=True, end="")
        line = sys.stdin.readline()
        if not line:
            return "q"
        line = line.strip() or default
        if line in ("y", "Y"):
            return "y"
        if line in ("n", "N"):
            return "n"
        if line in ("q", "Q"):
            return "q"


def _gather_code_blocks(text: str) -> list[str]:
    """Parse gangway HTML and extract bash code blocks."""
    soup = BeautifulSoup(text, features="html.parser")
    return [
        t.get_text().lstrip()
        for t in soup.find_all("code", class_="language-bash")
        if re.match(".*^kubectl ", t.get_text(), re.DOTALL | re.MULTILINE)
    ]


def _join_continuation_lines(code_blocks: list[str]) -> list[str]:
    """Join bash continuation lines."""
    lines = []
    for block in code_blocks:
        continuation = []  # type: list[str]
        for line in block.splitlines():
            stripped = line.rstrip()
            if continuation:
                if stripped.endswith("\\"):
                    continuation.append(stripped)
                else:
                    continuation.append(stripped.rstrip())
                    continuation = [c.rstrip("\\").strip() for i, c in enumerate(continuation)]
                    lines.append(" ".join(continuation))
                    continuation.clear()
            else:
                if stripped.startswith("$"):
                    stripped = stripped.lstrip("$").lstrip()
                if stripped.endswith("\\"):
                    continuation.append(stripped)
                else:
                    lines.append(stripped)
    return lines


def _run_sh_script(script: str, verbose=True) -> int:
    """Run shell script.

    Fail on command errors.

    :param script: script content
    :param verbose: suppress standard output if False
    :return: process exit code.
    """
    with subprocess.Popen(
        ["/bin/sh"],
        stdin=subprocess.PIPE,
        stdout=None if verbose else subprocess.DEVNULL,
        stderr=None,
        encoding="utf-8",
        text=True,
    ) as proc:
        proc.stdin.write("set -e" + os.linesep + script + os.linesep)  # type: ignore
        proc.communicate()
        return proc.returncode


def _run_ps1_script(script: str, verbose=True) -> int:
    """Run PowerShell script.

    Fail on command errors.

    :param script: script content
    :param verbose: suppress standard output if False
    :return: process exit code.
    """
    fd, ps1 = tempfile.mkstemp(suffix=".ps1")
    prefix = "$ErrorActionPreference = 'Stop'"
    script = prefix + os.linesep + script + os.linesep
    try:
        try:
            os.write(fd, script.encode("latin1"))
        finally:
            os.close(fd)
        args = [
            "powershell.exe",
            "-nologo",
            "-noprofile",
            "-Command",
            ps1,
        ]
        proc = subprocess.run(args, stdout=None if verbose else subprocess.DEVNULL, check=False)
    finally:
        os.remove(ps1)

    return proc.returncode


def _print_no_commands(message: str, r: Response, code_blocks: list[str]):
    """Print an error message followed by gangway response.

    Print code blocks if any, otherwise print full gangway response page.
    """
    print(message, file=sys.stderr)
    if code_blocks:
        print("\n".join(code_blocks), file=sys.stderr)
    else:
        print(r.text, file=sys.stderr)


def _fix_ps1_redirections(lines: list[str]):
    """Translate redirections to PowerShell syntax.

    Ensures redirections use ASCII instead of the default encoding.

    :param lines: list of commands, modified in place
    """
    for i, line in enumerate(lines):
        m = re.match(r"(.+)> ?([a-zA-Z0-9._\"-]+)$", line)
        if m:
            pem = m[1].replace("\\", "")
            lines[i] = f"{pem} | Out-File {m[2]} -Encoding ascii"


def run_kubectl_commands(r: Response, *, interactive=False, run_all=False, verbose=False):
    """Run kubectl commands from gangway post login page.

    :param r: gangway response after successful authentication
    :param interactive: print and require confirmation of commands
    :param run_all: run all commands if True, otherwise only kubectl config set-credentials
    :param verbose: print all commands and command outputs if True, otherwise only print errors
    """
    assert r.ok

    code_blocks = _gather_code_blocks(r.text)
    lines = _join_continuation_lines(code_blocks)
    if not lines:
        _print_no_commands("No kubectl commands found", r, code_blocks)
        return False

    if not run_all:
        set_creds = [line for line in lines if line.startswith("kubectl config set-credentials ")]
        if not set_creds:
            _print_no_commands("No set-credentials command found", r, code_blocks)
            return False
        lines = set_creds

    if os.name == "nt":
        _fix_ps1_redirections(lines)

    script = os.linesep.join(lines)
    if verbose or interactive:
        print(script)

    if interactive:
        confirmation = confirm("Run commands [Y/n/q]? ")
        if confirmation == "n":
            return True
        if confirmation == "q":
            return False

    if len(lines) == 1 and not run_all:
        # Only kubectl config set-credentials ...
        ret = subprocess.run(
            shlex.split(lines[0]),
            stdout=None if verbose else subprocess.DEVNULL,
            check=False,
        ).returncode
    elif os.name == "nt":
        ret = _run_ps1_script(script, verbose)
    else:
        ret = _run_sh_script(script, verbose)

    if ret != 0:
        print(
            f"Command exited with status non-zero status: {ret}",
            file=sys.stderr,
        )
        if not (verbose or interactive):
            for line in lines:
                print(f"  {line}", file=sys.stderr)

        return False

    return True


def download_kubeconfig(
    session: requests.Session, url: str, output_file: str, verify=True, verbose=False
) -> bool:
    """Download kubeconfig after successful gangway authentication.

    A backup of output_file is created if it already exists.

    :param session: authentication session
    :param url: url to download
    :param output_file: file to save and backup
    :param verify: TLS verification is disabled if False
    :param verbose: print actions taken if True
    """
    if verbose:
        print(f"Downloading kubeconfig from {url}...")

    r = session.get(url, verify=verify)
    if not r.ok:
        print(
            f"Downloading {url} failed with status {r.status_code}: {r.text}",
            file=sys.stderr,
        )
        return False

    # Verify that we didn't just download the login page (HTML) instead of the config (YAML)
    content_type = parse_content_type(r)
    if "text/html" in content_type or r.text.strip().startswith("<"):
        print(
            "Downloaded kubeconfig appears to be HTML. Authentication likely failed or redirected.",
            file=sys.stderr,
        )
        print(r.text, file=sys.stderr)
        return False

    if os.path.exists(output_file):
        backup_file = output_file + ".bak"
        if verbose:
            print(f"Backing up existing config to {backup_file}")
        shutil.copy2(output_file, backup_file)
    elif output_path := os.path.dirname(output_file):
        os.makedirs(output_path, exist_ok=True)

    with open(output_file, "wb") as f:
        f.write(r.content)

    if verbose:
        print(f"Kubeconfig saved to {output_file}")
    return True


def get_current_context():
    """Get current kubectl context.

    Returns an empty string if kubeconfig does not exist or does not
    have a current context set. Any other errors raises CalledProcessError.
    """
    r = subprocess.run(
        ["kubectl", "config", "current-context"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        output = r.stderr.strip()
        if "current-context is not set" not in output:
            r.check_returncode()
        return ""
    return r.stdout.strip()


def expand_kubeconfig_users(kubeconfig: Iterable[str]) -> list[str]:
    """Expand tilde in list of kubeconfig filenames."""
    return [os.path.expanduser(f) for f in kubeconfig]


_DEFAULT_KUBECONFIG = os.environ.get("KUBECONFIG") or "~/.kube/config"


def _validate_kubeconfigs(parser: ArgumentParser, args: Namespace) -> list[str]:
    """Process and validate --kubeconfig option.

    Fall back to KUBECONFIG environment or ~/.kube/config if --kubeconfig
    option is not used.

    A single option will be split like the KUBECONFIG variable by os.pathsep.

    Any element starting with ~/ or ~username/ will be expanded by
    os.path.expanduser.

    :params parser: ArgumentParser
    :params args: Result of parser.parse_args()
    :returns: list of kubeconfig filenames (never empty)
    """
    if not args.kubeconfig:
        configs = expand_kubeconfig_users(_DEFAULT_KUBECONFIG.split(os.pathsep))
    elif len(args.kubeconfig) == 1:
        configs = expand_kubeconfig_users(args.kubeconfig[0].split(os.pathsep))
    else:
        configs = expand_kubeconfig_users(args.kubeconfig)

    if (args.download or len(configs) > 1) and len(args.url) != len(configs):
        parser.exit(
            1,
            f"{len(args.url)} clusters specified, but {len(configs)} kubeconfigs: {configs}",
        )
    return configs


def main():
    """gangway-login main entrypoint."""

    parser = ArgumentParser()
    parser.add_argument("-u", "--user", "--username", dest="username")
    parser.add_argument("-p", "--pass", "--password", dest="password")
    parser.add_argument(
        "-i",
        "--interactive",
        dest="interactive",
        default=True,
        action="store_true",
        help="confirm commands to run",
    )
    parser.add_argument("-y", "--non-interactive", dest="interactive", action="store_false")
    parser.add_argument(
        "--all",
        action="store_true",
        help="run all gangway commands (not only kubectl config set-credentials)",
    )
    parser.add_argument("-k", "--insecure", default=True, dest="verify", action="store_false")
    parser.add_argument(
        "-q", "--quiet", action="store_false", dest="verbose", help="quiet operation"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", dest="verbose", help="verbose operation"
    )
    parser.add_argument(
        "--preserve-context",
        action="store_true",
        help="preserve current kubectl context",
    )
    parser.add_argument(
        "-d",
        "--download",
        action="store_true",
        help="Download and replace kubeconfig rather than running commands",
    )
    parser.add_argument("--download-url", dest="download", help="URL to download kubeconfig from")
    parser.add_argument(
        "-o",
        "--kubeconfig",
        nargs="*",
        help=f"Kubeconfig(s) to update or replace (default: {_DEFAULT_KUBECONFIG})",
    )
    parser.add_argument("url", nargs="+")

    args = parser.parse_args()
    kubeconfigs = _validate_kubeconfigs(parser, args)
    request_user_and_password(args)

    for i, url in enumerate(args.url):
        ok, r, session = login(args.username, args.password, url, verify=args.verify)
        if not ok:
            if r.ok:
                print(r.text, file=sys.stderr)
                parser.exit(1, f"Login stopped at {r.url}")
            else:
                print(r.text, file=sys.stderr)
                parser.exit(1, f"Login failed with status {r.status_code} at {r.url}")

        kubeconfig = kubeconfigs[0] if len(kubeconfigs) == 1 else kubeconfigs[i]
        if args.download:
            if args.download is True:
                kubeconf_url = url.rstrip("/") + "/kubeconf"
            else:
                kubeconf_url = urljoin(url, str(args.download))
            ok = download_kubeconfig(
                session,
                kubeconf_url,
                kubeconfig,
                verify=args.verify,
                verbose=args.verbose,
            )
        else:
            if args.kubeconfig:
                os.environ["KUBECONFIG"] = kubeconfig
            if args.preserve_context:
                original_context = get_current_context()
            else:
                original_context = ""
            try:
                ok = run_kubectl_commands(
                    r,
                    interactive=args.interactive,
                    run_all=args.all,
                    verbose=args.verbose,
                )
            finally:
                if original_context and original_context != get_current_context():
                    subprocess.run(
                        ["kubectl", "config", "use-context", original_context],
                        stdout=subprocess.DEVNULL,
                        check=True,
                    )
        if not ok:
            parser.exit(1)


if __name__ == "__main__":
    main()
