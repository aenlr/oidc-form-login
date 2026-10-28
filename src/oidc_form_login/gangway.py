#!/usr/bin/env python3
try:
    # For PyInstaller
    import pip_system_certs.wrapt_requests  # noqa
    pip_system_certs.wrapt_requests.inject_truststore()
except ImportError:
    pass

import os
import re
import requests
import shlex
import shutil
import subprocess
import sys
import tempfile

from bs4 import BeautifulSoup
from requests import Response
from urllib.parse import urljoin

from oidc_form_login.login import login, parse_content_type


def confirm(prompt) -> str:
    while True:
        print(prompt, flush=True, end="")
        line = sys.stdin.readline()
        if not line:
            return "q"
        line = line.strip()
        if line in ("y", "Y") or not line:
            return "y"
        elif line in ("n", "N"):
            return "n"
        elif line in ("q", "Q"):
            return "q"


def run_kubectl_commands(r: Response, *, interactive=False, run_all=False, verbose=False):
    if not r.ok:
        print(f"Auth failed with status {r.status_code}", file=sys.stderr)
        print(r.text, file=sys.stderr)
        return False

    soup = BeautifulSoup(r.text, features="html.parser")
    code_blocks = [
        t.get_text().lstrip()
        for t in soup.find_all("code", class_="language-bash")
        if re.match(".*^kubectl ", t.get_text(), re.DOTALL | re.MULTILINE)
    ]

    lines = []
    for block in code_blocks:
        continuation = []
        for line in block.splitlines():
            stripped = line.rstrip()
            if continuation:
                if stripped.endswith("\\"):
                    continuation.append(stripped)
                else:
                    continuation.append(stripped.rstrip())
                    continuation = [
                        c.rstrip("\\").strip() for i, c in enumerate(continuation)
                    ]
                    lines.append(" ".join(continuation))
                    continuation.clear()
            else:
                if stripped.startswith("$"):
                    stripped = stripped.lstrip("$").lstrip()
                if stripped.endswith("\\"):
                    continuation.append(stripped)
                else:
                    lines.append(stripped)

    if not run_all:
        set_credentials_cmd = []
        for i, line in enumerate(lines):
            if line.startswith("kubectl config set-credentials "):
                set_credentials_cmd.append(line)
                break
        else:
            print("No set-credentials command found", file=sys.stderr)
            if code_blocks:
                print("\n".join(code_blocks), file=sys.stderr)
            else:
                print(r.text, file=sys.stderr)
            return False
        lines = set_credentials_cmd
    elif not lines:
        print("No kubectl commands found", file=sys.stderr)
        if code_blocks:
            print("\n".join(code_blocks), file=sys.stderr)
        else:
            print(r.text, file=sys.stderr)
        return False

    if os.name == "nt":
        for i, line in enumerate(lines):
            m = re.match(r"(.+)> ?([a-zA-Z0-9._\"-]+)$", line)
            if m:
                pem = m[1].replace("\\", "")
                lines[i] = f"{pem} | Out-File {m[2]} -Encoding ascii"

        args = ["powershell.exe", "-nologo", "-noprofile", "-Command", "-"]
    else:
        args = ["/bin/sh"]

    nl = os.linesep
    script = nl.join(lines)
    if verbose or interactive:
        print(script)

    if interactive:
        confirmation = confirm("Run commands [Y/n/q]? ")
        if confirmation == "n":
            return True
        elif confirmation == "q":
            return False

    if len(lines) == 1:
        args = shlex.split(lines[0])
        proc = subprocess.run(args, stdout=None if verbose else subprocess.DEVNULL)
        return_code = proc.returncode
    elif os.name == "nt":
        fd, ps1 = tempfile.mkstemp(suffix=".ps1")
        try:
            try:
                os.write(fd, "$ErrorActionPreference = 'Stop'\n".encode("latin1"))
                os.write(fd, "\n".join(lines).encode("latin1"))
            finally:
                os.close(fd)
            args = [
                "powershell.exe",
                "-nologo",
                "-noprofile",
                "-Command",
                ps1,
            ]
            proc = subprocess.run(args, stdout=None if verbose else subprocess.DEVNULL)
            return_code = proc.returncode

        finally:
            os.remove(ps1)

    else:
        return_code = -1
        with subprocess.Popen(args,
                              stdin=subprocess.PIPE,
                              stdout=None if verbose else subprocess.DEVNULL,
                              stderr=None,
                              encoding="utf-8"
                              ) as proc:
            proc.stdin.write("set -e\n" + script)
            proc.communicate()
            return_code = proc.returncode

    if return_code != 0:
        print(
            f"Command exited with status non-zero status: {proc.returncode}",
            file=sys.stderr,
        )
        if not (verbose or interactive):
            for line in lines:
                print(f"  {line}", file=sys.stderr)

        return False

    return True


def download_kubeconfig(session: requests.Session, url: str, output_file: str, verify=True, verbose=False) -> bool:
    if verbose:
        print(f"Downloading kubeconfig from {url}...")

    r = session.get(url, verify=verify)
    if not r.ok:
        print(f"Downloading {url} failed with status {r.status_code}: {r.text}", file=sys.stderr)
        return False

    # Verify that we didn't just download the login page (HTML) instead of the config (YAML)
    content_type = parse_content_type(r)
    if "text/html" in content_type or r.text.strip().startswith("<"):
        print("Downloaded kubeconfig appears to be HTML. Authentication likely failed or redirected.", file=sys.stderr)
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
    r = subprocess.run(["kubectl", "config", "current-context"],
                          capture_output=True, text=True)
    if r.returncode != 0:
        output = r.stderr.strip()
        if "current-context is not set" not in output:
            r.check_returncode()
        return ""
    return r.stdout.strip()


def main():
    from argparse import ArgumentParser
    from getpass import getpass, getuser

    default_kubeconfig = os.environ.get("KUBECONFIG") or "~/.kube/config"
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
    parser.add_argument(
        "-y", "--non-interactive", dest="interactive", action="store_false"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="run all gangway commands (not only kubectl config set-credentials)",
    )
    parser.add_argument(
        "-k", "--insecure", default=True, dest="verify", action="store_false"
    )
    parser.add_argument("-q", "--quiet", action="store_false", dest="verbose",
                        help="quiet operation")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                        help="verbose operation")
    parser.add_argument("--preserve-context", action="store_true", help="preserve current kubectl context")
    parser.add_argument("-d", "--download", action="store_true",
                        help="Download and replace kubeconfig rather than running commands")
    parser.add_argument("--download-url", dest="download", help="URL to download kubeconfig from")
    parser.add_argument("-o", "--kubeconfig",
                        help=f"Kubeconfig(s) to update or replace (default: {default_kubeconfig})")
    parser.add_argument("url", nargs="+")

    args = parser.parse_args()
    if not args.username:
        args.username = os.environ.get("OIDC_USERNAME")
        if not args.username:
            args.username = getuser()
    if not args.password:
        args.password = os.environ.get("OIDC_PASSWORD")
        if not args.password:
            args.password = getpass("Password: ")

    kubeconfigs = [os.path.expanduser(f) for f in str(args.kubeconfig or default_kubeconfig).split(os.pathsep)]
    if args.download and 1 < len(args.url) != len(kubeconfigs):
        parser.exit(1, f"{len(args.url)} clusters specified, but only {len(kubeconfigs)} kubeconfigs: {kubeconfigs}")

    for i, url in enumerate(args.url):
        ok, r, session = login(args.username, args.password, url, verify=args.verify)
        if ok:
            kubeconfig = kubeconfigs[0] if len(kubeconfigs) == 1 else kubeconfigs[i]
            if args.download:
                if args.download is True:
                    kubeconf_url = url.rstrip('/') + '/kubeconf'
                else:
                    kubeconf_url = urljoin(url, str(args.download))
                ok = download_kubeconfig(session, kubeconf_url, kubeconfig,
                                         verify=args.verify, verbose=args.verbose)
            else:
                if args.kubeconfig:
                    os.environ["KUBECONFIG"] = kubeconfig
                if args.preserve_context:
                    original_context = get_current_context()
                else:
                    original_context = ""
                try:
                    ok = run_kubectl_commands(r, interactive=args.interactive, run_all=args.all, verbose=args.verbose)
                finally:
                    if original_context and original_context != get_current_context():
                        subprocess.run(["kubectl", "config", "use-context", original_context],
                                       stdout=subprocess.DEVNULL, check=True)
            if not ok:
                parser.exit(1)
        elif r.ok:
            print(r.text, file=sys.stderr)
            parser.exit(1, f"Login stopped at {r.url}")
        else:
            print(r.text, file=sys.stderr)
            parser.exit(1, f"Login failed with status {r.status_code} at {r.url}")


if __name__ == "__main__":
    main()
