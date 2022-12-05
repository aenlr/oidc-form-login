#!/usr/bin/env python3
import shlex

try:
    import pip_system_certs.wrapt_requests  # noqa
except ImportError:
    pass

import os
import re
import subprocess
import sys

from bs4 import BeautifulSoup
from requests import Response

from oidc_form_login.login import login


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


def process_gangway_commandline(r: Response, *, interactive=False, run_all=False):
    if not r.ok:
        print(f"Auth failed with status {r.status_code}", file=sys.stderr)
        print(r.text, file=sys.stderr)
        return False

    soup = BeautifulSoup(r.text, features="html.parser")
    code_blocks = [t.get_text().lstrip() for t in soup.find_all("code", class_="language-bash")
                   if re.match(".*^kubectl ", t.get_text(), re.DOTALL | re.MULTILINE)]

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

    if not run_all:
        set_credentials_cmd = []
        for i, line in enumerate(lines):
            if line.startswith("kubectl config set-credentials "):
                c = "`" if os.name == "nt" else "\\"
                for next_line in lines[i:]:
                    set_credentials_cmd.append(next_line)
                    if not next_line.endswith(c):
                        break
                break
        if not set_credentials_cmd:
            print("No set-credentials command found", file=sys.stderr)
            if code_blocks:
                print("\n".join(code_blocks), file=sys.stderr)
            else:
                print(r.text, file=sys.stderr)
            return False
        lines = set_credentials_cmd

    if not lines:
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
                lines[i] = f"{m[1]} | Out-File {m[2]} -Encoding utf8"

        args = ["powershell.exe", "-nologo", "-noprofile", "-Command", "-"]
    else:
        args = ["/bin/sh"]

    nl = os.linesep
    script = nl.join(lines)
    print(script)

    if interactive:
        confirmation = confirm("Run commands [Y/n/q]? ")
        if confirmation == "n":
            return True
        elif confirmation == "q":
            return False

    if len(lines) == 1:
        args = shlex.split(lines[0])
        proc = subprocess.run(args)
        if proc.returncode != 0:
            print(f"Command exited with status non-zero status: {proc.returncode}", file=sys.stderr)
            return False
    else:
        with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=None, stderr=None) as proc:
            proc.stdin.write(script.encode("utf-8"))
            proc.communicate()
            if proc.returncode != 0:
                print(f"Command exited with status non-zero status: {proc.returncode}", file=sys.stderr)
                return False

    return True


def main():
    from argparse import ArgumentParser
    from getpass import getpass, getuser
    parser = ArgumentParser()
    parser.add_argument("-u", "--user", "--username", dest="username")
    parser.add_argument("-p", "--pass", "--password", dest="password")
    parser.add_argument("-i", "--interactive", dest="interactive", default=True, action="store_true",
                        help="confirm commands to run")
    parser.add_argument("-y", "--non-interactive", dest="interactive", action="store_false")
    parser.add_argument("--all", action="store_true",
                        help="run all gangway commands (not only kubectl config set-credentials)")
    parser.add_argument("-k", "--insecure", default=True, dest="verify", action="store_false")
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

    for url in args.url:
        r = login(args.username, args.password, url, verify=args.verify)
        if r.ok:
            if not process_gangway_commandline(r, interactive=args.interactive, run_all=args.all):
                parser.exit(1)
        else:
            print(r.text, file=sys.stderr)
            parser.exit(1, f"Login failed with status {r.status_code}")


if __name__ == '__main__':
    main()
