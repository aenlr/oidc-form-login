#!/usr/bin/env python3
"""Generic interactive OIDC form login module."""

try:
    # For PyInstaller
    import pip_system_certs.wrapt_requests

    pip_system_certs.wrapt_requests.inject_truststore()
except ImportError:
    pass


import os
import re
import sys
import urllib.parse
from argparse import ArgumentParser, Namespace
from getpass import getpass, getuser
from typing import Any
from urllib.parse import parse_qs, urljoin

import bs4
import requests
import urllib3.util
from bs4 import BeautifulSoup
from requests import Response, Session
from urllib3.util.url import Url


class LoginError(Exception):
    """Login error exception."""


def replace_query_param(q: str, name: str, value: str, encode=True):
    """Replace a query string parameter with a new value.

    Not using urllib in case there are improperly encoded
    parameters or mismatched charset.

    :param q: encoded query string
    :param name: name of parameter
    :param value: value of parameter
    :param encode: True to quote parameter value
    :return: new query string

    >>> replace_query_param("foo=bar&baz=quux", "foo", "oy")
    'foo=oy&baz=quux'
    >>> replace_query_param("?foo=bar&baz=quux&q=", "foo", "oy")
    '?foo=oy&baz=quux&q='
    >>> replace_query_param("foo=bar&baz=quux&q=", "baz", "oy")
    'foo=bar&baz=oy&q='
    """
    repl = f"{name}={urllib.parse.quote(value) if encode else value}"
    q, n = re.subn(rf"(^\?|&|^)({re.escape(name)}=[^&]*)", rf"\1{repl}", q)
    if not n:
        q = f"{q}&{repl}" if q else repl
    return q


def url_no_query(url: Url):
    """Return a URL with query and fragment stripped."""
    return str(url._replace(query=None, fragment=None))


def parse_content_type(r: Response) -> str:
    """Return lowercase content-type header without parameters."""
    h = r.headers.get("content-type")
    if h:
        return h.split(";")[0].strip().lower()
    return ""


def _is_input_type_text(f):
    return f.name == "input" and f.attrs.get("type", "text") == "text"


def _is_input_type_password(f):
    return f.name == "input" and f.attrs.get("type", "text") == "password"


def _is_input_autocomplete_username(f):
    autocomplete = f.attrs.get("autocomplete")
    return f.has_attr("name") and autocomplete == "username"


def _is_input_possibly_username(f):
    autocomplete = f.attrs.get("autocomplete")
    if autocomplete and autocomplete != "off":
        return False

    name = f.attrs.get("name")
    return name in ("username", "user", "login")


def _is_input_autocomplete_password(f):
    autocomplete = f.attrs.get("autocomplete")
    return autocomplete == "current-password"


def _is_input_possibly_password(f):
    autocomplete = f.attrs.get("autocomplete")
    if autocomplete and autocomplete != "off":
        return False

    name = f.attrs.get("name")
    return name in ("password", "passwd", "pass", "pwd")


# pylint: disable=R0913,R0914
def _submit_login_form(
    username: str,
    password: str,
    url: Url,
    session: Session,
    *,
    soup: BeautifulSoup,
    form: bs4.Tag,
    username_field: bs4.Tag,
    password_field: bs4.Tag,
    fields: list,
    verify=True,
) -> Response:
    submit_button = form.find(["input", "button"], {"type": "submit"})
    if not submit_button and form.has_attr("id"):
        submit_button = soup.find(
            ["input", "button"], {"form": form["id"], "type": "submit"}
        )
    if submit_button and not submit_button.has_attr("name"):
        submit_button = None

    action = form["action"] if form.has_attr("action") else str(url)
    method = str(form["method"]).upper() if form.has_attr("method") else "GET"
    action = urljoin(url_no_query(url), action)

    payload = {}
    username_field_name = username_field["name"]
    password_field_name = password_field["name"]
    for f in fields:
        name = f["name"]
        field_type = f.attrs.get("type", "text")
        if name == username_field_name:
            payload[name] = username
        elif name == password_field_name:
            payload[name] = password
        elif f.name == "textarea":
            payload["name"] = f.get_text()
        elif field_type == "submit":
            if submit_button and name == submit_button["name"]:
                if f.has_attr("value"):
                    payload["name"] = f["value"]
                else:
                    payload["name"] = f.get_text()
        else:
            payload["name"] = f.attrs.get("value", "")

    headers = {}
    if method == "POST":
        enctype = form.attrs.get("enctype")
        if isinstance(enctype, str):
            headers["content-type"] = enctype
        else:
            headers["content-type"] = "application/x-www-form-urlencoded"
    return session.request(
        method,
        action,
        params=payload if method == "GET" else None,
        data=payload if method == "POST" else None,
        headers=headers,
        verify=verify,
    )


def _process_forms(
    username: str,
    password: str,
    *,
    url: Url,
    html: str,
    session: Session,
    username_field: str | None = None,
    password_field: str | None = None,
    verify=True,
) -> Response | None:
    soup = BeautifulSoup(html, features="html.parser")
    forms = list(soup("form"))
    for form in forms:
        fields = list(form.find_all(["input", "textarea"]))
        fields.extend(form.find_all("button", {"type": "submit"}))
        if form.has_attr("id"):
            fields.extend(soup.find_all(["input", "textarea"], {"form": form["id"]}))
            fields.extend(
                soup.find_all("button", {"type": "submit", "form": form["id"]})
            )

        fields = [f for f in fields if f.has_attr("name")]
        text_inputs = [f for f in fields if _is_input_type_text(f)]
        password_inputs = [f for f in fields if _is_input_type_password(f)]

        if username_field:
            uf = next((f for f in text_inputs if f.get("name") == username_field), None)
            if not uf:
                uf = next(
                    (f for f in text_inputs if f.get("id") == username_field), None
                )
        else:
            uf = next(
                (f for f in text_inputs if _is_input_autocomplete_username(f)), None
            )
            if not uf:
                uf = next(
                    (f for f in text_inputs if _is_input_possibly_username(f)), None
                )

        if password_field:
            pf = next(
                (f for f in password_inputs if f.get("name") == password_field), None
            )
            if not pf:
                pf = next(
                    (f for f in password_inputs if f.get("id") == password_field), None
                )
        else:
            pf = next(
                (f for f in password_inputs if _is_input_autocomplete_password(f)), None
            )
            if not pf:
                pf = next(
                    (f for f in password_inputs if _is_input_possibly_password(f)), None
                )

        if not (uf and pf) and len(forms) == 1:
            if not uf and len(text_inputs) == 1:
                uf = text_inputs[0]
            if not pf and len(password_inputs) == 1:
                pf = password_inputs[0]

        if uf and pf:
            return _submit_login_form(
                username,
                password,
                url,
                session,
                soup=soup,
                form=form,
                username_field=uf,
                password_field=pf,
                fields=fields,
                verify=verify,
            )

    return None


def _find_navigation_links(html: str, url: str) -> list[str]:
    soup = BeautifulSoup(html, features="html.parser")
    elements = list(soup("a"))
    links: list[str] = []
    base = urllib3.util.parse_url(url)
    for a in elements:
        if a.has_attr("href"):
            href = a.get("href")
            if isinstance(href, str) and not href.startswith("#"):
                href = urljoin(str(url), href)
                target = urllib3.util.parse_url(href)
                if target.host != base.host or target.path != base.path:
                    links.append(href)
    return links


# pylint: disable=R0912,R0915
def login(
    username: str,
    password: str,
    url: str | None = None,
    *,
    issuer: str | None = None,
    authorization_endpoint: str | None = None,
    params: dict[str, str] | None = None,
    token_endpoint: str | None = None,
    username_field: str | None = None,
    password_field: str | None = None,
    verify=True,
) -> tuple[bool, Response, Session]:
    """Form login by username and password.

    Any redirects are followed until the form web page is reached.
    Then the form is then posted with the user credentials.
    Redirects are once again followed until the final redirect URL is
    reached (as specified by the OIDC redirect_uri parameter).
    The authorization code

    OTP is not currently supported.

    """
    auth_params = dict(params or {})

    if issuer:
        oidc_config: dict[str, Any] = requests.get(
            f"{issuer}/.well-known/openid-configuration", timeout=10
        ).json()
        if not authorization_endpoint:
            authorization_endpoint = oidc_config.get("authorization_endpoint")
        if not token_endpoint:
            token_endpoint = oidc_config.get("token_endpoint")

    if url:
        start_url = urllib3.util.parse_url(url)
        if url_no_query(start_url) == authorization_endpoint:
            authorization_endpoint = url
            url = None

    if not url:
        if not authorization_endpoint:
            raise ValueError("URL or authorization endpoint is required")
        start_url = urllib3.util.parse_url(authorization_endpoint)
        query = start_url.query or ""

        if "response_type" not in auth_params:
            auth_params["response_type"] = "code"

        if "scope" not in auth_params:
            auth_params["scope"] = "openid profile email offline_access groups"

        for k, v in auth_params.items():
            query = replace_query_param(query, k, v, encode=k not in ("state", "nonce"))

        start_url = start_url._replace(query=query)
        auth_url = start_url
        url = str(start_url)
    else:
        auth_url = None

    redirected = False
    session = Session()
    while True:
        r = session.get(url, verify=verify, allow_redirects=False)
        if r.is_redirect:
            redirected = True
            url = urljoin(url, r.headers["location"])
            redirect_url = urllib3.util.parse_url(url)

            redirect_params = {
                k: v[0] for k, v in parse_qs(redirect_url.query or "").items()
            }
            redirect_path = url_no_query(redirect_url)
            if not auth_url and all(
                p in redirect_params for p in ("redirect_uri", "client_id", "scope")
            ):
                auth_url = redirect_url
                authorization_endpoint = redirect_path
                auth_params.update(redirect_params)
            if redirect_path == auth_params.get("redirect_uri") and (
                (
                    "code" in redirect_params
                    and token_endpoint
                    and "client_secret" in auth_params
                )
                or any(p in redirect_params for p in ("token", "id_token"))
            ):
                # pylint: disable=W0511
                # TODO: request token
                pass
        elif r.text and not redirected:
            links = _find_navigation_links(r.text, url)
            if len(links) == 1:
                url = links[0]
            else:
                break
        else:
            break

    stop_url = urllib3.util.parse_url(url)
    content_type = parse_content_type(r)
    if content_type == "text/html":
        post_response = _process_forms(
            username,
            password,
            url=stop_url,
            html=r.text,
            session=session,
            username_field=username_field,
            password_field=password_field,
            verify=verify,
        )
        if post_response:
            return post_response.ok, post_response, session

    return False, r, session


def request_user_and_password(args: Namespace):
    """Set/request username and password properties.

    If username and/or password are not set they are filled in
    by OIDC_USERNAME and OIDC_PASSWORD environment variables.

    The user is prompted if a value is not provided explicitly
    or by environment variable.

    :param args: Result of ArgumentParser.parse_args(). Modified in place.
    """
    if not args.username:
        args.username = os.environ.get("OIDC_USERNAME")
        if not args.username:
            args.username = getuser()
    if not args.password:
        args.password = os.environ.get("OIDC_PASSWORD")
        if not args.password:
            args.password = getpass("Password: ")


def main():
    # pylint: disable=R0801
    """Main entrypoint for oidc-form-login utility."""
    parser = ArgumentParser()
    parser.add_argument("--issuer", metavar="URL")
    parser.add_argument("--client-id")
    parser.add_argument("--client-secret")
    parser.add_argument("-u", "--user", "--username", dest="username")
    parser.add_argument("-p", "--pass", "--password", dest="password")
    parser.add_argument(
        "--username-field", help="name of username input field in login form"
    )
    parser.add_argument(
        "--password-field", help="name of password input field in login form"
    )
    parser.add_argument("--authorization-endpoint")
    parser.add_argument("--redirect-uri")
    parser.add_argument("--token-endpoint")
    parser.add_argument("--scope", action="append")
    parser.add_argument(
        "-k", "--insecure", default=True, dest="verify", action="store_false"
    )
    parser.add_argument("url", nargs="?")

    args = parser.parse_args()
    request_user_and_password(args)

    auth_params = {}
    if args.scope:
        auth_params["scope"] = " ".join(
            s for e in args.scope for s in re.split("[ ,]*", e)
        )
    if args.client_id:
        auth_params["client_id"] = args.client_id
    if args.client_secret:
        auth_params["client_secret"] = args.client_secret
    if args.redirect_uri:
        auth_params["redirect_uri"] = args.redirect_uri

    ok, r, _ = login(
        args.username,
        args.password,
        args.url,
        authorization_endpoint=args.authorization_endpoint,
        token_endpoint=args.token_endpoint,
        params=auth_params,
        username_field=args.username_field,
        password_field=args.password_field,
        verify=args.verify,
    )

    if ok:
        print(r.text)
    elif r.ok:
        print(r.text, file=sys.stderr)
        parser.exit(1, f"Login stopped at {r.url}")
    else:
        print(r.text, file=sys.stderr)
        parser.exit(1, f"Login failed with status {r.status_code} at {r.url}")


if __name__ == "__main__":
    main()
