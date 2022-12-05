#!/usr/bin/env python3
try:
    import pip_system_certs.wrapt_requests  # noqa
except ImportError:
    pass

import cgi
import os
import re
import sys
import urllib.parse
from typing import Optional, Dict, Any
from urllib.parse import parse_qs, urljoin

import requests
import urllib3.util
from bs4 import BeautifulSoup
from requests import Response, Session
from urllib3.util.url import Url


class LoginError(Exception):
    pass


def replace_query_param(q, name, value, encode=True):
    """ Replace a query string parameter with a new value.

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
    q, n = re.subn(rf"(^\?|&|^)({re.escape(name)}=[^&]*)",
                   lambda m: f"{m[1]}{repl}",
                   q)
    if not n:
        q = f"{q}&{repl}" if q else repl
    return q


def url_no_query(url: Url):
    return str(url._replace(query=None, fragment=None))  # noqa


def parse_content_type(r: Response) -> Optional[str]:
    h = r.headers.get("content-type")
    if h:
        return cgi.parse_header(h)[0].lower()
    return None


def is_input_type_text(f):
    return f.name == "input" and f.attrs.get("type", "text") == "text"


def is_input_type_password(f):
    return f.name == "input" and f.attrs.get("type", "text") == "password"


def is_input_autocomplete_username(f):
    autocomplete = f.attrs.get("autocomplete")
    return f.has_attr("name") and autocomplete == "username"


def is_input_possibly_username(f):
    autocomplete = f.attrs.get("autocomplete")
    if autocomplete and autocomplete != "off":
        return False

    name = f.attrs.get("name")
    return name == "username" or name == "user" or name == "login"


def is_input_autocomplete_password(f):
    autocomplete = f.attrs.get("autocomplete")
    return autocomplete == "current-password"


def is_input_possibly_password(f):
    autocomplete = f.attrs.get("autocomplete")
    if autocomplete and autocomplete != "off":
        return False

    name = f.attrs.get("name")
    return name == "password" or name == "passwd" or name == "pass" or name == "pwd"


def submit_login_form(
    username: str,
    password: str,
    url: Url,
    session: requests.Session,
    soup,
    form,
    username_field,
    password_field,
    fields: list,
    verify=True
) -> Response:
    submit_button = form.find(["input", "button"], {"type": "submit"})
    if not submit_button and form.has_attr("id"):
        submit_button = soup.find(["input", "button"], {"form": form["id"], "type": "submit"})
    if not submit_button.has_attr("name"):
        submit_button = None

    action = form["action"] if form.has_attr("action") else str(url)
    method = form["method"].upper() if form.has_attr("method") else "GET"
    action = urljoin(url_no_query(url), action)

    payload = {}
    username_field_name = username_field["name"]
    password_field_name = password_field["name"]
    for f in fields:
        name = f["name"]
        type = f.attrs.get("type", "text")
        if name == username_field_name:
            payload[name] = username
        elif name == password_field_name:
            payload[name] = password
        elif f.name == "textarea":
            payload["name"] = f.get_text()
        elif type == "submit":
            if name == submit_button["name"]:
                if f.has_attr("value"):
                    payload["name"] = f["value"]
                else:
                    payload["name"] = f.get_text()
        else:
            payload["name"] = f.attrs.get("value", "")

    headers = {}
    if method == "POST":
        headers["content-type"] = form.attrs.get("enctype", "application/x-www-form-urlencoded")
    return session.request(method, action,
                           params=payload if method == "GET" else None,
                           data=payload if method == "POST" else None,
                           headers=headers,
                           verify=verify)


def process_forms(
    username: str,
    password: str,
    url: Url,
    html: str,
    session: requests.Session,
    username_field: Optional[str] = None,
    password_field: Optional[str] = None,
    verify=True
):
    soup = BeautifulSoup(html, features="html.parser")
    forms = list(soup("form"))
    for form in forms:
        fields = list(form.find_all(["input", "textarea"]))
        fields.extend(form.find_all("button", {"type": "submit"}))
        if form.has_attr("id"):
            fields.extend(soup.find_all(["input", "textarea"], {"form": form["id"]}))
            fields.extend(soup.find_all("button", {"type": "submit", "form": form["id"]}))

        fields = [f for f in fields if f.has_attr("name")]
        text_inputs = [f for f in fields if is_input_type_text(f)]
        password_inputs = [f for f in fields if is_input_type_password(f)]

        if username_field:
            uf = next((f for f in text_inputs if f.get('name') == username_field), None)
        else:
            uf = next((f for f in text_inputs if is_input_autocomplete_username(f)), None)
            if not uf:
                uf = next((f for f in text_inputs if is_input_possibly_username(f)), None)

        if password_field:
            pf = next((f for f in password_inputs if f.get('name') == password_field), None)
        else:
            pf = next((f for f in password_inputs if is_input_autocomplete_password(f)), None)
            if not pf:
                pf = next((f for f in password_inputs if is_input_possibly_password(f)), None)

        if not (uf and pf) and len(forms) == 1:
            if not uf and len(text_inputs) == 1:
                uf = text_inputs[0]
            if not pf and len(password_inputs) == 1:
                pf = password_inputs[0]

        if uf and pf:
            return submit_login_form(username, password, url, session,
                                     soup=soup,
                                     form=form,
                                     username_field=uf,
                                     password_field=pf,
                                     fields=fields,
                                     verify=verify)


def login(username: str,
          password: str,
          url: Optional[str] = None,
          *,
          issuer: Optional[str] = None,
          authorization_endpoint: Optional[str] = None,
          params: Optional[Dict[str, None]] = None,
          token_endpoint: Optional[str] = None,
          username_field: Optional[str] = None,
          password_field: Optional[str] = None,
          verify=True
          ):
    auth_params: Dict[str, str] = dict(params) if params else {}

    if issuer:
        oidc_config: Dict[str, Any] = requests.get(f"{issuer}/.well-known/openid-configuration").json()
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

        start_url = start_url._replace(query=query)  # noqa
        auth_url = start_url
        url = str(start_url)
    else:
        auth_url = None

    with Session() as session:
        while True:
            r = session.get(url, verify=verify, allow_redirects=False)
            if r.is_redirect:
                url = urljoin(url, r.headers["location"])
                redirect_url = urllib3.util.parse_url(url)

                redirect_params = {k: v[0] for k, v in parse_qs(redirect_url.query or "").items()}
                redirect_path = url_no_query(redirect_url)
                if not auth_url and all(p in redirect_params for p in ("redirect_uri", "client_id", "scope")):
                    auth_url = redirect_url
                    authorization_endpoint = redirect_path
                    auth_params.update(redirect_params)
                if redirect_path == auth_params.get("redirect_uri"):
                    if "code" in redirect_params and token_endpoint and "client_secret" in auth_params:
                        pass
                    elif any(p in redirect_params for p in ("token", "id_token")):
                        pass
            else:
                break

        stop_url = urllib3.util.parse_url(url)
        content_type = parse_content_type(r)
        if content_type == "text/html":
            return process_forms(username, password,
                                 url=stop_url,
                                 html=r.text,
                                 session=session,
                                 username_field=username_field,
                                 password_field=password_field,
                                 verify=verify)

        return r


def main():
    from argparse import ArgumentParser
    from getpass import getpass, getuser
    parser = ArgumentParser()
    parser.add_argument("--issuer", metavar="URL")
    parser.add_argument("--client-id")
    parser.add_argument("--client-secret")
    parser.add_argument("-u", "--user", "--username", dest="username")
    parser.add_argument("-p", "--pass", "--password", dest="password")
    parser.add_argument("--username-field", help="name of username input field in login form")
    parser.add_argument("--password-field", help="name of password input field in login form")
    parser.add_argument("--authorization-endpoint")
    parser.add_argument("--redirect-uri")
    parser.add_argument("--token-endpoint")
    parser.add_argument("--scope", action="append")
    parser.add_argument("-k", "--insecure", default=True, dest="verify", action="store_false")
    parser.add_argument("url", nargs="?")

    args = parser.parse_args()
    if not args.username:
        args.username = os.environ.get("OIDC_USERNAME")
        if not args.username:
            args.username = getuser()
    if not args.password:
        args.password = os.environ.get("OIDC_PASSWORD")
        if not args.password:
            args.password = getpass("Password: ")

    auth_params = {}
    if args.scope:
        auth_params["scope"] = " ".join(s for e in args.scope
                                        for s in re.split("[ ,]*", e))
    if args.client_id:
        auth_params["client_id"] = args.client_id

    if args.client_secret:
        auth_params["client_secret"] = args.client_secret

    if args.redirect_uri:
        auth_params["redirect_uri"] = args.redirect_uri

    r = login(args.username, args.password, args.url,
              authorization_endpoint=args.authorization_endpoint,
              token_endpoint=args.token_endpoint,
              params=auth_params,
              username_field=args.username_field,
              password_field=args.password_field,
              verify=args.verify)
    if r.ok:
        print(r.text)
    else:
        print(r.text, file=sys.stderr)
        parser.exit(1, f"Login failed with status {r.status_code}")


if __name__ == '__main__':
    main()
