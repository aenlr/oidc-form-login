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
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum, auto
from getpass import getpass, getuser
from re import RegexFlag
from typing import Any, Self, cast
from urllib.parse import parse_qs, urljoin

import bs4
import keyring
import requests
from bs4 import BeautifulSoup
from keyring.credentials import SimpleCredential
from keyring.errors import InitError, NoKeyringError
from requests import Response, Session
from urllib3.util import parse_url
from urllib3.util.url import Url


class AuthResultMode(StrEnum):
    """When to consider authentication finished."""

    LAST = auto()
    """Stop when there are no more navigations."""

    POST_REDIRECT_URI = auto()
    """Like LAST but only if redirect_uri was requested"""

    PRE_REDIRECT_URI = auto()
    """Stop before requesting the authorization redirect_uri URL"""

    TOKEN_RESPONSE = auto()
    """Stop before requesting the authorization redirect uri, then
       request and return the token response directly"""


CredentialProvider = Callable[[str], str | None]


@dataclass
class AuthRequest:
    """Authentication request settings."""

    mode: AuthResultMode = AuthResultMode.POST_REDIRECT_URI
    """Authentication result to return."""

    verify: bool = True
    """TLS verification is disabled if False"""

    url: str | None = None
    """Start URL"""

    username: str | CredentialProvider | None = None
    """Username or callable"""

    password: str | CredentialProvider | None = None
    """Password string or callable"""

    otp: str | CredentialProvider | None = None
    """OTP string or callable"""

    click_before: list[str] = field(default_factory=list)
    """List of elements to click before authentication"""

    click_after: list[str] = field(default_factory=list)
    """List of elements to click after authentication"""

    submit_field: list[str] = field(default_factory=list)
    """List of element names, ids or selectors for submit button"""
    username_field: list[str] = field(default_factory=list)
    """List of element names, ids or selectors for username field"""
    password_field: list[str] = field(default_factory=list)
    """List of element names, ids or selectors for password field"""
    otp_field: list[str] = field(default_factory=list)
    """List of element names, ids or selectors for OTP field"""

    issuer: str | None = None
    """OIDC issuer"""

    authorization_endpoint: str | None = None
    """OIDC authorization endpoint"""

    params: dict[str, str] = field(default_factory=dict)
    """OIDC authorization request params"""

    token_endpoint: str | None = None
    """OIDC token endpoint"""

    client_secret: str | None = None
    """Client secret"""


@dataclass
class NavHistory:
    """Authentication request history"""

    url: str
    method: str
    request_headers: dict[str, str] = field(default_factory=dict)
    data: object | None = None

    status: int = 0
    response_headers: Mapping[str, str] = field(default_factory=dict)


@dataclass
class FormSubmission:
    """Form submission data."""

    action: str
    enctype: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] | None = None
    data: dict[str, str] | None = None


@dataclass
class AuthResult:
    """Authentication result."""

    session: Session
    """Request session including cookies"""
    response: Response | None
    """Authorization request"""
    auth_request: dict[str, str] = field(default_factory=dict)
    """Last response processed"""
    auth_response: dict[str, str] = field(default_factory=dict)
    """Parameters provided to redirect uri if any"""
    token_response: dict[str, Any] = field(default_factory=dict)
    """Returned when a token response is observed"""

    history: list[NavHistory] = field(default_factory=list)
    """Request history"""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.session.close()


class CredentialMissing(Exception):
    """Credential missing."""


class LoginError(Exception):
    """Login error exception."""

    def __init__(self, msg: str, result: AuthResult) -> None:
        super().__init__(msg)
        self.result = result
        result.session.close()


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


def is_html_response(r: Response) -> bool:
    """Check if a response is HTML."""
    content_type = parse_content_type(r)
    return content_type in ("text/html", "application/xhtml+xml") and r.text.lstrip().startswith(
        "<"
    )


def _is_input_type_text(f):
    return f.name == "input" and f.get("type", "text").lower() == "text"


def _is_input_type_password(f):
    return f.name == "input" and f.get("type", "text").lower() == "password"


def _is_input_autocomplete_username(f):
    autocomplete = f.get("autocomplete")
    return f.has_attr("name") and autocomplete == "username"


def _is_input_possibly_username(f: bs4.Tag):
    autocomplete = f.get("autocomplete")
    if autocomplete and autocomplete != "off":
        return False

    name = cast(str, f.get("name"))
    if not name:
        return False
    return name.lower() in ("username", "user", "login")


def _is_input_autocomplete_password(f):
    autocomplete = f.get("autocomplete")
    return autocomplete == "current-password"


def _is_input_possibly_password(f):
    autocomplete = f.get("autocomplete")
    if autocomplete and autocomplete != "off":
        return False

    name = f.get("name")
    if not name:
        return False
    return name in ("password", "passwd", "pass", "pwd")


def _prepare_submit_form(
    req: AuthRequest,
    res: AuthResult,
    soup: BeautifulSoup,
    form: bs4.Tag,
    fields: list[bs4.Tag],
    *,
    username_field: bs4.Tag | None = None,
    password_field: bs4.Tag | None = None,
    otp_field: bs4.Tag | None = None,
) -> FormSubmission | None:
    assert res.response is not None
    url = parse_url(res.response.url)

    submit_button = _guess_submit_button(soup, fields, req.submit_field)
    if not submit_button and req.submit_field:
        return None

    if submit_button and submit_button.has_attr("formaction"):
        action = str(submit_button["formaction"])
    else:
        action = str(form["action"]) if form.has_attr("action") else str(url)
    if submit_button and submit_button.has_attr("formenctype"):
        enctype = str(submit_button["formenctype"])
    else:
        enctype = (
            str(form["enctype"])
            if form.has_attr("enctype")
            else "application/x-www-form-urlencoded"
        )
    if submit_button and submit_button.has_attr("formmethod"):
        method = str(submit_button["formmethod"]).upper()
    else:
        method = str(form["method"]).upper() if form.has_attr("method") else "GET"

    baseurl = url_no_query(url)
    action = urljoin(baseurl, action)
    payload = {}
    for f in fields:
        if not f.has_attr("name"):
            continue
        if f.has_attr("disabled"):
            continue

        name = cast(str, f["name"])
        if f == username_field and req.username is not None:
            if isinstance(req.username, str):
                payload[name] = req.username
            elif username := req.username(baseurl):
                payload[name] = username
        elif f == password_field and req.password is not None:
            if isinstance(req.password, str):
                payload[name] = req.password
            elif password := req.password(baseurl):
                payload[name] = password
        elif f == otp_field and req.otp is not None:
            if isinstance(req.otp, str):
                payload[name] = req.otp
            elif otp := req.otp(baseurl):
                payload[name] = otp
        elif f == submit_button:
            if cast(str, f.get("type", "submit")).lower() == "submit":
                payload[name] = cast(str, f.get("value", f.get_text()))
        elif f.name == "textarea":
            payload[name] = f.get_text()
        elif f.name == "select":
            for opt in f.find_all("option"):
                if opt.has_attr("disabled"):
                    continue
                if opt.has_attr("selected"):
                    payload[name] = cast(str, opt.get("value", f.get_text()))
                    break
        elif f.get("type") == "checkbox":
            if f.has_attr("checked"):
                payload[name] = cast(str, f.get("value", ""))
        else:
            payload[name] = cast(str, f.get("value", ""))

    headers = {}
    if method == "POST":
        if enctype != "application/x-www-form-urlencoded":
            raise ValueError(f"Unsupported form encoding: {enctype}")
        headers["content-type"] = enctype
    return FormSubmission(
        action=action,
        method=method,
        enctype=enctype,
        headers=headers,
        params=payload if method == "GET" else None,
        data=payload if method == "POST" else None,
    )


# pylint: disable=R0913,R0914
def _submit_form(res: AuthResult, submission: FormSubmission) -> Response:
    hist = NavHistory(
        submission.action,
        submission.method,
        request_headers=submission.headers,
        data=submission.params or submission.data,
    )
    res.history.append(hist)
    r = res.session.request(
        submission.method,
        submission.action,
        params=submission.params,
        data=submission.data,
        headers=submission.headers,
        allow_redirects=False,
    )
    res.response = r
    hist.response_headers = r.headers
    hist.status = r.status_code
    hist.url = r.url
    return r


def _find_form_elements(soup: BeautifulSoup, form: bs4.Tag) -> Generator[bs4.Tag]:
    def _is_skipped_element(b):
        # button element that is not a submit button
        if b.name == "button":
            return _get_str_lower(b, "type", "submit") != "submit"
        # input element that is a reset button
        if b.name == "input":
            return _get_str_lower(b, "type") == "reset"
        # submit button or other form element
        return False

    form_id = cast(str | None, form.get("id"))
    # Find elements without form id nested in this form
    for e in form.find_all(["input", "textarea", "select", "button"]):
        if _is_skipped_element(e):
            continue
        if not e.has_attr("form"):
            yield e

    if form_id:
        # Add elements with form="<id>" attributes
        for e in soup.find_all(["input", "textarea", "select", "button"], {"form": form_id}):
            if not _is_skipped_element(e):
                yield e


def _find_form_element(soup: BeautifulSoup, specs: list[str]) -> bs4.Tag | None:
    for spec in specs:
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", spec):
            e = soup.find("input", {"name": spec}) or soup.find("input", {"id": spec})
        else:
            e = soup.select_one(spec)
        if e:
            return e
    return None


def _get_str_lower(f: bs4.Tag, attr: str, default: str | None = None) -> str | None:
    v = f.get(attr)
    return default if v is None else cast(str, v).lower()


def _guess_submit_button(
    soup: BeautifulSoup, fields: list[bs4.Tag], specs: list[str]
) -> bs4.Tag | None:
    if specs:
        btn = _find_form_element(soup, specs)
        if btn:
            return btn

    buttons = []  # type: list[bs4.Tag]
    for f in fields:
        if (
            f.name == "input"
            and _get_str_lower(f, "type") == "submit"
            or f.name == "button"
            and _get_str_lower(f, "type", "submit") == "submit"
        ):
            buttons.append(f)

    if len(buttons) == 1:
        return buttons[0]

    return None


def _guess_username_field(fields: list[bs4.Tag]) -> bs4.Tag | None:
    for f in fields:
        if _is_input_autocomplete_username(f):
            return f

    for f in fields:
        if _is_input_possibly_username(f):
            return f

    return None


def _guess_password_field(fields: list[bs4.Tag]) -> bs4.Tag | None:
    for f in fields:
        if _is_input_autocomplete_password(f):
            return f

    for f in fields:
        if _is_input_possibly_password(f):
            return f

    return None


def _guess_otp_field(fields: list[bs4.Tag]) -> bs4.Tag | None:
    for f in fields:
        if f.get("autocomplete") == "one-time-code":
            return f

    return None


def _process_forms(req: AuthRequest, res: AuthResult) -> FormSubmission | None:
    assert res.response is not None
    soup = BeautifulSoup(res.response.text, features="html.parser")
    forms = list(soup("form"))
    for form in forms:
        fields = list(_find_form_elements(soup, form))
        text_inputs = [f for f in fields if _is_input_type_text(f)]
        password_inputs = [f for f in fields if _is_input_type_password(f)]

        # Username field
        if req.username_field:
            uf = _find_form_element(soup, req.username_field)
            if not uf:
                continue
        else:
            uf = _guess_username_field(text_inputs)

        # Password field
        if req.password_field:
            pf = _find_form_element(soup, req.password_field)
            if not pf:
                continue
        else:
            pf = _guess_password_field(password_inputs)

        # OTP field
        if req.otp_field:
            of = _find_form_element(soup, req.otp_field)
        else:
            of = _guess_otp_field(text_inputs)

        # If no fields were detected and there is
        # exactly one form with one field for each
        # input then use those fields.
        if not (uf and pf) and len(forms) == 1:
            if not uf and len(text_inputs) == 1:
                uf = text_inputs[0]
            if not pf and len(password_inputs) == 1:
                pf = password_inputs[0]
        elif not uf and not pf:
            continue

        return _prepare_submit_form(
            req,
            res,
            soup=soup,
            form=form,
            username_field=uf,
            password_field=pf,
            otp_field=of,
            fields=fields,
        )

    return None


def _collect_nav_links(url: str, elements: bs4.ResultSet[bs4.Tag]) -> list[str]:
    links = []  # type: list[str]
    base = parse_url(url)
    for a in elements:
        if (href := a.get("href")) and isinstance(href, str) and not href.startswith("#"):
            href = urljoin(str(url), href)
            target = parse_url(href)
            if target.host != base.host or target.path != base.path:
                links.append(href)
    return links


def _find_pre_auth_nav(html: str, url: str, clicks: list[str]) -> str | None:
    soup = BeautifulSoup(html, features="html.parser")
    if clicks:
        click_target = clicks[0]
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", click_target):
            elements = soup.find_all("a", id=click_target) or soup.select(click_target)
        else:
            elements = soup.select(click_target)
        if elements:
            click = click_target
        else:
            # For pre-auth we try any link if nothing matched user request
            click = None
            elements = soup.find_all("a")
    else:
        if soup.find("form"):
            return None
        click = None
        elements = soup.find_all("a")

    links = _collect_nav_links(url, elements)

    if len(links) != 1:
        return None

    if click:
        del clicks[0]
    return links[0]


def _find_post_auth_nav(html: str, url: str, clicks: list[str]) -> str | None:
    if not clicks:
        # For post-auth we do not attempt to follow anything but what
        # the user requested.
        return None

    soup = BeautifulSoup(html, features="html.parser")
    click = clicks[0]
    if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", click):
        elements = soup.find_all("a", id=click) or soup.select(click)
    else:
        elements = soup.select(click)

    links = _collect_nav_links(url, elements)

    if len(links) != 1:
        return None

    del clicks[0]
    return links[0]


def _fetch_oidc_discovery(req: AuthRequest):
    if not req.issuer:
        return
    url = f"{req.issuer}/.well-known/openid-configuration"
    oidc_config = requests.get(url, timeout=10).json()  # dict[str, Any]
    if not req.authorization_endpoint:
        req.authorization_endpoint = oidc_config.get("authorization_endpoint")
    if not req.token_endpoint:
        req.token_endpoint = oidc_config.get("token_endpoint")


def _normalize_start_url(req: AuthRequest) -> tuple[str, Url | None]:
    if req.url:
        start_url = parse_url(req.url)
        if url_no_query(start_url) == req.authorization_endpoint:
            req.authorization_endpoint = req.url
            req.url = None

    if req.url:
        return req.url, None

    if not req.authorization_endpoint:
        raise ValueError("URL or authorization endpoint is required")
    start_url = parse_url(req.authorization_endpoint)
    query = start_url.query or ""

    if "response_type" not in req.params:
        req.params["response_type"] = "code"

    if "scope" not in req.params:
        req.params["scope"] = "openid profile email"

    for k, v in req.params.items():
        query = replace_query_param(query, k, v, encode=k not in ("state", "nonce"))

    start_url = start_url._replace(query=query)
    auth_url = start_url
    return str(start_url), auth_url


def _is_auth_request_params(params: dict[str, str]) -> bool:
    return all(p in params for p in ("redirect_uri", "client_id", "scope"))


_AUTH_TOKEN_PARAMS = "access_token", "id_token", "refresh_token"
_AUTH_RESPONSE_PARAMS = _AUTH_TOKEN_PARAMS + ("error", "code")


def _check_redirect_to_rp(req: AuthRequest, res: AuthResult, url: str) -> bool:
    path, params = _parse_response_params(req, url)
    return _check_auth_response(req, res, url, path, params)


def _check_form_post_to_rp(req: AuthRequest, res: AuthResult, submit: FormSubmission) -> bool:
    if req.params.get("response_mode") != "form_post":
        return False

    if submit.params:
        params = submit.params
    elif submit.data:
        params = submit.data
    else:
        return False

    path = url_no_query(parse_url(submit.action))
    return _check_auth_response(req, res, submit.action, path, params)


def _check_auth_response(
    req: AuthRequest, res: AuthResult, url: str, path: str, params: dict[str, str]
) -> bool:
    # Check that this is a request to the expected endpoint
    if path != req.params.get("redirect_uri"):
        return False

    # Check for parameters indicating an OIDC response
    if not any(p in params for p in _AUTH_RESPONSE_PARAMS):
        return False

    # Check for matching state in response to detect redirect mismatches.
    if req.params.get("state") != params.get("state"):
        return False

    res.auth_response = params
    if any(p in params for p in _AUTH_TOKEN_PARAMS):
        res.token_response = dict(params)
        for p in ("expires_in", "expires_at", "refresh_expires_in", "refresh_expires_at"):
            if p in params:
                res.token_response[p] = int(params[p])

    if "error" in params:
        raise LoginError(f"Authorization error: {params['error']}", res)

    if req.mode == AuthResultMode.PRE_REDIRECT_URI:
        return True

    if "code" in params and req.mode == AuthResultMode.TOKEN_RESPONSE:
        # Return token response to caller
        if not req.token_endpoint:
            raise ValueError("Missing token_endpoint")
        if not "client_id" in req.params:
            raise ValueError("Missing client_id")
        token_request = {
            "grant_type": "authorization_code",
            "client_id": req.params["client_id"],
            "code": params["code"],
            "redirect_uri": req.params["redirect_uri"],
        }
        for p in ("scope", "code_verifier"):
            if p in req.params:
                token_request[p] = req.params[p]
        if req.client_secret is not None:
            token_request["client_secret"] = req.client_secret
        headers = {"content-type": "application/x-www-form-urlencoded"}
        r = res.session.post(req.token_endpoint, token_request, headers=headers)
        res.response = r
        res.token_response = r.json()
        if r.ok:
            return True
        if "error" in res.token_response:
            raise LoginError(f"Token request error: {res.token_response['error']}", res)
        raise LoginError(f"Token request error: {r.status_code}", res)

    if req.mode == AuthResultMode.TOKEN_RESPONSE:
        if not res.token_response:
            raise LoginError(f"No token response received at {url}", res)
        return True

    return False


def _split_url_params(no_query: str) -> tuple[Url, str, dict[str, str]]:
    """Parse and split a URL into host+path and query parameters."""
    parsed = parse_url(no_query)
    params = {k: v[0] for k, v in parse_qs(parsed.query or "").items()}
    no_query = url_no_query(parsed)
    return parsed, no_query, params


def _parse_response_params(req: AuthRequest, url: str) -> tuple[str, dict[str, str]]:
    """Parse an OIDC response URL (fragment or query) and separate parameters from URL."""
    response_mode = req.params.get("response_mode")
    if response_mode == "fragment":
        parsed = parse_url(url)
        params = {k: v[0] for k, v in parse_qs(parsed.fragment or "").items()}
        return url_no_query(parsed), params

    if response_mode is None or response_mode == "query":
        parsed = parse_url(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query or "").items()}
        return url_no_query(parsed), params

    return url, {}


def _find_autosubmit_form(soup: BeautifulSoup) -> bs4.Tag | None:
    body = soup.find("body")
    if not body:
        return None
    onload = body.get("onload")
    if not isinstance(onload, str):
        return None
    m = re.match(r"""document.forms\[["']([a-zA-Z0-9_-]+)["']]""", onload)
    if m:
        form_id = m.group(1)
        return soup.find("form", {"id": form_id})

    forms = list(body.find_all("form"))
    m = re.match(r"""document.forms\[(\d+)]""", onload)
    if not m:
        return None

    form_idx = int(m.group(1))
    if form_idx < len(forms):
        return forms[form_idx]
    if len(forms) == 1:
        return forms[0]
    return None


def _check_autosubmit_form(
    req: AuthRequest, res: AuthResult, r: Response
) -> FormSubmission | None:
    if r.is_redirect or not is_html_response(r):
        return None

    soup = BeautifulSoup(r.text, features="html.parser")
    form = _find_autosubmit_form(soup)
    if not form:
        return None
    fields = list(_find_form_elements(soup, form))
    return _prepare_submit_form(req, res, soup, form, fields)


def _get_with_history(res: AuthResult, url: str):
    hist = NavHistory(url, "GET")
    res.history.append(hist)
    r = res.session.get(url, allow_redirects=False)
    hist.response_headers = r.headers
    hist.status = r.status_code
    res.response = r
    return r


def _check_response_status(res: AuthResult):
    if res.response is not None and not res.response.ok:
        raise LoginError(
            f"Login failed at {res.response.url} with HTTP {res.response.status_code}", res
        )


# pylint: disable=R0912,R0915
def login(req: AuthRequest) -> AuthResult:
    """Form login by username and password.

    Any redirects are followed until the form web page is reached.
    Then the form is then posted with the user credentials.
    Redirects are once again followed until the final redirect URL is
    reached (as specified by the OIDC redirect_uri parameter).
    The authorization code

    OTP is not currently supported.

    """
    _fetch_oidc_discovery(req)
    url, auth_url = _normalize_start_url(req)
    session = Session()
    session.verify = req.verify
    auth_requested = False
    res = AuthResult(session, response=None)
    click_before = list(req.click_before)
    while True:
        if _check_redirect_to_rp(req, res, url):
            # PRE_REDIRECT_URI or TOKEN_RESPONSE
            return res

        if not auth_requested:
            target, path, params = _split_url_params(url)
            if _is_auth_request_params(params) and (
                not auth_url or path == req.authorization_endpoint
            ):
                # Detected authorization endpoint. Save parameters.
                auth_requested = True
                auth_url = target
                req.authorization_endpoint = path
                req.params = dict(params)
                res.auth_request = req.params

        r = _get_with_history(res, url)
        while True:
            submit = _check_autosubmit_form(req, res, r)
            if not submit:
                break
            if _check_form_post_to_rp(req, res, submit):
                return res
            r = _submit_form(res, submit)

        _check_response_status(res)

        if r.is_redirect:
            url = urljoin(url, r.headers["location"])
        elif is_html_response(r):
            link = _find_pre_auth_nav(r.text, url, click_before)
            if not link:
                break
            url = link
        elif req.mode == AuthResultMode.LAST or res.auth_response:
            # LAST or POST_REDIRECT_URI
            return res
        else:
            raise LoginError(f"Invalid response received at {url}", res)

    # Stopped at some URL that returned an HTML response.
    assert res.response is not None
    assert is_html_response(res.response)

    # Process login form
    submit = _process_forms(req, res)
    if submit:
        while submit:
            if _check_form_post_to_rp(req, res, submit):
                return res
            r = _submit_form(res, submit)
            submit = _check_autosubmit_form(req, res, r)
        url = r.url
        _check_response_status(res)

    # Process post login navigation
    click_after = list(req.click_after)
    while True:
        if r.is_redirect:
            url = urljoin(url, r.headers["location"])
        elif click_after and is_html_response(r):
            link = _find_post_auth_nav(r.text, url, click_after)
            if not link:
                break
            url = link
        else:
            break

        if _check_redirect_to_rp(req, res, url):
            # PRE_REDIRECT_URI or TOKEN_RESPONSE
            return res

        r = _get_with_history(res, url)
        while True:
            submit = _check_autosubmit_form(req, res, r)
            if not submit:
                break
            if _check_form_post_to_rp(req, res, submit):
                return res
            r = _submit_form(res, submit)
        url = r.url
        _check_response_status(res)

    if req.mode == AuthResultMode.POST_REDIRECT_URI and not res.auth_response:
        raise LoginError(f"Login stopped at {url} before reaching redirect url", res)

    return res


def prompt_username(username: str | None = None) -> str:
    """Prompt for username."""
    if username is None:
        try:
            username = getuser()
        except OSError:
            pass

    try:
        prompt = f"Username ({username}): " if username else "Username: "
        print(prompt, flush=True, end="")
        resolved_username = sys.stdin.readline().strip()
        if resolved_username:
            return resolved_username
        if username:
            return username

        raise CredentialMissing("No username provided")
    except EOFError as e:
        raise CredentialMissing("EOF") from e


def prompt_stdin_password(args: Namespace):
    """Prompt for password if - is set."""
    if args.password == "-":
        if sys.stdin.isatty():
            args.password = getpass("Password: ")
        else:
            print("Password: ", end="", flush=True)
            args.password = sys.stdin.readline().rstrip()


def user_and_pass(args: Namespace, url: str = "") -> tuple[str | None, str | None]:
    """Set/request username and password properties.

    If username and/or password are not set they are filled in
    by OIDC_USERNAME and OIDC_PASSWORD environment variables.

    The user is prompted if a value is not provided explicitly
    or by environment variable.

    :param args: Result of ArgumentParser.parse_args(). Modified in place.
    :param url: url for which to save/read credentials
    """
    usr = args.username
    psw = args.password
    if psw:
        # Explicit user credentials have priority over everything else
        if not usr:
            try:
                usr = getuser()
            except OSError:
                usr = prompt_username("")
            args.username = usr
        return usr, psw

    single_credential = getattr(args, "single_credential", False)
    cached = getattr(args, "credential", None)  # type: keyring.credentials.Credential | None
    if cached and (single_credential or url == args.credential_url):
        # Reuse already resolved credentials if it is for the same URL
        return cached.username, cached.password

    use_keyring = url and args.keyring
    if use_keyring:
        try:
            keyring.get_keyring()
        except (InitError, NoKeyringError):
            args.keyring = False
            use_keyring = False

    args.credential_url = url
    if use_keyring and usr:
        cred = keyring.get_credential(url, usr)
        if cred:
            args.credential = cred
            return cred.username, cred.password

    prompted_user = False
    printed_url = False
    if usr is None:
        if use_keyring:
            cred = keyring.get_credential(url, None)
            if cred:
                args.credential = cred
                return cred.username, cred.password

        if len(args.url) > 1 and not single_credential:
            printed_url = True
            print(f"Authenticating at {url}")
            # Reuse last username as default.
            prompted_user = True
            usr = prompt_username(cached.username if cached else None)
        else:
            # Single url/credential and no explicit username. Use system username.
            try:
                usr = getuser()
            except OSError:
                prompted_user = True
                usr = prompt_username()

    if len(args.url) > 1 and not printed_url:
        print(f"Authenticating at {url}", flush=True)

    # Ask user for password and store it.
    if cached and cached.username == usr:
        psw = getpass("Password (****): ")
    else:
        psw = getpass("Password: " if prompted_user else f"Password ({usr}): ")

    if use_keyring:
        keyring.set_password(url, usr, psw)

    args.credential = SimpleCredential(usr, psw)
    return usr, psw


def request_otp(args: Namespace) -> str:
    """Set otp properties.

    Get otp from OIDC_OTP environment variable or by asking for input
    if otp is not explicitly set.

    :param args: Result of ArgumentParser.parse_args(). Modified in place.
    """
    if not args.otp:
        print("OTP: ", flush=True, end="")
        args.otp = sys.stdin.readline().strip()
    return args.otp


def _print_dict(d: dict[str, str], file=sys.stdout):
    for k, v in d.items():
        print(f"- {k}={v}", file=file)


def _print_token_response(r: AuthResult, file=sys.stdout):
    print("Token response:")
    _print_dict(r.token_response, file)


def _print_auth_request(r: AuthResult, file=sys.stdout):
    print("Authorization request:")
    _print_dict(r.auth_request, file)


def _print_auth_response(r: AuthResult, file=sys.stdout):
    print("Authorization response:")
    _print_dict(r.auth_response, file)


def _print_result(r: AuthResult, file=sys.stdout):
    sep = ""
    if r.auth_request:
        _print_auth_request(r, file)
        sep = "\n"

    if r.auth_response and (not r.token_response or "code" in r.auth_response):
        print(sep, end="", file=file)
        _print_auth_response(r, file)
        sep = "\n"

    if r.token_response:
        print(sep, end="", file=file)
        _print_token_response(r, file)
        sep = "\n"

    if r.history:
        for h in r.history:
            print(sep, end="", file=file)
            print(f"> {h.method} {h.url}", file=file)
            if h.request_headers:
                for k, v in h.request_headers.items():
                    print(f"> {k}: {v}", file=file)
            if h.data:
                if isinstance(h.data, dict):
                    for k, v in h.data.items():
                        if re.match("pass|secret|credential|psw", k, RegexFlag.IGNORECASE):
                            print(f"  {k}=[MASKED]", file=file)
                        else:
                            print(f"  {k}={v}", file=file)
                else:
                    print(f"\n  {h.data}", file=file)
            print(f"< HTTP {h.status}", file=file)
            if h.response_headers:
                for k, v in h.response_headers.items():
                    print(f"< {k}: {v}", file=file)
            sep = "\n\n"

    if r.response is not None and r.response.text:
        if r.history:
            print(file=file)
        else:
            print(sep, end="", file=file)
            print(f"{r.response.url}:", file=file)
        print(r.response.text, file=file)


def common_args() -> ArgumentParser:
    parser = ArgumentParser(add_help=False)
    parser.add_argument(
        "-q", "--quiet", action="store_false", dest="verbose", help="print nothing unless needed"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", dest="verbose", help="verbose operation"
    )
    parser.add_argument(
        "-i",
        "--interactive",
        dest="interactive",
        default=True,
        action="store_true",
        help="confirm command execution",
    )
    parser.add_argument(
        "-u",
        "--username",
        metavar="USER",
        dest="username",
        default=os.environ.get("OIDC_USERNAME"),
        help="username (env: OIDC_USERNAME)",
    )
    parser.add_argument(
        "-p",
        "--password",
        metavar="PASS",
        dest="password",
        default=os.environ.get("OIDC_PASSWORD"),
        help="password (env: OIDC_PASSWORD)",
    )
    parser.add_argument(
        "--no-keyring",
        dest="keyring",
        default=os.environ.get("OIDC_KEYRING") in ("true", "1", None),
        action="store_false",
        help="do not store credentials (env: OIDC_KEYRING)",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        default=True,
        dest="verify",
        action="store_false",
        help="skip TLS host verification",
    )

    return parser


def username_provider(args: Namespace):
    """Return a function that returns the username for a URL."""

    def username(u: str):
        return user_and_pass(args, u)[0]

    return username


def password_provider(args: Namespace):
    """Return a function that returns the password for a URL."""

    def password(u: str):
        return user_and_pass(args, u)[1]

    return password


def otp_provider(args: Namespace):
    """Return a function that returns the OTP for a URL."""

    def otp(_):
        return request_otp(args)

    return otp


def main():
    # pylint: disable=R0801
    """Main entrypoint for oidc-form-login utility."""

    parser = ArgumentParser(parents=[common_args()])
    parser.add_argument("--client-id", default=os.environ.get("OIDC_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.environ.get("OIDC_CLIENT_SECRET"))
    parser.add_argument("--otp", "--totp", default=os.environ.get("OIDC_OTP"))
    parser.add_argument(
        "--username-field", nargs="*", help="name of username input field in login form"
    )
    parser.add_argument(
        "--password-field", nargs="*", help="name of password input field in login form"
    )
    parser.add_argument("--otp-field", nargs="*", help="name of OTP input field in login form")
    parser.add_argument(
        "--mode", default=AuthResultMode.LAST.value, choices=[e.value for e in AuthResultMode]
    )
    parser.add_argument("--issuer", metavar="URL")
    parser.add_argument("--authorization-endpoint", metavar="URL")
    parser.add_argument("--redirect-uri", metavar="URL")
    parser.add_argument("--token-endpoint", metavar="URL")
    parser.add_argument("--scope", nargs="*")
    parser.add_argument("--state")
    parser.add_argument("--click-before", action="append", default=[])
    parser.add_argument("--click-after", action="append", default=[])
    parser.add_argument("url", help="login start page")

    args = parser.parse_args()
    prompt_stdin_password(args)

    req = AuthRequest(
        url=args.url,
        mode=AuthResultMode[args.mode.upper()],
        username=username_provider(args),
        password=password_provider(args),
        otp=otp_provider(args),
        issuer=args.issuer,
        authorization_endpoint=args.authorization_endpoint,
        token_endpoint=args.token_endpoint,
        click_before=args.click_before,
        click_after=args.click_after,
        username_field=args.username_field,
        password_field=args.password_field,
        otp_field=args.otp_field,
        verify=args.verify,
    )

    if args.scope:
        req.params["scope"] = " ".join(s for e in args.scope for s in re.split("[ ,]*", e))
    if args.client_id:
        req.params["client_id"] = args.client_id
    if args.state:
        req.params["state"] = args.state
    if args.client_secret:
        req.client_secret = args.client_secret
    if args.redirect_uri:
        req.params["redirect_uri"] = args.redirect_uri

    try:
        with login(req) as r:
            _print_result(r)
    except LoginError as e:
        print(str(e), file=sys.stderr)
        _print_result(e.result, file=sys.stderr)
        parser.exit(1)


if __name__ == "__main__":
    main()
