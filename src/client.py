# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Shared HTTP plumbing for talking to the Zero Networks portal API."""

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration
from soar_sdk.logging import getLogger

from .consts import ALLOWED_URL_SCHEMES, DEFAULT_TIMEOUT_SECONDS

logger = getLogger()

# Status codes the Zero Networks API documents for every endpoint, mapped to
# messages that tell an analyst what to actually do about it.
_STATUS_HINTS = {
    401: "Unauthorized. Check that the API token on the asset is valid and has not expired.",
    403: "Forbidden. The API token is valid but lacks permission for this operation.",
    404: "Not found. The requested resource does not exist in this Zero Networks tenant.",
    429: "Rate limited by the Zero Networks API. Retry the action shortly.",
}

# How much of an unexpected response body to quote back to the analyst.
_BODY_SNIPPET_CHARS = 200


def normalize_base_url(raw: str) -> str:
    """Validate the asset's base URL and return a normalized, credential-free form.

    The result is safe to log: a URL carrying userinfo is rejected outright rather
    than stripped, because the Zero Networks API authenticates with the API token
    header and userinfo in the asset config is always a misconfiguration.
    """
    url = (raw or "").strip()
    if not url:
        raise AssetMisconfiguration("The Zero Networks base URL must not be empty.")

    # urlsplit tolerates embedded control characters and whitespace by stripping
    # some of them, which would let two different configs build the same client.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        raise AssetMisconfiguration(
            "The Zero Networks base URL must not contain whitespace or control characters."
        )

    try:
        parts = urlsplit(url)
    except ValueError as err:
        raise AssetMisconfiguration(
            f"The Zero Networks base URL is not a valid URL: {err}"
        ) from err

    if parts.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise AssetMisconfiguration(
            f"The Zero Networks base URL must use one of {sorted(ALLOWED_URL_SCHEMES)}, "
            f"not '{parts.scheme or 'no scheme'}'. Example: https://portal.zeronetworks.com/api/v1"
        )

    if parts.username or parts.password:
        raise AssetMisconfiguration(
            "The Zero Networks base URL must not embed a username or password. "
            "Authentication uses the API token on the asset."
        )

    if not parts.hostname:
        raise AssetMisconfiguration(
            "The Zero Networks base URL must include a host. "
            "Example: https://portal.zeronetworks.com/api/v1"
        )

    if parts.query or parts.fragment:
        raise AssetMisconfiguration(
            "The Zero Networks base URL must not contain a query string or fragment."
        )

    try:
        port = parts.port
    except ValueError as err:
        raise AssetMisconfiguration(
            f"The Zero Networks base URL has an invalid port: {err}"
        ) from err

    host = parts.hostname
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path.rstrip("/"), "", ""))


def build_client(base_url: str, api_token: str, verify: bool = True) -> httpx.Client:
    """Create an httpx client pre-configured for the Zero Networks portal API.

    Zero Networks expects the raw API token in the ``Authorization`` header with no
    scheme prefix, so ``token_type`` is deliberately empty.
    """
    return httpx.Client(
        base_url=normalize_base_url(base_url),
        auth=StaticTokenAuth(api_token, token_type="", header_name="Authorization"),
        timeout=DEFAULT_TIMEOUT_SECONDS,
        verify=verify,
        headers={"Accept": "application/json"},
    )


def _snippet(text: str) -> str:
    """Trim a response body down to something safe to put in an action message."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= _BODY_SNIPPET_CHARS:
        return collapsed
    return f"{collapsed[:_BODY_SNIPPET_CHARS]}..."


def _error_detail(response: httpx.Response) -> str:
    """Pull the most useful message out of a Zero Networks error body."""
    try:
        body = response.json()
    except ValueError:
        return _snippet(response.text)

    if isinstance(body, dict):
        # The API's error schema is {"error": str, "message": str}.
        detail = body.get("message") or body.get("error")
        if detail:
            return str(detail)
    return _snippet(str(body))


def raise_for_status(response: httpx.Response, context: str) -> None:
    """Translate a non-2xx Zero Networks response into an ActionFailure."""
    if response.is_success:
        return

    parts = [f"{context} failed with HTTP {response.status_code}"]
    if hint := _STATUS_HINTS.get(response.status_code):
        parts.append(hint)
    if detail := _error_detail(response):
        parts.append(f"API response: {detail}")

    raise ActionFailure(" ".join(parts))


def request_json(
    client: httpx.Client,
    method: str,
    url: str,
    context: str,
    **kwargs: Any,
) -> dict:
    """Send a request and return the decoded JSON body, failing the action on error.

    An absent body is normalized to ``{}``, since the quarantine endpoints document
    an empty success response. A body that is present but is not a JSON object fails
    the action instead of being silently discarded: treating it as ``{}`` would make
    ``search asset`` report a confident "no asset found" for what is really an
    unreadable response.
    """
    try:
        response = client.request(method, url, **kwargs)
    except httpx.TimeoutException as err:
        raise ActionFailure(
            f"{context} timed out after {DEFAULT_TIMEOUT_SECONDS}s. "
            "Check the Zero Networks base URL and network connectivity."
        ) from err
    except httpx.HTTPError as err:
        raise ActionFailure(
            f"{context} could not reach the Zero Networks API: {err}"
        ) from err

    logger.debug("%s %s -> %s", method.upper(), url, response.status_code)

    raise_for_status(response, context)

    # A genuinely empty body is the documented success shape for the quarantine
    # endpoints. Whitespace-only counts as empty.
    if not response.content.strip():
        return {}

    try:
        body = response.json()
    except ValueError as err:
        raise ActionFailure(
            f"{context} returned HTTP {response.status_code} with a body that is not valid JSON. "
            f"Response starts: {_snippet(response.text)}"
        ) from err

    if not isinstance(body, dict):
        raise ActionFailure(
            f"{context} returned HTTP {response.status_code} with a JSON "
            f"{type(body).__name__} where an object was expected. "
            f"Response starts: {_snippet(response.text)}"
        )

    return body
