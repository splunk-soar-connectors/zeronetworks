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

import httpx
from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import DEFAULT_TIMEOUT_SECONDS

logger = getLogger()

# Status codes the Zero Networks API documents for every endpoint, mapped to
# messages that tell an analyst what to actually do about it.
_STATUS_HINTS = {
    401: "Unauthorized. Check that the API token on the asset is valid and has not expired.",
    403: "Forbidden. The API token is valid but lacks permission for this operation.",
    404: "Not found. The requested resource does not exist in this Zero Networks tenant.",
    429: "Rate limited by the Zero Networks API. Retry the action shortly.",
}


def build_client(base_url: str, api_token: str, verify: bool = True) -> httpx.Client:
    """Create an httpx client pre-configured for the Zero Networks portal API.

    Zero Networks expects the raw API token in the ``Authorization`` header with no
    scheme prefix, so ``token_type`` is deliberately empty.
    """
    return httpx.Client(
        base_url=base_url.rstrip("/"),
        auth=StaticTokenAuth(api_token, token_type="", header_name="Authorization"),
        timeout=DEFAULT_TIMEOUT_SECONDS,
        verify=verify,
        headers={"Accept": "application/json"},
    )


def _error_detail(response: httpx.Response) -> str:
    """Pull the most useful message out of a Zero Networks error body."""
    try:
        body = response.json()
    except ValueError:
        return response.text.strip()[:500]

    if isinstance(body, dict):
        # The API's error schema is {"error": str, "message": str}.
        detail = body.get("message") or body.get("error")
        if detail:
            return str(detail)
    return str(body)[:500]


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

    Endpoints such as quarantine return an empty JSON object on success, so a body
    that is absent or not a JSON object is normalized to ``{}``.
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

    raise_for_status(response, context)

    if not response.content:
        return {}
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
