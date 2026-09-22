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
import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.client import build_client, raise_for_status, request_json


class TestBuildClient:
    def test_sends_raw_token_in_authorization_header(self):
        # Zero Networks expects the bare token, with no "Bearer " prefix.
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={})

        client = build_client("https://portal.zeronetworks.com/api/v1", "secret-token")
        client._transport = httpx.MockTransport(handler)
        with client:
            client.get("/assets/statistics")

        assert captured[0].headers["authorization"] == "secret-token"

    def test_joins_endpoints_onto_a_base_url_with_a_trailing_slash(self):
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={})

        client = build_client("https://portal.zeronetworks.com/api/v1/", "t")
        client._transport = httpx.MockTransport(handler)
        with client:
            client.get("/assets/statistics")

        assert (
            str(captured[0].url)
            == "https://portal.zeronetworks.com/api/v1/assets/statistics"
        )


class TestRaiseForStatus:
    def test_passes_through_success(self):
        raise_for_status(httpx.Response(200, json={}), "Something")

    @pytest.mark.parametrize(
        ("status", "hint"),
        [
            (401, "has not expired"),
            (403, "lacks permission"),
            (404, "does not exist"),
            (429, "Retry the action shortly"),
        ],
    )
    def test_adds_an_actionable_hint(self, status, hint):
        response = httpx.Response(status, json={"error": "e", "message": "detail here"})
        with pytest.raises(ActionFailure) as err:
            raise_for_status(response, "Quarantine of asset a:a:JF2xro6g")
        assert hint in str(err.value)
        assert "detail here" in str(err.value)
        assert "Quarantine of asset a:a:JF2xro6g" in str(err.value)

    def test_handles_a_non_json_error_body(self):
        response = httpx.Response(500, text="<html>gateway error</html>")
        with pytest.raises(ActionFailure, match="gateway error"):
            raise_for_status(response, "Something")

    def test_handles_an_empty_error_body(self):
        with pytest.raises(ActionFailure, match="HTTP 500"):
            raise_for_status(httpx.Response(500), "Something")


class TestRequestJson:
    def _client(self, handler) -> httpx.Client:
        return httpx.Client(
            base_url="https://portal.zeronetworks.com/api/v1",
            transport=httpx.MockTransport(handler),
        )

    def test_returns_decoded_body(self):
        client = self._client(
            lambda _r: httpx.Response(200, json={"assetId": "a:a:JF2xro6g"})
        )
        assert request_json(client, "GET", "/assets/searchId", "Search") == {
            "assetId": "a:a:JF2xro6g"
        }

    def test_normalizes_an_empty_body_to_an_empty_dict(self):
        # The quarantine endpoint returns an empty response on success.
        client = self._client(lambda _r: httpx.Response(200))
        assert (
            request_json(client, "PUT", "/assets/x/actions/quarantine", "Quarantine")
            == {}
        )

    def test_normalizes_a_non_object_body_to_an_empty_dict(self):
        client = self._client(lambda _r: httpx.Response(200, json=[1, 2, 3]))
        assert request_json(client, "GET", "/whatever", "Something") == {}

    def test_converts_a_timeout_into_an_action_failure(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out", request=request)

        client = self._client(handler)
        with pytest.raises(ActionFailure, match="timed out after"):
            request_json(client, "GET", "/assets/statistics", "Connectivity test")

    def test_converts_a_connection_error_into_an_action_failure(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host", request=request)

        client = self._client(handler)
        with pytest.raises(
            ActionFailure, match="could not reach the Zero Networks API"
        ):
            request_json(client, "GET", "/assets/statistics", "Connectivity test")
