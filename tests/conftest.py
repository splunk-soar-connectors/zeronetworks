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
from collections.abc import Callable

import httpx
import pytest

from src.app import Asset, app


@pytest.fixture
def asset() -> Asset:
    return Asset(
        base_url="https://portal.zeronetworks.com/api/v1",
        api_token="test-token",
        verify_server_cert=True,
    )


class ActionRun:
    """The outcome of invoking an action against a mocked Zero Networks API."""

    def __init__(self, succeeded: bool, requests: list[httpx.Request], result) -> None:
        self.succeeded = succeeded
        self.requests = requests
        self.result = result

    @property
    def request(self) -> httpx.Request:
        """The single request the action made, asserting there was exactly one."""
        assert len(self.requests) == 1, f"expected 1 request, got {len(self.requests)}"
        return self.requests[0]

    @property
    def message(self) -> str:
        return self.result.get_message()

    @property
    def data(self) -> list[dict]:
        return self.result.get_data()


@pytest.fixture
def run_action(mocker, asset: Asset) -> Callable[..., ActionRun]:
    """Invoke an action with the Zero Networks API replaced by a mock transport.

    ``responder`` receives the outgoing ``httpx.Request`` and returns the
    ``httpx.Response`` the fake API should reply with.
    """

    def run(action, params, responder) -> ActionRun:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return responder(request)

        def fake_build_client(base_url: str, api_token: str, verify: bool = True):
            return httpx.Client(
                base_url=base_url.rstrip("/"),
                transport=httpx.MockTransport(handler),
            )

        mocker.patch("src.app.build_client", side_effect=fake_build_client)
        # Actions resolve their asset through App.asset, which is normally built from
        # the config the platform passes in. Seed it directly for tests.
        mocker.patch.object(app, "_asset", asset, create=True)

        # The test connectivity wrapper takes no params, unlike regular actions.
        succeeded = action() if params is None else action(params)
        return ActionRun(
            succeeded, requests, app.actions_manager.get_action_results()[-1]
        )

    return run


def ok_json(body: dict) -> Callable[[httpx.Request], httpx.Response]:
    """Responder that always replies 200 with the given JSON body."""
    return lambda _request: httpx.Response(200, json=body)
