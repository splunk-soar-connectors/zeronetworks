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
import json

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.app import (
    Asset,
    QuarantineParams,
    SearchAssetParams,
    _validated_asset_id,
    quarantine_asset,
    search_asset,
    unquarantine_asset,
)

# Aliased so pytest does not collect the action itself as a test case.
from src.app import test_connectivity as connectivity_action

from .conftest import ok_json

ASSET_ID = "a:a:JF2xro6g"


class TestAssetConfig:
    def test_base_url_defaults_to_production_portal(self):
        asset = Asset(api_token="token")
        assert asset.base_url == "https://portal.zeronetworks.com/api/v1"
        assert asset.verify_server_cert is True

    def test_base_url_is_overridable(self):
        asset = Asset(
            base_url="https://portal-dev.zeronetworks.com/api/v1", api_token="t"
        )
        assert asset.base_url == "https://portal-dev.zeronetworks.com/api/v1"


class TestValidatedAssetId:
    @pytest.mark.parametrize(
        "asset_id", ["a:a:JF2xro6g", "a:d:abcd1234", "  a:a:JF2xro6g  "]
    )
    def test_accepts_well_formed_ids(self, asset_id):
        assert _validated_asset_id(asset_id) == asset_id.strip()

    @pytest.mark.parametrize(
        "asset_id",
        [
            "server.domain.local",  # an FQDN passed by mistake
            "a:a:short",  # ID suffix must be exactly 8 characters
            "u:a:w27loY5p",  # a user ID, not an asset ID
            "",
        ],
    )
    def test_rejects_malformed_ids(self, asset_id):
        with pytest.raises(ActionFailure, match="not a valid Zero Networks asset ID"):
            _validated_asset_id(asset_id)


class TestTestConnectivity:
    def test_calls_asset_statistics(self, run_action):
        run = run_action(connectivity_action, None, ok_json({"total": 5}))
        assert run.succeeded
        assert run.request.method == "GET"
        assert run.request.url.path.endswith("/assets/statistics")

    def test_fails_on_bad_token(self, run_action):
        run = run_action(
            connectivity_action,
            None,
            lambda _r: httpx.Response(
                401, json={"error": "unauthorized", "message": "bad token"}
            ),
        )
        assert not run.succeeded
        assert "has not expired" in run.message
        assert "bad token" in run.message


class TestSearchAsset:
    def test_returns_asset_id_for_fqdn(self, run_action):
        run = run_action(
            search_asset,
            SearchAssetParams(fqdn="server.domain.local"),
            ok_json({"assetId": ASSET_ID}),
        )
        assert run.succeeded
        assert run.request.method == "GET"
        assert run.request.url.path.endswith("/assets/searchId")
        assert run.request.url.params["fqdn"] == "server.domain.local"
        assert run.data == [{"asset_id": ASSET_ID, "fqdn": "server.domain.local"}]

    def test_trims_surrounding_whitespace(self, run_action):
        run = run_action(
            search_asset,
            SearchAssetParams(fqdn="  server.domain.local  "),
            ok_json({"assetId": ASSET_ID}),
        )
        assert run.request.url.params["fqdn"] == "server.domain.local"

    def test_fails_when_no_asset_matches(self, run_action):
        # The API answers 200 with an empty body rather than 404 for a miss.
        run = run_action(
            search_asset, SearchAssetParams(fqdn="ghost.local"), ok_json({})
        )
        assert not run.succeeded
        assert "No Zero Networks asset found with FQDN 'ghost.local'" in run.message

    def test_fails_on_blank_fqdn_without_calling_api(self, run_action):
        run = run_action(search_asset, SearchAssetParams(fqdn="   "), ok_json({}))
        assert not run.succeeded
        assert run.requests == []
        assert "must not be empty" in run.message


class TestQuarantine:
    def test_sends_quarantine_true(self, run_action):
        run = run_action(
            quarantine_asset, QuarantineParams(asset_id=ASSET_ID), ok_json({})
        )
        assert run.succeeded
        assert run.request.method == "PUT"
        assert run.request.url.path == f"/api/v1/assets/{ASSET_ID}/actions/quarantine"
        assert json.loads(run.request.content) == {"quarantine": True}
        assert run.data == [{"asset_id": ASSET_ID, "quarantined": True}]

    def test_rejects_bad_asset_id_without_calling_api(self, run_action):
        run = run_action(
            quarantine_asset,
            QuarantineParams(asset_id="server.domain.local"),
            ok_json({}),
        )
        assert not run.succeeded
        assert run.requests == []

    def test_surfaces_not_found(self, run_action):
        run = run_action(
            quarantine_asset,
            QuarantineParams(asset_id=ASSET_ID),
            lambda _r: httpx.Response(
                404, json={"error": "not_found", "message": "no such asset"}
            ),
        )
        assert not run.succeeded
        assert "does not exist in this Zero Networks tenant" in run.message


class TestUnquarantine:
    def test_sends_quarantine_false_to_the_same_endpoint(self, run_action):
        run = run_action(
            unquarantine_asset, QuarantineParams(asset_id=ASSET_ID), ok_json({})
        )
        assert run.succeeded
        assert run.request.method == "PUT"
        assert run.request.url.path == f"/api/v1/assets/{ASSET_ID}/actions/quarantine"
        assert json.loads(run.request.content) == {"quarantine": False}
        assert run.data == [{"asset_id": ASSET_ID, "quarantined": False}]

    def test_rejects_bad_asset_id_without_calling_api(self, run_action):
        run = run_action(
            unquarantine_asset, QuarantineParams(asset_id="nope"), ok_json({})
        )
        assert not run.succeeded
        assert run.requests == []
