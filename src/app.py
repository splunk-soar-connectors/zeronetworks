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
"""Splunk SOAR app for Zero Networks.

Looks up Zero Networks assets by FQDN and quarantines or releases them.
"""

import re

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from .client import build_client, request_json
from .consts import (
    ASSET_ID_PATTERN,
    ASSET_QUARANTINE_ENDPOINT,
    ASSET_SEARCH_ENDPOINT,
    CEF_ZN_ASSET_ID,
    CONNECTIVITY_ENDPOINT,
    DEFAULT_BASE_URL,
)

logger = getLogger()

APP_ID = "85010388-bc3f-48a9-af39-0af675dcd405"


class Asset(BaseAsset):
    """Connection details for a Zero Networks tenant."""

    base_url: str = AssetField(
        default=DEFAULT_BASE_URL,
        description="Zero Networks portal API base URL",
    )
    api_token: str = AssetField(
        sensitive=True,
        description="Zero Networks API token, sent in the Authorization header",
    )
    verify_server_cert: bool = AssetField(
        default=True,
        description="Verify the TLS certificate presented by the Zero Networks portal",
    )


app = App(
    name="Zero Networks for Splunk SOAR",
    app_type="network security",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Zero Networks",
    product_name="Zero Networks Segment",
    publisher="Splunk Inc.",
    appid=APP_ID,
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


def _validated_asset_id(asset_id: str) -> str:
    """Reject IDs that the Zero Networks API would reject anyway, with a clearer message."""
    asset_id = asset_id.strip()
    if not re.match(ASSET_ID_PATTERN, asset_id):
        raise ActionFailure(
            f"'{asset_id}' is not a valid Zero Networks asset ID (expected a value like "
            "'a:a:JF2xro6g'). Run 'search asset' with the FQDN to look one up."
        )
    return asset_id


def _set_quarantine(asset: Asset, asset_id: str, quarantine: bool) -> None:
    """Enable or disable quarantine for an asset.

    Both directions use the same endpoint; only the request body differs.
    """
    verb = "Quarantine" if quarantine else "Unquarantine"
    with build_client(
        asset.base_url, asset.api_token, asset.verify_server_cert
    ) as client:
        request_json(
            client,
            "PUT",
            ASSET_QUARANTINE_ENDPOINT.format(asset_id=asset_id),
            context=f"{verb} of asset {asset_id}",
            json={"quarantine": quarantine},
        )


@app.test_connectivity()
def test_connectivity(asset: Asset) -> None:
    """Verify that the configured token can reach and authenticate to Zero Networks."""
    logger.progress(f"Connecting to {asset.base_url}")

    with build_client(
        asset.base_url, asset.api_token, asset.verify_server_cert
    ) as client:
        request_json(client, "GET", CONNECTIVITY_ENDPOINT, context="Connectivity test")

    logger.progress("Connectivity test passed")


class SearchAssetParams(Params):
    fqdn: str = Param(
        description="Fully qualified domain name of the asset to look up",
        primary=True,
        cef_types=["host name"],
    )


class SearchAssetOutput(ActionOutput):
    asset_id: str = OutputField(
        cef_types=[CEF_ZN_ASSET_ID],
        example_values=["a:a:JF2xro6g"],
        column_name="Asset ID",
    )
    fqdn: str = OutputField(
        cef_types=["host name"],
        example_values=["server.domain.local"],
        column_name="FQDN",
    )


@app.action(
    name="search asset",
    action_type="investigate",
    read_only=True,
    render_as="table",
    verbose="Looks up a Zero Networks asset ID by fully qualified domain name. "
    "The returned asset ID is the input for the quarantine and unquarantine actions.",
)
def search_asset(
    params: SearchAssetParams, asset: Asset, soar: SOARClient
) -> SearchAssetOutput:
    """Search for a Zero Networks asset by FQDN."""
    fqdn = params.fqdn.strip()
    if not fqdn:
        raise ActionFailure("The fqdn parameter must not be empty.")

    with build_client(
        asset.base_url, asset.api_token, asset.verify_server_cert
    ) as client:
        body = request_json(
            client,
            "GET",
            ASSET_SEARCH_ENDPOINT,
            context=f"Asset search for '{fqdn}'",
            params={"fqdn": fqdn},
        )

    asset_id = body.get("assetId")
    if not asset_id:
        # The API answers 200 with an empty payload when nothing matches.
        raise ActionFailure(f"No Zero Networks asset found with FQDN '{fqdn}'.")

    soar.set_message(f"Found asset {asset_id} for {fqdn}")
    return SearchAssetOutput(asset_id=asset_id, fqdn=fqdn)


class QuarantineParams(Params):
    asset_id: str = Param(
        description="Zero Networks asset ID, as returned by the 'search asset' action",
        primary=True,
        cef_types=[CEF_ZN_ASSET_ID],
    )


class QuarantineOutput(ActionOutput):
    asset_id: str = OutputField(
        cef_types=[CEF_ZN_ASSET_ID],
        example_values=["a:a:JF2xro6g"],
        column_name="Asset ID",
    )
    quarantined: bool = OutputField(
        example_values=[True, False],
        column_name="Quarantined",
    )


@app.action(
    name="quarantine asset",
    action_type="contain",
    read_only=False,
    render_as="table",
    verbose="Quarantines a Zero Networks asset, cutting off its network access. "
    "Use the 'unquarantine asset' action to release it again.",
)
def quarantine_asset(
    params: QuarantineParams, asset: Asset, soar: SOARClient
) -> QuarantineOutput:
    """Quarantine a Zero Networks asset."""
    asset_id = _validated_asset_id(params.asset_id)

    _set_quarantine(asset, asset_id, quarantine=True)

    soar.set_message(f"Quarantined asset {asset_id}")
    return QuarantineOutput(asset_id=asset_id, quarantined=True)


@app.action(
    name="unquarantine asset",
    action_type="correct",
    read_only=False,
    render_as="table",
    verbose="Releases a Zero Networks asset from quarantine, restoring its network access.",
)
def unquarantine_asset(
    params: QuarantineParams, asset: Asset, soar: SOARClient
) -> QuarantineOutput:
    """Release a Zero Networks asset from quarantine."""
    asset_id = _validated_asset_id(params.asset_id)

    _set_quarantine(asset, asset_id, quarantine=False)

    soar.set_message(f"Released asset {asset_id} from quarantine")
    return QuarantineOutput(asset_id=asset_id, quarantined=False)


if __name__ == "__main__":
    app.cli()
