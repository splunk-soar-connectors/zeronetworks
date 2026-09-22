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
"""Constants for the Zero Networks SOAR app."""

# Default Zero Networks portal API root. Overridable per-asset so that customers
# on the development portal (or an on-prem proxy) can point the app elsewhere.
DEFAULT_BASE_URL = "https://portal.zeronetworks.com/api/v1"

# Endpoints, relative to the asset's base URL.
ASSET_SEARCH_ENDPOINT = "/assets/searchId"
ASSET_QUARANTINE_ENDPOINT = "/assets/{asset_id}/actions/quarantine"
CONNECTIVITY_ENDPOINT = "/assets/statistics"

# Zero Networks asset IDs look like "a:a:JF2xro6g" -- see the assetIdParameter
# schema in the Zero Networks OpenAPI spec.
ASSET_ID_PATTERN = r"^a:[a-zA-Z]:[a-zA-Z0-9]{8}$"

# CEF contains-type used to chain the asset ID between actions in the SOAR UI.
CEF_ZN_ASSET_ID = "zeronetworks asset id"

DEFAULT_TIMEOUT_SECONDS = 30
