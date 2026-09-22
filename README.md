# Zero Networks for Splunk SOAR

Publisher: Splunk Inc. <br>
Connector Version: 1.0.0 <br>
Product Vendor: Zero Networks <br>
Product Name: Zero Networks Segment <br>
Minimum Product Version: 7.0.0

Segment, quarantine and release assets managed by Zero Networks

## Overview

[Zero Networks](https://zeronetworks.com) automatically segments assets with least-privilege
network policies. This app lets a playbook find an asset by its fully qualified domain name and
then contain it — cutting off its network access — or release it again once the incident is
resolved.

## Prerequisites

You need an API token for the Zero Networks tenant you want to manage. Create one from the Zero
Networks portal and give it permission to read assets and to run asset actions; a read-only token
can run **search asset** and **test connectivity** but will get a `403 Forbidden` on the
quarantine actions. See the [Zero Networks support site](https://support.zeronetworks.com) for
current instructions on issuing API tokens.

## Configuring the asset

| Field | Notes |
| --- | --- |
| **base_url** | Leave at the default `https://portal.zeronetworks.com/api/v1` for production tenants. Development tenants use `https://portal-dev.zeronetworks.com/api/v1`. |
| **api_token** | The API token described above. It is sent verbatim in the `Authorization` header, with no `Bearer` prefix — paste the token on its own. |
| **verify_server_cert** | Leave enabled unless you terminate TLS on an inspecting proxy with a private CA. |

Run **test connectivity** after saving. It calls the asset statistics endpoint, which confirms
that the base URL is reachable and that the token authenticates.

## Working with asset IDs

The quarantine actions address assets by Zero Networks asset ID, which looks like `a:a:JF2xro6g`
— not by hostname or IP. Chain the actions to get one:

1. **search asset** with the FQDN, for example `server.domain.local`, returns
   `action_result.data.*.asset_id`.
1. Feed that value into **quarantine asset** or **unquarantine asset**.

Both actions tag the asset ID with the `zeronetworks asset id` CEF type, so the SOAR UI offers
them as contextual actions wherever an asset ID appears.

**quarantine asset** and **unquarantine asset** call the same Zero Networks endpoint and differ
only in the flag they send, so unquarantining is the exact inverse of quarantining. The endpoint
returns an empty body on success, so the actions report back the asset ID and the quarantine
state they applied rather than a state read back from the API.

### Configuration variables

This table lists the configuration variables required to operate Zero Networks for Splunk SOAR. These variables are specified when configuring a Zero Networks Segment asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Zero Networks portal API base URL |
**api_token** | required | password | Zero Networks API token, sent in the Authorization header |
**verify_server_cert** | required | boolean | Verify the TLS certificate presented by the Zero Networks portal |

### Supported Actions

[test connectivity](#action-test-connectivity) - Verify that the configured token can reach and authenticate to Zero Networks. <br>
[search asset](#action-search-asset) - Search for a Zero Networks asset by FQDN. <br>
[quarantine asset](#action-quarantine-asset) - Quarantine a Zero Networks asset. <br>
[unquarantine asset](#action-unquarantine-asset) - Release a Zero Networks asset from quarantine.

## action: 'test connectivity'

Verify that the configured token can reach and authenticate to Zero Networks.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'search asset'

Search for a Zero Networks asset by FQDN.

Type: **investigate** <br>
Read only: **True**

Looks up a Zero Networks asset ID by fully qualified domain name. The returned asset ID is the input for the quarantine and unquarantine actions.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fqdn** | required | Fully qualified domain name of the asset to look up | string | `host name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.fqdn | string | `host name` | |
action_result.data.\*.asset_id | string | `zeronetworks asset id` | a:a:JF2xro6g |
action_result.data.\*.fqdn | string | `host name` | server.domain.local |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'quarantine asset'

Quarantine a Zero Networks asset.

Type: **contain** <br>
Read only: **False**

Quarantines a Zero Networks asset, cutting off its network access. Use the 'unquarantine asset' action to release it again.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**asset_id** | required | Zero Networks asset ID, as returned by the 'search asset' action | string | `zeronetworks asset id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.asset_id | string | `zeronetworks asset id` | |
action_result.data.\*.asset_id | string | `zeronetworks asset id` | a:a:JF2xro6g |
action_result.data.\*.quarantined | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unquarantine asset'

Release a Zero Networks asset from quarantine.

Type: **correct** <br>
Read only: **False**

Releases a Zero Networks asset from quarantine, restoring its network access.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**asset_id** | required | Zero Networks asset ID, as returned by the 'search asset' action | string | `zeronetworks asset id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.asset_id | string | `zeronetworks asset id` | |
action_result.data.\*.asset_id | string | `zeronetworks asset id` | a:a:JF2xro6g |
action_result.data.\*.quarantined | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
