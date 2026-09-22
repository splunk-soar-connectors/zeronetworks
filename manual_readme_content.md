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
