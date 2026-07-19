# Gateway services

This repository owns two gateway services:

1. `cloudflared`, exposing only the loopback web service through Cloudflare Tunnel.
2. `fcr-rfid-encoder`, an Impinj R700 inventory/exact-TID EPC writer, authenticated
   tag-assignment UI, and optional UniFi-authorized gate trigger.

For the release installer and basic commands, start with the
[project README](../README.md#rfid-gateway-service). This document covers the
runtime architecture and commissioning details.

```mermaid
flowchart LR
    U["Authorized operator"] --> A["Cloudflare Access"]
    A --> T["cloudflared"]
    T -->|"127.0.0.1 only"| W["FCR Gate web service"]
    W -->|"claim / revoke"| E["Rust RFID service + SQLite"]
    E <-->|"IoT Device Interface"| R["Impinj R700"]
    E -->|"current user + policy + schedule"| UA["UniFi Access API"]
    UA -->|"attributed remote unlock"| G["Entry Gate"]
```

## Safety boundary

- The web service must bind to loopback, not the LAN or WAN interface.
- Cloudflare Access must protect the hostname before the operator UI is enabled.
- Every operator route requires Cloudflare's authenticated-user email header;
  Cloudflare Access policy determines which identities are allowed.
- RFID writes default to disabled and require an explicit server-side setting.
- UniFi gate unlocks use a separate setting and also default to disabled.
- `/healthz` contains no tag or user data, binds to loopback with the UI, and should
  use a Cloudflare Access service token for external monitoring.
- Every write must record the operator, requested EPC, result, and timestamp without
  logging reader passwords, tunnel tokens, or other credentials.
- Reader and Cloudflare credentials live below `/data/fcr-gate/secrets/` with mode
  `0600`; they are never command-line arguments or repository content.
- Reported EPC exports are operational data and remain ignored by Git.

## Reader credentials

Impinj documents `root` / `impinj` as the legacy factory login for R700 and
Speedway readers. R700 firmware 9.0 and newer requires the password to be changed
on first login. If the factory login still works, change it before connecting any
service. Do not put either the old or new password in this repository.

- Troubleshooting and login guidance:
  <https://support.impinj.com/article/177630167898291497>
- R700 firmware 9.x first-login behavior:
  <https://support.impinj.com/hc/article_attachments/22893542233107>

## R700 encoder

The Rust service uses the R700 IoT Device Interface rather than LLRP. At startup it
checks `/api/v1/status`, verifies tag-access support from `/api/v1/openapi.json`,
and installs a persistent inventory preset. It streams newline-delimited events
from `/api/v1/data/stream` and submits one transient access operation at
`/api/v1/profiles/inventory/tag-access`.

An encode transaction has all of these gates:

1. The tag is on the configured antenna, has the known default EPC, reports a TID
   through FastID, and exceeds the RSSI threshold.
2. The same TID is read repeatedly during a short window, with no second default-EPC
   TID present. Only one transaction may be in flight.
3. A SQLite transaction durably assigns the TID a site prefix plus 32-bit sequence.
4. The R700 selector matches the complete TID. Six one-word commands write EPC bank
   words 2 through 7, followed by a six-word read-back command.
5. Every command must report success and the read-back must equal the assigned EPC.
6. A subsequent normal inventory event must pair the same TID with the new EPC.

The database uses WAL mode and `synchronous=FULL`. Interrupted queued operations
return to `pending` on restart and reuse their existing EPC; they never allocate a
replacement. Failed writes use a cooldown and maximum-attempt limit. An unexpected
non-default EPC for an assigned TID becomes a conflict requiring an explicit retry.
The audit table records allocations, attempts, verification, completion, failures,
and the configured actor without storing reader credentials.

Retrying a conflict explicitly authorizes repair of that exact TID back to its
existing durable assignment. The normal default-EPC and ambiguity gates still
apply to ordinary first-time encodes.

The event connection is recycled after 90 seconds without reader data, and an
in-flight transaction is released after its configured timeout. SIGINT/SIGTERM
shutdown stops the service-owned preset, which also makes the R700 discard any
still-pending transient access request.

Writes are disabled by default. Commission them in this order:

1. Set the R700 to the IoT Device Interface and configure its regulatory region.
2. Isolate one loose tag in the antenna field. A far-field gate antenna can see a
   nearby spool or vehicle tag, so physical separation and reduced transmit power
   are part of the safety system.
3. Configure the reader password file, antenna port, conservative power/RSSI values,
   and leave `RFID_WRITES_ENABLED=false`. Run until logs consistently report one
   dry-run candidate.
4. Choose and record a site-unique 64-bit `RFID_EPC_PREFIX`. This implementation
   writes only the 96-bit EPC; it does not change access, kill, or lock state.
5. Enable writes for a single test tag. Verify the service reports both read-back
   and ordinary-inventory confirmation before using it at the gate.

Tags that do not provide a usable FastID TID are ignored intentionally; the service
will not fall back to selecting the shared default EPC. Inspect state or authorize a
controlled retry with:

```bash
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder status
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder retry <TID>
```

## Ownership and gate authorization

Encoding and ownership are deliberately separate. A newly encoded tag is
`unassigned`, even if it is immediately readable at the gate. The operator UI
allows a claim only while that exact TID has been seen recently. It searches active
UniFi users, verifies that the selected user has an Entry Gate policy, and stores
the mapping locally. It never writes comma-separated EPCs into `employee_number`
and never treats an EPC as a native UniFi NFC credential.

Ownership states are `unassigned`, `active`, `revoked`, and `lost` (the latter is
reserved in the database for operational loss handling). Transfers require an
explicit revoke followed by a new claim. Claims and revocations record the
Cloudflare-authenticated operator email in `audit_log`.

With `RFID_GATE_MODE=dry-run` or `live`, a read from an active assignment is not
itself authorization. The service asks UniFi for the user's current status and all
direct and group access policies, expands door groups, and evaluates the Entry Gate
policy's weekly and holiday schedules. Any missing resource, malformed response,
inactive user, out-of-schedule policy, or API failure leaves the gate locked.

Dry-run records the same granted, denied, and error decisions in `gate_events` with
`mode='dry-run'`, but never calls the unlock endpoint. Live mode invokes UniFi's
remote door unlock with the user ID/name as the actor and the TID/EPC/policy in
passthrough metadata. Repeated reads are rate-limited per TID in both modes.

```bash
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder gate-events --limit 50
```

Required Access API token permissions are `view:user`, `view:policy`, `view:space`,
and `edit:space`. Store the token in
`/data/fcr-gate/secrets/unifi-access-api-key` with mode `0600`. Schedule evaluation
uses the service's local timezone, so set `TZ=America/Denver` on this gateway.

Expose the UI through the existing named tunnel, for example:

```yaml
ingress:
  - hostname: rfid.fallscreekranch.org
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Before setting `FCR_GATE_WEB_ENABLED=true`, create a Cloudflare Access application
for that hostname and restrict its policy to the intended operators. Keep
`RFID_GATE_MODE=disabled` while testing claims and revocations, then use `dry-run`
to verify assigned, revoked, allowed, and out-of-schedule tags. Change it to `live`
only after reviewing those decisions.

## Health monitoring

`FCR_GATE_HEALTH_ENABLED=true` exposes `GET /healthz` on the loopback HTTP port,
independently of the operator UI. The reader stream updates an in-memory connection
and activity marker when its HTTPS stream connects or receives bytes. A brief
reconnect remains healthy using the most recent activity time; activity older than
`FCR_GATE_HEALTH_STALE_MS` is unhealthy. The check also opens the SQLite database
and reads the durable allocator row.

- `200`: reader activity is recent and SQLite is readable.
- `503`: reader activity is stale/missing or SQLite cannot be read.

The response deliberately excludes TID, EPC, user, vehicle, policy, and error text.
Use a path-specific Cloudflare Access service-token policy for external monitoring,
or query `http://127.0.0.1:8080/healthz` locally.

Impinj references:

- IoT Device Interface API: <https://support.impinj.com/article/32195454977555>
- R700 firmware release notes: <https://support.impinj.com/article/32123172324755>
- Reader configuration and REST examples: <https://support.impinj.com/article/202756008>

## Durable Cloudflare service

The checked-in [`deploy/cloudflared.service`](../deploy/cloudflared.service) reads
the tunnel token from a root-only file and runs the binary from persistent `/data`.
The boot script recreates the systemd unit after startup.

Expected layout on a UniFi OS 4.x/5.x Cloud Gateway:

```text
/data/fcr-gate/
├── bin/
│   ├── cloudflared
│   ├── fcr-gate-admin
│   └── fcr-rfid-encoder
├── deploy/
│   ├── cloudflared.service
│   └── fcr-rfid-encoder.service
├── rfid-encoder.sqlite3
└── secrets/
    ├── cloudflare-tunnel-token
    ├── impinj-password
    ├── unifi-access-api-key
    └── gateway.env
```

Install the current community UniFi boot hook, then place or link
`deploy/20-cloudflared.sh` at `/data/on_boot.d/20-cloudflared.sh`. Run the script
once to install and start the unit. This is a community-supported appliance
customization, so verify it after every UniFi OS upgrade.

Install `deploy/30-fcr-rfid-encoder.sh` through the same boot-hook mechanism after
cross-compiling/copying the encoder binary for the gateway architecture. Start
with the example environment and keep the password and environment files mode
`0600`. The script enables the unit; it does not alter the checked-in safety
default that keeps writes off.

Tagged GitHub releases automate installation and updates for the FCR Gate binaries
and encoder service. They do not install or update `cloudflared`. See
[Install on the UniFi gateway](../README.md#install-on-the-unifi-gateway) for the
verified release workflow.

Cloudflare references:

- Tunnel setup: <https://developers.cloudflare.com/tunnel/setup/>
- Linux service: <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/as-a-service/linux/>
- Token files: <https://developers.cloudflare.com/tunnel/advanced/run-parameters/#token-file>

## EPC report ingestion

Keep the actual export outside Git and inspect it locally:

```bash
/data/fcr-gate/bin/fcr-gate-admin epc-report reported_EPCs.csv --list
```

Use the original CSV export as input. Text copied through chat or email may lose
the delimiters required by the parser.
