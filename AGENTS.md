# AGENTS.md

Repository-specific implementation and safety guidance. See `README.md` for user
setup and `docs/gateway-services.md` for gateway operations.

## What this repo is

Rust gateway service for the **FCR Gate** UniFi **Access** controller:
`fcr-rfid-encoder` inventories an Impinj R700, learns vehicle RFID tags from
repeated license-plate passages, and can authorize the Entry Gate from a tag
owner's current UniFi Access user, policy, and schedule. It never writes EPCs and
never mutates the Access directory — UniFi Access administration (users, visitors,
plates) is done by a separate application.

## Controller / API facts

- **Console:** `100.89.168.42`, UniFi **Access** Open API on **port 12445** (HTTPS).
  - This is the **Access** API, NOT Protect. The key is an Access bearer token;
    Protect endpoints (`/proxy/protect/...`, `X-API-KEY`) will 401 with it.
  - Auth header: `Authorization: Bearer $UNIFI_API_KEY`.
  - Self-signed cert — calls skip TLS verification unless `UNIFI_TLS_VERIFY=true`.
  - API reference PDF: <https://assets.identity.ui.com/unifi-access/api_reference.pdf>
- **Entry Gate door id:** `1b620b81-f457-45f7-9fd2-27de1d8c4fdc` (building "FCR Gate").
- The service reads its UniFi credentials from the environment (`UNIFI_API_KEY_FILE`
  preferred, or `UNIFI_API_KEY`); on the gateway these live under
  `/data/fcr-gate/secrets/`. Never hardcode or commit real tokens.

## Access API usage (read/authorize only)

- Plate reads = `door_openings` system-log entries where
  `authentication.credential_provider == "LICENSEPLATE"`; the plate is
  `authentication.issuer`. Only entry-side events participate in discovery.
- Gate authorization reads the current user, their access policy, door group,
  weekly schedule, and holidays before issuing a remote unlock. See `src/unifi.rs`
  for the exact endpoints and decision logic.

## Binaries

- `fcr-rfid-encoder` — long-running R700 TID inventory service, health endpoint,
  optional UniFi-authorized Entry Gate trigger, and multi-visit vehicle-tag
  discovery. It never writes EPCs.
  - `discovery-status` reports retained tag-to-plate evidence. Visitor-backed
    candidates remain `needs-resident`.
  - `associate-discovered TAG_KEY UNIFI_USER_ID --dry-run` validates a proposed
    permanent owner without writing; `--apply` stores the local association.

## Conventions / gotchas

- All application code is Rust; Bash is limited to gateway installation and
  release automation.
- Date math uses Unix seconds.
- **Live access-control system.** Gate authorization and discovery default to
  disabled; use `dry-run` before setting either to `live`. Only entry-side
  license-plate events participate in discovery; exit-side and directionless
  events fail closed.

## Release invariants

- Automated releases use `vYYYY.M.D` without zero padding. Only
  `scripts/release/set-version.sh` should update the package and lockfile versions.
- A release tag must identify the exact checked-out commit, match the Cargo package
  version, and be derived from the default branch.
- Calendar preparation may change only `Cargo.toml` and `Cargo.lock`; the reusable
  Release workflow independently rebuilds, verifies, attests, and publishes assets.
- Published release bytes are immutable. A rerun may repair a draft or verify an
  identical published release, but must never replace published assets.
