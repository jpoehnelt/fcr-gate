# AGENTS.md

Repository-specific implementation and safety guidance. See `README.md` for user
setup and `docs/gateway-services.md` for gateway operations.

## What this repo is

Rust tools and services for the **FCR Gate** UniFi **Access** controller: extracting
license-plate reads from the gate's system log, and enrolling plates as temporary
recurring Visitors so they can pass the Entry Gate.

## Controller / API facts

- **Console:** `100.89.168.42`, UniFi **Access** Open API on **port 12445** (HTTPS).
  - This is the **Access** API, NOT Protect. The `.env` key is an Access bearer
    token. Protect endpoints (`/proxy/protect/...`, `X-API-KEY`) will 401 with it.
  - Auth header: `Authorization: Bearer $UNIFI_API_KEY`.
  - Self-signed cert — all calls skip TLS verification (`curl -k` / `CERT_NONE`).
  - API reference PDF: <https://assets.identity.ui.com/unifi-access/api_reference.pdf>
- **Entry Gate door id:** `1b620b81-f457-45f7-9fd2-27de1d8c4fdc` (building "FCR Gate").
- Secrets live in `.env` (`UNIFI_API_KEY=...`). Never hardcode the token; the Rust
  admin CLI reads it from `.env` or `UNIFI_API_KEY_FILE`. Do not commit real tokens.

## Key API endpoints

| Purpose | Method | Path |
| --- | --- | --- |
| Fetch system logs (plate reads) | POST | `/api/v1/developer/system/logs` (body `{topic,since,until}`) |
| Create visitor | POST | `/api/v1/developer/visitors` |
| Assign plates to visitor | PUT | `/api/v1/developer/visitors/:id/license_plates` (body `["PLATE",...]`) |
| List all visitors | GET | `/api/v1/developer/visitors?page_num=&page_size=` |
| Visitor detail | GET | `/api/v1/developer/visitors/:id` |
| Delete (soft-cancel) visitor | DELETE | `/api/v1/developer/visitors/:id` |
| Unassign one plate | DELETE | `/api/v1/developer/visitors/:id/license_plates/:plate_id` |

- **Visitor status enum:** `UPCOMING=1, VISITED=2, VISITING=3, CANCELLED=4, NO_VISIT=5, ACTIVE=6`.
- **`DELETE /visitors/:id` is a soft cancel**, not a hard delete. It sets status to
  `CANCELLED` but the shell record (and any attached plates) stays in the directory.
  There is **no hard-delete endpoint** — cancelled shells must be cleared in the
  Access UI or they expire at `end_time`. A plate left bound to a cancelled visitor
  can block re-registering that plate to a real user, so strip plates on cleanup
  (`fcr-gate-admin cleanup-visitors`).

- Plate reads = `door_openings` log entries where
  `authentication.credential_provider == "LICENSEPLATE"`; plate is `authentication.issuer`.
- A Visitor is the "temporary user" primitive: `start_time`/`end_time` validity plus
  an optional `week_schedule`. **Presence of `week_schedule` ⇒ recurring; absence ⇒
  one-time.** 24/7 = every day `00:00:00`–`23:59:59`.

## Binaries

- `fcr-gate-admin extract-plates` — pull plate reads to CSV.
  - `--days N` (default 2) or `--all` (full retained history).
  - `--out CSV` and optional `--json DUMP` (the dump feeds `enroll-plates`).
- `fcr-gate-admin enroll-plates` — create one recurring 24/7 Visitor per plate from
  `/tmp/plates_all.json`.
  - `--dry-run` prints the plan and makes NO changes; `--apply` is live.
  - Deduplicates OCR variants (`O`↔`0`, `I`↔`1`) and attaches them to one visitor.
  - Tags visitors with remark `LPR_BULK`, names them `LPR <plate>`.
  - Writes `enrolled_visitors.json` (per-plate result + `visitor_id`).
- `fcr-gate-admin cleanup-visitors` — undo a bulk enroll. Soft-cancels every `LPR_BULK`
  visitor and unassigns all their plates. `--dry-run` / `--apply`. Cannot remove
  the cancelled shells (no API hard-delete) — those need the Access UI.
- `fcr-gate-admin epc-report` — inspect an Impinj reported-EPC CSV offline.
- `fcr-rfid-encoder` — long-running R700 encoder, assignment UI, health endpoint,
  optional UniFi-authorized Entry Gate trigger, and multi-visit discovery of
  existing non-default vehicle tags.

## Conventions / gotchas

- All application code is Rust; Bash is limited to gateway installation and
  release automation.
- Date math uses Unix seconds. The Rust CLI writes `enrolled_visitors.json` after
  completing a live enrollment run.
- **Live access-control system.** Creating/deleting visitors changes who can enter
  the gate. Always `--dry-run` before `--apply`. Note that every historical plate
  read was `BLOCKED` (unknown) before enrollment, so the bulk enroll grants access
  to formerly-denied vehicles, including OCR noise — review before trusting.

## Rollback

Use `fcr-gate-admin cleanup-visitors --dry-run`, review the result, then use
`--apply`. It soft-cancels matching visitors and strips their plate associations.

## Release invariants

- Automated releases use `vYYYY.M.D` without zero padding. Only
  `scripts/release/set-version.sh` should update the package and lockfile versions.
- A release tag must identify the exact checked-out commit, match the Cargo package
  version, and be derived from the default branch.
- Calendar preparation may change only `Cargo.toml` and `Cargo.lock`; the reusable
  Release workflow independently rebuilds, verifies, attests, and publishes assets.
- Published release bytes are immutable. A rerun may repair a draft or verify an
  identical published release, but must never replace published assets.
