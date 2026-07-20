# FCR Gate

Rust tools and gateway services for the FCR Gate UniFi Access controller. The
project extracts license-plate reads, manages temporary recurring visitors,
encodes RFID tags through an Impinj R700, and can authorize the Entry Gate from a
tag owner's current UniFi policy and schedule.

## Components

| Component | Purpose | Safety default |
| --- | --- | --- |
| `fcr-gate-admin` | License-plate administration and offline EPC reports | Mutating commands require `--apply` |
| `fcr-rfid-encoder` | R700 encoding, tag ownership, health, and gate authorization | RFID writes and gate unlocks disabled |
| `deploy/` | Persistent systemd units and UniFi boot hooks | Local-only services and root-owned secrets |

## Build and configure

Rust 1.85 or newer is required. The repository pins its development and release
toolchain in `rust-toolchain.toml`.

```bash
cargo build --release --locked
cp .env.example .env
```

Add the UniFi Access bearer token to `.env`:

```dotenv
UNIFI_API_KEY=<token>
```

Process environment variables override `.env`. `UNIFI_API_KEY_FILE` is preferred
for long-running services. Never commit `.env`, secret files, exported plate data,
or the encoder's SQLite database.

## UniFi Access administration

### Extract license-plate reads

```bash
target/release/fcr-gate-admin extract-plates
target/release/fcr-gate-admin extract-plates --days 7
target/release/fcr-gate-admin extract-plates --all \
  --out license_plates_all.csv --json /tmp/plates_all.json
```

The default window is two days. The CSV contains
`timestamp,plate,result,gate,door_id`; the optional JSON output feeds the visitor
enrollment command.

### Enroll and remove visitors

Review the enrollment plan before making a live access-control change:

```bash
target/release/fcr-gate-admin enroll-plates --dry-run
target/release/fcr-gate-admin enroll-plates --apply
```

The command reads `/tmp/plates_all.json`, groups common OCR variants, creates one
recurring visitor per plate group, and records the result in
`enrolled_visitors.json`.

> [!WARNING]
> Historical reads can include denied vehicles, pass-by traffic, and OCR noise.
> Enrollment grants real Entry Gate access to the selected plates.

Rollback also starts with a dry run:

```bash
target/release/fcr-gate-admin cleanup-visitors --dry-run
target/release/fcr-gate-admin cleanup-visitors --apply
```

UniFi only soft-cancels visitors. Cleanup removes their plate associations and
cancels the visitor records, but the cancelled shells remain until they expire or
are cleared in the Access UI.

### Inspect an EPC report

```bash
target/release/fcr-gate-admin epc-report reported_EPCs.csv --list
```

This operation is offline and never changes the reader.

## RFID gateway service

`fcr-rfid-encoder` inventories the configured R700 antenna and recognizes the
factory EPC `300833B2DDD9014000000000`. It requires repeated, strong reads of one
exact TID before allocating and writing a durable 96-bit EPC. Every write is read
back and then confirmed through ordinary inventory. An independent multi-visit
discovery mode can also learn an existing, non-default vehicle tag from repeated
successful LPR passages without rewriting the tag.

Start in observation-only mode:

```bash
cp deploy/gateway.env.example /data/fcr-gate/secrets/gateway.env
# Configure the reader, but leave RFID_WRITES_ENABLED=false.
set -a
. /data/fcr-gate/secrets/gateway.env
set +a
target/release/fcr-rfid-encoder run
```

RFID writes, automatic LPR ownership correlation, the operator UI, and gate
unlocks have independent safety controls. See
[Gateway services](docs/gateway-services.md) for commissioning, tag ownership,
Cloudflare Access, health monitoring, and failure handling.

### Install on the UniFi gateway

Tagged releases contain static ARM64 and x86-64 Linux binaries. For a quick
install, run this on the gateway as root:

```bash
curl -fsSL https://github.com/jpoehnelt/fcr-gate/releases/latest/download/install-fcr-gate.sh | bash
```

That command executes the latest published installer without inspecting it first.
To review and optionally verify the installer before execution:

```bash
curl --fail --location --proto '=https' --tlsv1.2 \
  --output /tmp/install-fcr-gate.sh \
  https://github.com/jpoehnelt/fcr-gate/releases/latest/download/install-fcr-gate.sh
less /tmp/install-fcr-gate.sh
```

If the GitHub CLI is available, verify the signed build provenance:

```bash
gh attestation verify /tmp/install-fcr-gate.sh --repo jpoehnelt/fcr-gate
```

Run the reviewed installer:

```bash
bash /tmp/install-fcr-gate.sh
```

For a version-pinned installation, replace the example tag with the required
calendar release:

```bash
TAG=v2026.7.19
curl -fsSL -o /tmp/install-fcr-gate.sh \
  "https://github.com/jpoehnelt/fcr-gate/releases/download/$TAG/install-fcr-gate.sh"
bash /tmp/install-fcr-gate.sh --version "$TAG"
```

The installer verifies the archive checksum, member list, binary versions, and
target architecture. It installs both binaries atomically, preserves existing
configuration and secrets, installs the systemd unit and boot hook, and starts the
service. `--no-start` installs and enables the service without restarting it.

Cloudflare Tunnel is managed separately; the release installer only manages the
FCR Gate binaries and service. See [Durable Cloudflare service](docs/gateway-services.md#durable-cloudflare-service).

### Operate and monitor

```bash
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder status
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder gate-events --limit 50
curl --fail-with-body http://127.0.0.1:8080/healthz
```

The health response contains service, reader, and database status only. It never
includes tags, users, vehicles, or credentials.

## Development checks

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
npx --yes markdownlint-cli2@0.23.1 '**/*.md' '#target/**'
```

CI also verifies Rust 1.85 compatibility, command interfaces, shell scripts, and
workflow syntax. The Security workflow runs Gitleaks, RustSec, and pull-request
dependency review; RustSec also runs weekly.

Live UniFi behavior must still be tested with `--dry-run` before any `--apply`
command.

## Publish a release

The Calendar Release workflow checks the default branch every day at 09:17 UTC.
When commits exist after the latest release, it calculates an America/Denver date
tag such as `v2026.7.19`, updates `Cargo.toml` and `Cargo.lock`, reruns the core
checks, commits the version, and creates an annotated tag. Days without repository
changes produce no commit, tag, or release. Calendar components are deliberately
not zero-padded so the version remains compatible with Cargo's SemVer parser.

Run the same workflow manually for today or an explicit date:

```bash
gh workflow run calendar-release.yml
gh workflow run calendar-release.yml -f release_date=2026-07-19
```

If a tag exists but publishing was interrupted, the calendar workflow resumes it.
The Release workflow can also be dispatched directly with that existing tag:

```bash
gh workflow run release.yml -f tag=v2026.7.19
```

The workflow rebuilds and verifies the project, creates deterministic static
archives in digest-pinned containers, records signed provenance, and assembles all
assets in a draft release. It downloads and byte-checks every asset before making
the release public. A rerun can repair a draft but will not replace a published
release with different bytes.

Release assets include individual checksum files and `SHA256SUMS`:

```bash
sha256sum --check SHA256SUMS
gh attestation verify fcr-gate-aarch64-unknown-linux-musl.tar.gz \
  --repo jpoehnelt/fcr-gate
```

Dependabot proposes weekly Rust and GitHub Actions updates. The calendar workflow
needs permission to push its two-file version commit to `main`; account for that
before enabling a branch rule that restricts direct pushes. Require the CI and
Security checks for ordinary changes, disallow force pushes, and enable immutable
releases in the repository settings.

## Documentation

- [Gateway services](docs/gateway-services.md): architecture, commissioning,
  authorization, monitoring, and durable installation.
- `AGENTS.md`: repository-specific implementation and safety guidance for coding
  agents.
