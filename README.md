# FCR Gate

Rust gateway service for the FCR Gate UniFi Access controller. It learns vehicle
RFID tags through an Impinj R700 and can authorize the Entry Gate from a tag
owner's current UniFi policy and schedule.

## Components

| Component | Purpose | Safety default |
| --- | --- | --- |
| `fcr-rfid-encoder` | R700 TID discovery, tag ownership, health, and gate authorization | Discovery and gate unlocks disabled |
| `deploy/` | Persistent systemd units and UniFi boot hooks | Local-only services and root-owned secrets |

## Build and configure

Rust 1.85 or newer is required. The repository pins its development and release
toolchain in `rust-toolchain.toml`.

```bash
cargo build --release --locked
```

The gateway service reads its configuration and UniFi Access credentials from the
environment; see `deploy/gateway.env.example`. On the gateway these live under
`/data/fcr-gate/secrets/`, and `UNIFI_API_KEY_FILE` is preferred over
`UNIFI_API_KEY` for the long-running service. Never commit secret files or the
RFID service's SQLite database.

## RFID gateway service

`fcr-rfid-encoder` inventories the configured R700 antenna and uses FastID TIDs as
durable tag identities. Multi-visit discovery learns a vehicle tag from repeated
successful LPR passages. It never writes or changes a tag's EPC.

Start in observation-only mode:

```bash
cp deploy/gateway.env.example /data/fcr-gate/secrets/gateway.env
# Configure the reader and leave discovery and gate authorization disabled.
set -a
. /data/fcr-gate/secrets/gateway.env
set +a
target/release/fcr-rfid-encoder run
```

Discovery and gate unlocks have independent safety controls. See
[Gateway services](docs/gateway-services.md) for commissioning, learned tag
ownership, health monitoring, and failure handling.

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

The installer verifies the archive checksum, member list, binary version, and
target architecture. It installs the binary atomically, preserves existing
configuration and secrets, installs the systemd unit and boot hook, and starts the
service. `--no-start` installs and enables the service without restarting it.

Cloudflare Tunnel is managed separately; the release installer only manages the
FCR Gate binaries and service. See [Durable Cloudflare service](docs/gateway-services.md#durable-cloudflare-service).

### Operate and monitor

```bash
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder gate-events --limit 50
RFID_STATE_DB=/data/fcr-gate/rfid-encoder.sqlite3 \
  /data/fcr-gate/bin/fcr-rfid-encoder discovery-status --limit 100
curl --fail-with-body http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/metrics
```

The health response contains service, reader, and database status only. It never
includes tags, users, vehicles, or credentials.

Service logs are newline-delimited JSON in journald. Each operational record has
a stable `event` field plus relevant values such as `tid`, `epc`, `plate`,
`decision`, and `reason`. The service can also copy these records directly to
Loki without blocking RFID processing; see
[Loki event inspection](docs/gateway-services.md#loki-event-inspection).

Successful UniFi LPR Visitor events can build durable tag-to-plate evidence, but
they never become gate owners automatically. A mature `needs-resident` candidate
must be validated against a permanent UniFi user with `associate-discovered`; the
command is dry-run unless `--apply` is supplied. See
[Gateway services](docs/gateway-services.md#multi-visit-discovery-for-existing-vehicle-tags).

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
