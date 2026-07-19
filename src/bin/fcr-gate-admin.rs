use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use fcr_rfid_encoder::admin::{
    AdminClient, AdminConfig, EnrollmentLog, EnrollmentResult, build_plate_groups,
    extract_plate_rows, load_plate_issuers, normalize_epc, read_epcs, summarize_statuses,
    visitor_payload, write_json, write_plate_csv,
};

const DEFAULT_PLATE_DUMP: &str = "/tmp/plates_all.json";
const DEFAULT_ENROLLMENT_LOG: &str = "enrolled_visitors.json";
const VALID_DAYS: i64 = 90;

#[derive(Debug, Parser)]
#[command(about = "Administrative CLI for FCR Gate UniFi Access", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Extract license-plate reads from the UniFi Access system log.
    ExtractPlates(ExtractPlatesArgs),
    /// Enroll recurring 24/7 visitors from an extracted system-log dump.
    EnrollPlates(EnrollPlatesArgs),
    /// Cancel bulk LPR visitors and unassign their plates.
    CleanupVisitors(ChangeMode),
    /// Inspect an Impinj reported-EPC CSV without contacting the reader.
    EpcReport(EpcReportArgs),
}

#[derive(Debug, Args)]
struct ExtractPlatesArgs {
    /// Look back this many days.
    #[arg(long, conflicts_with = "all")]
    days: Option<f64>,
    /// Query the full retained history (since=0).
    #[arg(long, conflicts_with = "days")]
    all: bool,
    /// CSV output path.
    #[arg(long, default_value = "plates.csv")]
    out: PathBuf,
    /// Also write the raw API response as JSON.
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct EnrollPlatesArgs {
    #[command(flatten)]
    mode: ChangeMode,
    /// Raw system-log JSON produced by extract-plates --json.
    #[arg(long, default_value = DEFAULT_PLATE_DUMP)]
    source: PathBuf,
    /// Per-plate apply result log.
    #[arg(long, default_value = DEFAULT_ENROLLMENT_LOG)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct ChangeMode {
    /// Report the plan without changing UniFi (the default).
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,
    /// Make live changes to UniFi Access.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
}

#[derive(Debug, Args)]
struct EpcReportArgs {
    /// reported_EPCs_*.csv export.
    report: PathBuf,
    /// Print each unique normalized EPC.
    #[arg(long)]
    list: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::ExtractPlates(args) => extract(args).await,
        Command::EnrollPlates(args) => enroll(args).await,
        Command::CleanupVisitors(mode) => cleanup(mode).await,
        Command::EpcReport(args) => epc_report(args),
    }
}

async fn extract(args: ExtractPlatesArgs) -> Result<()> {
    let days = args.days.unwrap_or(2.0);
    if !args.all && (!days.is_finite() || days <= 0.0) {
        bail!("--days must be a positive finite number");
    }
    let until = unix_seconds()?;
    let since = if args.all {
        0
    } else {
        until.saturating_sub((days * 24.0 * 3600.0) as i64)
    };
    let config = AdminConfig::from_env(false)?;
    let client = AdminClient::new(&config)?;
    let response = client.fetch_system_logs(since, until).await?;
    if let Some(path) = &args.json {
        write_json(path, &response, false)?;
    }
    let rows = extract_plate_rows(&response)?;
    write_plate_csv(&args.out, &rows)?;

    let total = response
        .pointer("/pagination/total")
        .and_then(serde_json::Value::as_u64)
        .map_or_else(|| "unknown".into(), |value| value.to_string());
    let window = if args.all {
        "ALL".into()
    } else {
        format!("{days}d")
    };
    println!("window: since={since} until={until} ({window})");
    println!("door_openings total: {total} | plate reads: {}", rows.len());
    if let (Some(first), Some(last)) = (rows.first(), rows.last()) {
        let mut plate_counts = HashMap::<&str, usize>::new();
        let mut result_counts = BTreeMap::<&str, usize>::new();
        for row in &rows {
            *plate_counts.entry(&row.plate).or_default() += 1;
            *result_counts.entry(&row.result).or_default() += 1;
        }
        let mut top = plate_counts.into_iter().collect::<Vec<_>>();
        top.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
        println!(
            "unique plates: {} | by result: {:?}",
            top.len(),
            result_counts
        );
        println!("range: {} .. {}", first.timestamp, last.timestamp);
        println!(
            "top plates: {}",
            top.into_iter()
                .take(8)
                .map(|(plate, reads)| format!("{plate}x{reads}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    print!("wrote {}", args.out.display());
    if let Some(path) = args.json {
        print!(" and {}", path.display());
    }
    println!();
    Ok(())
}

async fn enroll(args: EnrollPlatesArgs) -> Result<()> {
    let raw = load_plate_issuers(&args.source)?;
    let plan = build_plate_groups(&raw);
    println!(
        "raw reads: {} | unique strings: {} | collapsed visitors: {}",
        raw.len(),
        raw.iter().collect::<BTreeSet<_>>().len(),
        plan.len()
    );
    let merged = plan
        .iter()
        .filter(|group| group.variants.len() > 1)
        .collect::<Vec<_>>();
    println!("groups merging >1 variant: {}", merged.len());
    for group in merged {
        println!("  {:10} <- {:?}", group.canonical, group.variants);
    }
    if !args.mode.apply {
        println!("\n[dry-run] no changes made. Re-run with --apply to create visitors.");
        return Ok(());
    }

    let config = AdminConfig::from_env(true)?;
    let door_id = config.entry_gate_door_id()?.to_owned();
    let client = AdminClient::new(&config)?;
    let start = unix_seconds()?;
    let end = start.saturating_add(VALID_DAYS * 24 * 3600);
    let mut results = Vec::new();
    for (index, group) in plan.iter().enumerate() {
        let payload = visitor_payload(group, &door_id, start, end);
        match client.create_visitor(&payload).await {
            Ok(visitor_id) => match client
                .assign_license_plates(&visitor_id, &group.variants)
                .await
            {
                Ok(()) => {
                    println!(
                        "[{}/{}] OK  {:10} -> {}  plates={:?}",
                        index + 1,
                        plan.len(),
                        group.canonical,
                        visitor_id,
                        group.variants
                    );
                    results.push(EnrollmentResult {
                        canonical: group.canonical.clone(),
                        visitor_id: Some(visitor_id),
                        plates: Some(group.variants.clone()),
                        status: "OK".into(),
                        error: None,
                    });
                }
                Err(error) => {
                    eprintln!(
                        "[{}/{}] ERR {:10} visitor {} created but plate assignment failed: {error:#}",
                        index + 1,
                        plan.len(),
                        group.canonical,
                        visitor_id
                    );
                    results.push(EnrollmentResult {
                        canonical: group.canonical.clone(),
                        visitor_id: Some(visitor_id),
                        plates: None,
                        status: "ERR".into(),
                        error: Some(format!("plate assignment failed: {error:#}")),
                    });
                }
            },
            Err(error) => {
                eprintln!(
                    "[{}/{}] ERR {:10} {error:#}",
                    index + 1,
                    plan.len(),
                    group.canonical
                );
                results.push(EnrollmentResult {
                    canonical: group.canonical.clone(),
                    visitor_id: None,
                    plates: None,
                    status: "ERR".into(),
                    error: Some(format!("{error:#}")),
                });
            }
        }
    }
    let ok = results
        .iter()
        .filter(|result| result.status == "OK")
        .count();
    write_json(
        &args.out,
        &EnrollmentLog {
            start_time: start,
            end_time: end,
            results,
        },
        true,
    )?;
    println!(
        "\ndone: {ok}/{} created. log -> {}",
        plan.len(),
        args.out.display()
    );
    Ok(())
}

async fn cleanup(mode: ChangeMode) -> Result<()> {
    let config = AdminConfig::from_env(false)?;
    let client = AdminClient::new(&config)?;
    let visitors = client.list_visitors().await?;
    let lpr = visitors
        .into_iter()
        .filter(|visitor| visitor.is_lpr())
        .collect::<Vec<_>>();
    println!(
        "LPR visitors: {} | status: {:?}",
        lpr.len(),
        summarize_statuses(&lpr)
    );
    let plate_total = lpr
        .iter()
        .map(|visitor| visitor.license_plates.len())
        .sum::<usize>();
    println!("plates still bound: {plate_total}");
    if !mode.apply {
        println!("\n[dry-run] no changes. Re-run with --apply.");
        return Ok(());
    }

    let mut cancelled = 0;
    let mut stripped = 0;
    for visitor in &lpr {
        if !visitor.is_cancelled() {
            client
                .cancel_visitor(&visitor.id)
                .await
                .with_context(|| format!("failed while cleaning visitor {}", visitor.id))?;
            cancelled += 1;
        }
        let detail = client.visitor(&visitor.id).await?;
        for plate in detail.license_plates {
            client
                .unassign_license_plate(&visitor.id, &plate.id)
                .await
                .with_context(|| {
                    format!(
                        "failed while unassigning plate {} from visitor {}",
                        plate.id, visitor.id
                    )
                })?;
            stripped += 1;
        }
    }
    println!("cancelled: {cancelled} | plates unassigned: {stripped}");
    let remaining = client
        .list_visitors()
        .await?
        .into_iter()
        .filter(|visitor| visitor.is_lpr())
        .collect::<Vec<_>>();
    let remaining_plates = remaining
        .iter()
        .map(|visitor| visitor.license_plates.len())
        .sum::<usize>();
    println!(
        "after: {} cancelled shells remain, {} plates still bound",
        remaining.len(),
        remaining_plates
    );
    println!(
        "note: cancelled shells must be cleared in the UniFi Access UI or expire at end_time."
    );
    Ok(())
}

fn epc_report(args: EpcReportArgs) -> Result<()> {
    let epcs = read_epcs(&args.report)?;
    let unique = epcs.iter().cloned().collect::<BTreeSet<_>>();
    println!("rows: {} | unique EPCs: {}", epcs.len(), unique.len());
    if args.list {
        for epc in unique {
            println!("{}", normalize_epc(&epc)?);
        }
    }
    Ok(())
}

fn unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system time does not fit in an i64")
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn extract_all_does_not_conflict_with_the_default_window() {
        let cli = Cli::try_parse_from(["fcr-gate-admin", "extract-plates", "--all"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn extract_rejects_an_explicit_window_with_all() {
        let cli = Cli::try_parse_from(["fcr-gate-admin", "extract-plates", "--all", "--days", "7"]);
        assert!(cli.is_err());
    }

    #[test]
    fn live_admin_modes_are_mutually_exclusive() {
        let cli =
            Cli::try_parse_from(["fcr-gate-admin", "cleanup-visitors", "--dry-run", "--apply"]);
        assert!(cli.is_err());
    }
}
