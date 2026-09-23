//! `find-ip-networks` - resolve each IP address in a list to its registered
//! network (CIDR block).
//!
//! For every input IP an RDAP bootstrap query returns the containing network:
//! start/end addresses and, when the registry provides the RIR `cidr0_cidrs`
//! extension, the CIDR block. Rows that fail carry the error in the last
//! column; processing always continues with the next row.

use std::process::ExitCode;

use clap::Parser;
use icann_rdap_common::response::{Cidr0CidrPrefix, Network};
use rdap_utils::input;
use rdap_utils::output::{self, OutputFormat, Record};
use rdap_utils::rdap::RdapContext;
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "find-ip-networks",
    version,
    about = "Find the registered IP network (CIDR block) for each input IP address"
)]
struct Cli {
    /// Input file with one IP address per line, or a CSV file (use --column). "-" reads stdin.
    #[arg(short, long)]
    input: String,

    /// For CSV input: header name or 1-based index of the column holding the IP address.
    #[arg(long)]
    column: Option<String>,

    /// Output file (defaults to stdout).
    #[arg(short, long)]
    output: Option<String>,

    /// Output format: csv, json, ndjson, or jsonseq (RFC 7464).
    #[arg(long, default_value = "csv", value_parser = output::parse_format)]
    format: OutputFormat,
}

#[derive(Serialize)]
struct IpNetworkRow {
    ip: String,
    start_address: String,
    end_address: String,
    cidr_block: String,
    error: String,
}

impl Record for IpNetworkRow {
    const HEADER: &'static [&'static str] =
        &["ip", "start_address", "end_address", "cidr_block", "error"];

    fn row(&self) -> Vec<String> {
        vec![
            self.ip.clone(),
            self.start_address.clone(),
            self.end_address.clone(),
            self.cidr_block.clone(),
            self.error.clone(),
        ]
    }
}

/// Formats the first `cidr0_cidrs` entry as `prefix/length`, if present.
fn cidr_block(net: &Network) -> String {
    net.cidr0_cidrs
        .as_ref()
        .and_then(|c| c.first())
        .map(|c| {
            let prefix = match &c.prefix {
                Some(Cidr0CidrPrefix::V4Prefix(p)) | Some(Cidr0CidrPrefix::V6Prefix(p)) => {
                    p.clone()
                }
                None => String::new(),
            };
            let len = c.length.as_ref().map(|l| l.to_string()).unwrap_or_default();
            format!("{prefix}/{len}")
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> ExitCode {
    output::finish(run(Cli::parse()).await)
}

async fn run(cli: Cli) -> anyhow::Result<usize> {
    let entries = input::read_items(&cli.input, cli.column.as_deref())?;
    if entries.is_empty() {
        anyhow::bail!("no items found in {}", cli.input);
    }

    let ctx = RdapContext::new().map_err(anyhow::Error::msg)?;
    let mut rows: Vec<IpNetworkRow> = Vec::with_capacity(entries.len());
    let mut errors = 0usize;

    for entry in entries {
        let ip = match entry {
            Err(msg) => {
                errors += 1;
                eprintln!("warn: {msg}");
                rows.push(IpNetworkRow {
                    ip: String::new(),
                    start_address: String::new(),
                    end_address: String::new(),
                    cidr_block: String::new(),
                    error: msg,
                });
                continue;
            }
            Ok(ip) => ip,
        };
        match ctx.network(&ip).await {
            Ok(net) => rows.push(IpNetworkRow {
                ip: ip.clone(),
                start_address: net.start_address.clone().unwrap_or_default(),
                end_address: net.end_address.clone().unwrap_or_default(),
                cidr_block: cidr_block(&net),
                error: String::new(),
            }),
            Err(e) => {
                errors += 1;
                eprintln!("warn: {ip}: {e}");
                rows.push(IpNetworkRow {
                    ip,
                    start_address: String::new(),
                    end_address: String::new(),
                    cidr_block: String::new(),
                    error: e,
                });
            }
        }
    }

    output::write_output(&cli.output, cli.format, &rows)?;
    Ok(errors)
}
