//! `networks-of-nameservers` - find the IP networks where each domain's
//! nameservers are located.
//!
//! For every input domain an RDAP bootstrap query returns its nameservers;
//! for every IP address listed on a nameserver a second RDAP query returns
//! the containing network (start/end addresses). Rows that fail carry the
//! error in the last column; processing always continues with the next row.

use std::process::ExitCode;

use clap::Parser;
use rdap_utils::input;
use rdap_utils::output::{self, OutputFormat, Record};
use rdap_utils::rdap::{RdapContext, nameserver_ips, nameserver_name};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "networks-of-nameservers",
    version,
    about = "Find the IP networks containing each domain's nameservers via RDAP"
)]
struct Cli {
    /// Input file with one domain per line, or a CSV file (use --column). "-" reads stdin.
    #[arg(short, long)]
    input: String,

    /// For CSV input: header name or 1-based index of the column holding the domain name.
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
struct NsNetworkRow {
    domain: String,
    nameserver: String,
    ip: String,
    start_address: String,
    end_address: String,
    error: String,
}

impl Record for NsNetworkRow {
    const HEADER: &'static [&'static str] = &[
        "domain",
        "nameserver",
        "ip",
        "start_address",
        "end_address",
        "error",
    ];

    fn row(&self) -> Vec<String> {
        vec![
            self.domain.clone(),
            self.nameserver.clone(),
            self.ip.clone(),
            self.start_address.clone(),
            self.end_address.clone(),
            self.error.clone(),
        ]
    }
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
    let mut rows: Vec<NsNetworkRow> = Vec::new();
    let mut errors = 0usize;

    for entry in entries {
        let domain = match entry {
            Err(msg) => {
                errors += 1;
                eprintln!("warn: {msg}");
                rows.push(NsNetworkRow {
                    domain: String::new(),
                    nameserver: String::new(),
                    ip: String::new(),
                    start_address: String::new(),
                    end_address: String::new(),
                    error: msg,
                });
                continue;
            }
            Ok(domain) => domain,
        };
        match ctx.domain(&domain).await {
            Err(e) => {
                errors += 1;
                eprintln!("warn: {domain}: {e}");
                rows.push(NsNetworkRow {
                    domain,
                    nameserver: String::new(),
                    ip: String::new(),
                    start_address: String::new(),
                    end_address: String::new(),
                    error: e,
                });
            }
            Ok(d) => {
                let nss = d.nameservers.clone().unwrap_or_default();
                if nss.is_empty() {
                    errors += 1;
                    let msg = "no nameservers listed for domain".to_string();
                    eprintln!("warn: {domain}: {msg}");
                    rows.push(NsNetworkRow {
                        domain,
                        nameserver: String::new(),
                        ip: String::new(),
                        start_address: String::new(),
                        end_address: String::new(),
                        error: msg,
                    });
                    continue;
                }
                for ns in &nss {
                    let name = nameserver_name(ns);
                    let ips = nameserver_ips(ns);
                    if ips.is_empty() {
                        errors += 1;
                        let msg = "nameserver has no IP addresses".to_string();
                        eprintln!("warn: {domain} ({name}): {msg}");
                        rows.push(NsNetworkRow {
                            domain: domain.clone(),
                            nameserver: name,
                            ip: String::new(),
                            start_address: String::new(),
                            end_address: String::new(),
                            error: msg,
                        });
                        continue;
                    }
                    for ip in ips {
                        match ctx.network(&ip).await {
                            Ok(net) => rows.push(NsNetworkRow {
                                domain: domain.clone(),
                                nameserver: name.clone(),
                                ip,
                                start_address: net.start_address.clone().unwrap_or_default(),
                                end_address: net.end_address.clone().unwrap_or_default(),
                                error: String::new(),
                            }),
                            Err(e) => {
                                errors += 1;
                                eprintln!("warn: {domain} ({name}, {ip}): {e}");
                                rows.push(NsNetworkRow {
                                    domain: domain.clone(),
                                    nameserver: name.clone(),
                                    ip,
                                    start_address: String::new(),
                                    end_address: String::new(),
                                    error: e,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    output::write_output(&cli.output, cli.format, &rows)?;
    Ok(errors)
}
