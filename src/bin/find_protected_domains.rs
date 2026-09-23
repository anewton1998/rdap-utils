//! `find-protected-domains` - verify that each domain in a list is "locked"
//! against malicious modification.
//!
//! A domain is considered protected when its RDAP `status` array contains all
//! of: `client delete prohibited`, `client transfer prohibited`, and
//! `client update prohibited`. The registrar to contact is taken from the
//! first entity with the `registrar` role. Rows that fail carry the error in
//! the last column; processing always continues with the next row.

use std::process::ExitCode;

use clap::Parser;
use icann_rdap_common::response::ObjectCommonFields;
use rdap_utils::input;
use rdap_utils::output::{self, OutputFormat, Record};
use rdap_utils::rdap::{RdapContext, registrar_name};
use serde::Serialize;

/// Status values every domain must carry to be considered protected.
const REQUIRED_STATUS: &[&str] = &[
    "client delete prohibited",
    "client transfer prohibited",
    "client update prohibited",
];

#[derive(Parser)]
#[command(
    name = "find-protected-domains",
    version,
    about = "Check that each domain has the client*-prohibited RDAP statuses (is 'locked')"
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
struct ProtectedDomainRow {
    domain: String,
    registrar: String,
    protected: bool,
    status: Vec<String>,
    missing_status: Vec<String>,
    error: String,
}

impl Record for ProtectedDomainRow {
    const HEADER: &'static [&'static str] = &[
        "domain",
        "registrar",
        "protected",
        "status",
        "missing_status",
        "error",
    ];

    fn row(&self) -> Vec<String> {
        vec![
            self.domain.clone(),
            self.registrar.clone(),
            self.protected.to_string(),
            self.status.join("; "),
            self.missing_status.join("; "),
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
    let mut rows: Vec<ProtectedDomainRow> = Vec::with_capacity(entries.len());
    let mut errors = 0usize;

    for entry in entries {
        let domain = match entry {
            Err(msg) => {
                errors += 1;
                eprintln!("warn: {msg}");
                rows.push(ProtectedDomainRow {
                    domain: String::new(),
                    registrar: String::new(),
                    protected: false,
                    status: Vec::new(),
                    missing_status: Vec::new(),
                    error: msg,
                });
                continue;
            }
            Ok(domain) => domain,
        };
        match ctx.domain(&domain).await {
            Ok(d) => {
                let status: Vec<String> = d.status().to_vec();
                let missing: Vec<String> = REQUIRED_STATUS
                    .iter()
                    .filter(|s| !status.iter().any(|have| have.eq_ignore_ascii_case(s)))
                    .map(|s| s.to_string())
                    .collect();
                rows.push(ProtectedDomainRow {
                    domain,
                    registrar: registrar_name(&d),
                    protected: missing.is_empty(),
                    status,
                    missing_status: missing,
                    error: String::new(),
                });
            }
            Err(e) => {
                errors += 1;
                eprintln!("warn: {domain}: {e}");
                rows.push(ProtectedDomainRow {
                    domain,
                    registrar: String::new(),
                    protected: false,
                    status: Vec::new(),
                    missing_status: Vec::new(),
                    error: e,
                });
            }
        }
    }

    output::write_output(&cli.output, cli.format, &rows)?;
    Ok(errors)
}
