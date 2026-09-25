//! `find-ip-networks` - resolve each IP address in a list to its registered
//! network (CIDR block).
//!
//! For every input IP an RDAP bootstrap query returns the containing network:
//! start/end addresses and, when the registry provides the RIR `cidr0_cidrs`
//! extension, the CIDR block. Rows that fail carry the error in the last
//! column; processing always continues with the next row.

use std::process::ExitCode;

use clap::Parser;
use icann_rdap_common::response::ObjectCommonFields;
use rdap_utils::input;
use rdap_utils::output::{self, OutputFormat, Record};
use rdap_utils::rdap::{RdapContext, cidr_blocks, entity_name, registrant_name};
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
    handle: String,
    /// Name of the network's registrant (empty when not reported).
    registrant: String,
    /// The network's `name` field (empty when not reported).
    network_name: String,
    abuse: String,
    administrative: String,
    technical: String,

    start_address: String,
    end_address: String,
    /// All CIDR blocks from the registry's `cidr0_cidrs` extension (empty if absent).
    cidr_blocks: Vec<String>,
    error: String,
}

impl Record for IpNetworkRow {
    const HEADER: &'static [&'static str] = &[
        "ip",
        "handle",
        "network_name",
        "registrant",
        "abuse",
        "administrative",
        "technical",
        "start_address",
        "end_address",
        "cidr_blocks",
        "error",
    ];

    fn row(&self) -> Vec<String> {
        vec![
            self.ip.clone(),
            self.handle.clone(),
            self.network_name.clone(),
            self.registrant.clone(),
            self.abuse.clone(),
            self.administrative.clone(),
            self.technical.clone(),
            self.start_address.clone(),
            self.end_address.clone(),
            // pipe-separated in CSV; serialized as a JSON array otherwise
            self.cidr_blocks.join("|"),
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
    let mut rows: Vec<IpNetworkRow> = Vec::with_capacity(entries.len());
    let mut errors = 0usize;

    for entry in entries {
        let ip = match entry {
            Err(msg) => {
                errors += 1;
                eprintln!("warn: {msg}");
                rows.push(IpNetworkRow {
                    ip: String::new(),
                    handle: String::new(),
                    registrant: String::new(),
                    network_name: String::new(),
                    abuse: String::new(),
                    administrative: String::new(),
                    technical: String::new(),
                    start_address: String::new(),
                    end_address: String::new(),
                    cidr_blocks: Vec::new(),
                    error: msg,
                });
                continue;
            }
            Ok(ip) => ip,
        };
        match ctx.network(&ip).await {
            Ok(net) => rows.push(IpNetworkRow {
                ip: ip.clone(),
                handle: net.handle().unwrap_or_default().to_string(),
                network_name: net.name.as_deref().unwrap_or_default().to_string(),
                registrant: registrant_name(&net),
                abuse: entity_name(net.object_common.entities.as_ref(), "abuse"),
                administrative: entity_name(net.object_common.entities.as_ref(), "administrative"),
                technical: entity_name(net.object_common.entities.as_ref(), "technical"),
                start_address: net.start_address.clone().unwrap_or_default(),
                end_address: net.end_address.clone().unwrap_or_default(),
                cidr_blocks: cidr_blocks(&net),
                error: String::new(),
            }),
            Err(e) => {
                errors += 1;
                eprintln!("warn: {ip}: {e}");
                rows.push(IpNetworkRow {
                    ip,
                    handle: String::new(),
                    registrant: String::new(),
                    network_name: String::new(),
                    abuse: String::new(),
                    administrative: String::new(),
                    technical: String::new(),
                    start_address: String::new(),
                    end_address: String::new(),
                    cidr_blocks: Vec::new(),
                    error: e,
                });
            }
        }
    }

    output::write_output(&cli.output, cli.format, &rows)?;
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use icann_rdap_common::response::Network;

    fn test_network(cidr0: serde_json::Value) -> Network {
        serde_json::from_value(serde_json::json!({
            "objectClassName": "ip network",
            "handle": "NET-TEST",
            "startAddress": "10.0.0.0",
            "endAddress": "10.255.255.255",
            "cidr0_cidrs": cidr0
        }))
        .expect("test network deserializes")
    }

    #[test]
    fn all_cidr_blocks_are_reported() {
        let net = test_network(serde_json::json!([
            {"v4prefix": "10.0", "length": 8},
            {"v4prefix": "10.128", "length": 7}
        ]));
        assert_eq!(
            cidr_blocks(&net),
            vec!["10.0/8".to_string(), "10.128/7".to_string()]
        );
    }

    #[test]
    fn missing_cidr0_extension_yields_empty_list() {
        let net = test_network(serde_json::json!([]));
        assert!(cidr_blocks(&net).is_empty());
    }

    #[test]
    fn csv_row_joins_cidr_blocks_with_pipe() {
        let row = IpNetworkRow {
            ip: "10.1.2.3".to_string(),
            handle: "NET-TEST".to_string(),
            registrant: String::new(),
            network_name: String::new(),
            abuse: String::new(),
            administrative: String::new(),
            technical: String::new(),
            start_address: "10.0.0.0".to_string(),
            end_address: "10.255.255.255".to_string(),
            cidr_blocks: vec!["10.0/8".to_string(), "10.128/7".to_string()],
            error: String::new(),
        };
        assert_eq!(row.row()[9], "10.0/8|10.128/7");
    }

    #[test]
    fn json_row_serializes_cidr_blocks_as_array() {
        let row = IpNetworkRow {
            ip: "10.1.2.3".to_string(),
            handle: "NET-TEST".to_string(),
            registrant: String::new(),
            network_name: String::new(),
            abuse: String::new(),
            administrative: String::new(),
            technical: String::new(),
            start_address: "10.0.0.0".to_string(),
            end_address: "10.255.255.255".to_string(),
            cidr_blocks: vec!["10.0/8".to_string(), "10.128/7".to_string()],
            error: String::new(),
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["cidr_blocks"], serde_json::json!(["10.0/8", "10.128/7"]));
    }
}
