//! `networks-of-nameservers` - find the IP networks where each domain's
//! nameservers are located.
//!
//! For every input domain an RDAP bootstrap query returns its nameservers;
//! for every IP address listed on a nameserver a second RDAP query returns
//! the containing network (handle, start/end addresses, CIDR blocks). When the domain document
//! does not list IP addresses for a nameserver, a dedicated RDAP nameserver
//! lookup by name is used as a fallback. Rows that fail carry the error in
//! the last column; processing always continues with the next row.

use std::process::ExitCode;

use clap::Parser;
use icann_rdap_common::response::ObjectCommonFields;
use rdap_utils::input;
use rdap_utils::output::{self, OutputFormat, Record};
use rdap_utils::rdap::{
    RdapContext, cidr_blocks, entity_name, nameserver_ips, nameserver_name, registrant_name,
};
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

impl Record for NsNetworkRow {
    const HEADER: &'static [&'static str] = &[
        "domain",
        "nameserver",
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
            self.domain.clone(),
            self.nameserver.clone(),
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
                for ns in &nss {
                    let name = nameserver_name(ns);
                    let mut ips = nameserver_ips(ns);

                    // The domain document did not list IP addresses for this
                    // nameserver: fall back to a dedicated RDAP nameserver
                    // lookup by name.
                    if ips.is_empty() && !name.is_empty() {
                        match ctx.nameserver(&name).await {
                            Ok(found) => ips = nameserver_ips(&found),
                            Err(e) => {
                                errors += 1;
                                eprintln!("warn: {domain} ({name}): {e}");
                                rows.push(NsNetworkRow {
                                    domain: domain.clone(),
                                    nameserver: name,
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
                                    error: format!(
                                        "no IP addresses in domain response; nameserver lookup failed: {e}"
                                    ),
                                });
                                continue;
                            }
                        }
                    }

                    if ips.is_empty() {
                        errors += 1;
                        let msg = "nameserver has no IP addresses".to_string();
                        eprintln!("warn: {domain} ({name}): {msg}");
                        rows.push(NsNetworkRow {
                            domain: domain.clone(),
                            nameserver: name,
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
                    for ip in ips {
                        match ctx.network(&ip).await {
                            Ok(net) => rows.push(NsNetworkRow {
                                domain: domain.clone(),
                                nameserver: name.clone(),
                                ip,
                                handle: net.handle().unwrap_or_default().to_string(),
                                network_name: net.name.as_deref().unwrap_or_default().to_string(),
                                registrant: registrant_name(&net),
                                abuse: entity_name(net.object_common.entities.as_ref(), "abuse"),
                                administrative: entity_name(
                                    net.object_common.entities.as_ref(),
                                    "administrative",
                                ),
                                technical: entity_name(
                                    net.object_common.entities.as_ref(),
                                    "technical",
                                ),
                                start_address: net.start_address.clone().unwrap_or_default(),
                                end_address: net.end_address.clone().unwrap_or_default(),
                                cidr_blocks: cidr_blocks(&net),
                                error: String::new(),
                            }),
                            Err(e) => {
                                errors += 1;
                                eprintln!("warn: {domain} ({name}, {ip}): {e}");
                                rows.push(NsNetworkRow {
                                    domain: domain.clone(),
                                    nameserver: name.clone(),
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
                }
            }
        }
    }

    output::write_output(&cli.output, cli.format, &rows)?;
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_row_joins_cidr_blocks_with_pipe() {
        let row = NsNetworkRow {
            domain: "example.com".to_string(),
            nameserver: "ns1.example.net".to_string(),
            ip: "192.0.2.53".to_string(),
            handle: "NET-TEST".to_string(),
            registrant: String::new(),
            network_name: String::new(),
            abuse: String::new(),
            administrative: String::new(),
            technical: String::new(),
            start_address: "192.0.2.0".to_string(),
            end_address: "192.0.2.255".to_string(),
            cidr_blocks: vec!["192.0.2/24".to_string(), "198.51.100/24".to_string()],
            error: String::new(),
        };
        let r = row.row();
        assert_eq!(r[3], "NET-TEST");
        assert_eq!(r[11], "192.0.2/24|198.51.100/24");
    }

    #[test]
    fn json_row_serializes_cidr_blocks_as_array() {
        let row = NsNetworkRow {
            domain: "example.com".to_string(),
            nameserver: "ns1.example.net".to_string(),
            ip: "192.0.2.53".to_string(),
            handle: "NET-TEST".to_string(),
            registrant: String::new(),
            network_name: String::new(),
            abuse: String::new(),
            administrative: String::new(),
            technical: String::new(),
            start_address: "192.0.2.0".to_string(),
            end_address: "192.0.2.255".to_string(),
            cidr_blocks: vec!["192.0.2/24".to_string()],
            error: String::new(),
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["handle"], "NET-TEST");
        assert_eq!(v["cidr_blocks"], serde_json::json!(["192.0.2/24"]));
    }
}
