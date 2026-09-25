//! Thin async helpers over `icann-rdap-client` with built-in IANA bootstrapping.
//!
//! Failures are returned as human-readable strings so each binary can place them
//! in the `error` column of its output rows and continue with the next input row.

use icann_rdap_client::http::Client;
use icann_rdap_client::prelude::*;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::response::{Domain, Entity, Nameserver, Network, RdapResponse};

/// Shared RDAP client + bootstrap store. Create one per process and reuse it
/// for all queries so the IANA bootstrap registries are fetched only once.
pub struct RdapContext {
    client: Client,
    store: MemoryBootstrapStore,
}

impl RdapContext {
    /// Creates a new context with default client configuration.
    pub fn new() -> Result<Self, String> {
        let config = ClientConfig::default()
            .from_config()
            .user_agent_suffix("rdap-utils")
            .build();
        let client =
            create_client(&config).map_err(|e| format!("failed to create HTTP client: {e}"))?;
        Ok(Self {
            client,
            store: MemoryBootstrapStore::new(),
        })
    }

    /// Looks up a domain name and returns the parsed RDAP domain object.
    pub async fn domain(&self, name: &str) -> Result<Domain, String> {
        // Use the explicit Domain constructor: `QueryType::from_str` would
        // misclassify names matching `^ns...` (e.g. "nsw.gov.au") as
        // Nameserver lookups and hit the wrong RDAP endpoint.
        let query =
            QueryType::domain(name).map_err(|e| format!("invalid domain name '{name}': {e}"))?;
        let data = self.request(&query).await?;
        match data.rdap {
            RdapResponse::Domain(d) => Ok(*d),
            other => Err(self.unexpected(name, other)),
        }
    }

    /// Looks up an IP address (or CIDR block) and returns the parsed RDAP
    /// ip network object. Non-IP input fails fast with a validation error
    /// instead of being guessed as some other query type.
    pub async fn network(&self, ip: &str) -> Result<Network, String> {
        let query = Self::ip_query(ip)?;
        let data = self.request(&query).await?;
        match data.rdap {
            RdapResponse::Network(n) => Ok(*n),
            other => Err(self.unexpected(ip, other)),
        }
    }

    /// Looks up a nameserver by name and returns the parsed RDAP nameserver
    /// object. Used as a fallback when a domain document lists a nameserver
    /// without its IP addresses.
    pub async fn nameserver(&self, name: &str) -> Result<Nameserver, String> {
        let query =
            QueryType::ns(name).map_err(|e| format!("invalid nameserver name '{name}': {e}"))?;
        let data = self.request(&query).await?;
        match data.rdap {
            RdapResponse::Nameserver(n) => Ok(*n),
            other => Err(self.unexpected(name, other)),
        }
    }

    /// Parses an IP address or CIDR block into a query type.
    fn ip_query(ip: &str) -> Result<QueryType, String> {
        QueryType::ipv4(ip)
            .or_else(|_| QueryType::ipv6(ip))
            .or_else(|_| QueryType::ipv4cidr(ip))
            .or_else(|_| QueryType::ipv6cidr(ip))
            .map_err(|_| format!("invalid IP address or CIDR block: '{ip}'"))
    }

    async fn request(&self, query: &QueryType) -> Result<ResponseData, String> {
        rdap_bootstrapped_request(query, &self.client, &self.store, |_| {})
            .await
            .map_err(describe_error)
    }

    /// Formats an unexpected response. Note that RFC 9083 error documents
    /// (e.g. HTTP 404) arrive as a parsed `ErrorResponse`, not as `Err`.
    fn unexpected(&self, item: &str, other: RdapResponse) -> String {
        if let RdapResponse::ErrorResponse(err) = other {
            let code = err.error_code.to_string();
            let title = err.title.as_deref().map(str::to_string).unwrap_or_default();
            return if title.is_empty() {
                format!("RDAP server returned error {code}")
            } else {
                format!("RDAP server returned error {code}: {title}")
            };
        }
        format!("unexpected RDAP response for '{item}'")
    }
}

/// All CIDR blocks from a network's `cidr0_cidrs` extension, each as
/// `prefix/length`. Empty when the registry does not provide the extension.
pub fn cidr_blocks(net: &Network) -> Vec<String> {
    net.cidr0_cidrs
        .as_ref()
        .map(|cs| cs.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// Finds the first entity (top level) whose roles include `role` and returns
/// a contact name from its subtree: its own vCard full name, then organization
/// Finds the first entity (at any depth, document order) whose roles include
/// `role` and returns a contact name from its subtree: its own vCard full
/// name, then organization name, then the same from any nested entities.
fn entity_name_in(entities: Option<&Vec<Entity>>, role: &str) -> Option<String> {
    // Depth-first search (document order) for an entity carrying the role.
    let mut stack: Vec<&Entity> = entities.map(|es| es.iter()).unwrap_or_default().collect();
    let mut found = None;
    while let Some(e) = stack.pop() {
        if e.roles().iter().any(|r| r.eq_ignore_ascii_case(role)) {
            found = Some(e);
            break;
        }
        push_children(&mut stack, e);
    }
    let entity = found?;

    // Then the first usable contact name within its subtree.
    let mut stack: Vec<&Entity> = vec![entity];
    while let Some(e) = stack.pop() {
        if let Some(name) = e
            .contact()
            .and_then(|c| c.full_name().map(str::to_string))
            .or_else(|| {
                e.contact()
                    .and_then(|c| c.organization_name().map(str::to_string))
            })
        {
            return Some(name);
        }
        push_children(&mut stack, e);
    }
    None
}

/// Pushes an entity's nested entities onto the stack in reverse so a depth-
/// first walk visits children in document order.
fn push_children<'a>(stack: &mut Vec<&'a Entity>, e: &'a Entity) {
    let children: Vec<&Entity> = e
        .object_common
        .entities
        .as_deref()
        .unwrap_or_default()
        .iter()
        .rev()
        .collect();
    stack.extend(children);
}

/// The contact name of the first entity (at any depth) with the given role,
/// e.g. `abuse`, `administrative` or `technical`. Empty when absent.
pub fn entity_name(entities: Option<&Vec<Entity>>, role: &str) -> String {
    entity_name_in(entities, role).unwrap_or_default()
}

/// The registrant name of a network: the entity with the `registrant` role.
/// Empty when the registry reports no registrant (common for RIR allocations).
pub fn registrant_name(net: &Network) -> String {
    entity_name(net.object_common.entities.as_ref(), "registrant")
}

/// The display name of a nameserver (`ldhName`, falling back to `unicodeName`).
pub fn nameserver_name(ns: &Nameserver) -> String {
    ns.ldh_name
        .clone()
        .or_else(|| ns.unicode_name.clone())
        .unwrap_or_default()
}

/// All IP addresses (v4 and v6) listed on a nameserver object.
pub fn nameserver_ips(ns: &Nameserver) -> Vec<String> {
    let mut ips = Vec::new();
    if let Some(addrs) = ns.ip_addresses.as_ref() {
        if let Some(v4) = addrs.v4.as_ref() {
            ips.extend(v4.vec().iter().cloned());
        }
        if let Some(v6) = addrs.v6.as_ref() {
            ips.extend(v6.vec().iter().cloned());
        }
    }
    ips
}

/// The registrar name of a domain: the first entity with the `registrar` role,
/// preferring its vCard full name and falling back to its organization name.
pub fn registrar_name(domain: &Domain) -> String {
    domain
        .object_common
        .entities
        .iter()
        .flatten()
        .find_map(|e| {
            e.roles()
                .iter()
                .any(|r| r.eq_ignore_ascii_case("registrar"))
                .then(|| {
                    e.contact()
                        .and_then(|c| c.full_name().map(str::to_string))
                        .or_else(|| {
                            e.contact()
                                .and_then(|c| c.organization_name().map(str::to_string))
                        })
                        .unwrap_or_else(|| "unknown".to_string())
                })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Converts client errors into a concise, human-readable message.
fn describe_error(e: RdapClientError) -> String {
    match e {
        RdapClientError::BootstrapUnavailable => {
            "no bootstrap entry available (unknown RIR or registry)".to_string()
        }
        RdapClientError::ParsingError(info) => format!(
            "RDAP response could not be parsed (HTTP {} from {})",
            info.http_data.status_code, info.http_data.host
        ),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_network(entities: serde_json::Value) -> Network {
        serde_json::from_value(serde_json::json!({
            "objectClassName": "ip network",
            "handle": "NET-TEST",
            "startAddress": "10.0.0.0",
            "endAddress": "10.255.255.255",
            "entities": entities
        }))
        .expect("test network deserializes")
    }

    #[test]
    fn registrant_name_from_own_vcard() {
        let net = test_network(serde_json::json!([
            {
                "objectClassName": "entity",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Example Registrant"]]
                ]
            }
        ]));
        assert_eq!(registrant_name(&net), "Example Registrant");
    }

    #[test]
    fn registrant_name_from_nested_entity() {
        let net = test_network(serde_json::json!([
            {
                "objectClassName": "entity",
                "roles": ["registrant"],
                "entities": [
                    {
                        "objectClassName": "entity",
                        "roles": ["administrative"],
                        "vcardArray": ["vcard", [["org", {}, "text", "Nested Org"]]]
                    }
                ]
            }
        ]));
        assert_eq!(registrant_name(&net), "Nested Org");
    }

    #[test]
    fn entity_name_finds_nested_role_entity() {
        let net = test_network(serde_json::json!([
            {
                "objectClassName": "entity",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Example Registrant"]]
                ],
                "entities": [
                    {
                        "objectClassName": "entity",
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Abuse Contact"]]
                        ]
                    }
                ]
            }
        ]));
        assert_eq!(
            entity_name(net.object_common.entities.as_ref(), "abuse"),
            "Abuse Contact"
        );
        assert_eq!(
            entity_name(net.object_common.entities.as_ref(), "administrative"),
            ""
        );
    }

    #[test]
    fn missing_registrant_yields_empty() {
        let net = test_network(serde_json::json!([
            {
                "objectClassName": "entity",
                "roles": ["administrative"],
                "vcardArray": [["fn", {}, "text", "Some Admin"]]
            }
        ]));
        assert_eq!(registrant_name(&net), "");
    }
}
