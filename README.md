# rdap-utils

Three small RDAP command-line tools built on [`icann-rdap-client`](https://crates.io/crates/icann-rdap-client)
and [`icann-rdap-common`](https://crates.io/crates/icann-rdap-common), with built-in IANA bootstrapping.

| Binary | Purpose | Input items |
|---|---|---|
| `find-ip-networks` | Resolve each IP address to its registered network: handle, start/end addresses, and all CIDR blocks from the RIR `cidr0_cidrs` extension (pipe-separated in CSV, array in JSON) | IP addresses |
| `find-protected-domains` | Verify each domain is "locked" (has `client delete/transfer/update prohibited` statuses) and report its registrar | Domain names |
| `networks-of-nameservers` | Find the IP network containing each of a domain's nameserver IPs (handle, start/end addresses, CIDR blocks; falls back to an RDAP nameserver lookup when the domain document lacks NS IPs) | Domain names |

## Build

```sh
cargo build --release
```

Binaries land in `target/release/`: `find-ip-networks`, `find-protected-domains`,
`networks-of-nameservers`.

## Common options (all three binaries)

```
-i, --input <INPUT>      Input file: plain text (one item per line) or CSV. "-" reads stdin.
    --column <COLUMN>    For CSV input: header name (case-insensitive) or 1-based column
                         index holding the item. Required for CSV.
-o, --output <OUTPUT>    Output file (defaults to stdout).
    --format <FORMAT>    csv (default), json, ndjson (aka jsonl), or jsonseq (RFC 7464).
```

Input is treated as CSV when `--column` is given or the path ends in `.csv`;
otherwise it is plain text (blank lines and `#` comments are skipped).

## Output & error handling

Every input row always produces at least one output row. Failures (no bootstrap
entry, HTTP/RDAP errors such as 404, unexpected response types) are:

1. logged as a `warn:` line on stderr, and
2. recorded in the **last column / `"error"` field** of that row (empty on success).

Processing always continues with the next input row. The exit code is `0` when
every row succeeded and `1` if any row failed (or on fatal usage errors).

For `networks-of-nameservers`, one output row is emitted per nameserver IP; a
failed domain lookup produces a single row with only `domain` + `error`.

## Examples

```sh
# plain text input, CSV to stdout
echo "199.43.0.0" > ips.txt
find-ip-networks -i ips.txt
# ip,handle,start_address,end_address,cidr_blocks,error
# 199.43.0.0,NET-199-43-0-0,199.43.0.0,199.43.0.255,199.43.0.0/24,

# CSV input picking the column by name; JSON array to a file
find-protected-domains -i domains.csv --column domain --format json -o report.json

# stdin, NDJSON out
cat domains.txt | networks-of-nameservers -i - --format ndjson

# RFC 7464 JSON sequence (0x1F prefix, 0x1E separators)
find-ip-networks -i ips.txt --format jsonseq > ip_inventory.jsonseq
```

## Tests

```sh
cargo test        # unit tests for input parsing and all four output formats
cargo clippy --all-targets
```
