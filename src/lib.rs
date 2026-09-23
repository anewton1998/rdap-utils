//! Shared library for the `rdap-utils` binaries.
//!
//! Provides input parsing ([input]), output formatting in CSV / JSON / NDJSON /
//! JSON-sequence form ([output]), and thin async RDAP helpers built on top of
//! `icann-rdap-client` with built-in IANA bootstrapping ([rdap]).

pub mod input;
pub mod output;
pub mod rdap;
