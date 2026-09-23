//! Output formatting: CSV, JSON array, NDJSON (JSON lines), and JSON sequences
//! (RFC 7464).

use std::fmt::{Display, Formatter};
use std::io::{self, Write};
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::Context;
use serde::Serialize;

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// CSV with a header row.
    Csv,
    /// A single pretty-printed JSON array of records.
    Json,
    /// One JSON object per line (JSON lines / jsonl).
    NdJson,
    /// RFC 7464 JSON sequence: `0x1F` before the first record, records separated by `0x1E`.
    JsonSeq,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            "ndjson" | "jsonl" | "json-lines" => Ok(Self::NdJson),
            "jsonseq" | "json-seq" | "json-sequences" => Ok(Self::JsonSeq),
            other => Err(format!(
                "unknown format '{other}' (expected one of: csv, json, ndjson, jsonseq)"
            )),
        }
    }
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::NdJson => "ndjson",
            Self::JsonSeq => "jsonseq",
        };
        f.write_str(s)
    }
}

/// A result row: serializable to JSON and mappable to a flat CSV row.
pub trait Record: Serialize {
    /// Column headers, in the same order as the values returned by [`row`](Self::row).
    const HEADER: &'static [&'static str];

    /// Flat string values for CSV output. By convention the last column is `error`
    /// (empty on success).
    fn row(&self) -> Vec<String>;
}

/// Writes `records` to `out` in the requested format.
pub fn emit<R: Record>(
    out: &mut impl Write,
    format: OutputFormat,
    records: &[R],
) -> io::Result<()> {
    match format {
        OutputFormat::Csv => {
            let mut w = csv::Writer::from_writer(&mut *out);
            w.write_record(R::HEADER)?;
            for r in records {
                w.write_record(r.row())?;
            }
            w.flush()?;
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut *out, records)?;
            out.write_all(b"\n")?;
        }
        OutputFormat::NdJson => {
            for r in records {
                serde_json::to_writer(&mut *out, r)?;
                out.write_all(b"\n")?;
            }
        }
        OutputFormat::JsonSeq => {
            // RFC 7464: the first record is preceded by 0x1F and records are
            // separated by a single 0x1E.
            if !records.is_empty() {
                out.write_all(&[0x1f])?;
            }
            for (i, r) in records.iter().enumerate() {
                if i > 0 {
                    out.write_all(&[0x1e])?;
                }
                serde_json::to_writer(&mut *out, r)?;
            }
        }
    }
    Ok(())
}

/// Writes `rows` to `path` (or stdout) in the requested format.
pub fn write_output<R: Record>(
    path: &Option<String>,
    format: OutputFormat,
    rows: &[R],
) -> anyhow::Result<()> {
    let mut out: Box<dyn Write> = match path {
        Some(p) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("failed to create {p}"))?,
        )),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    emit(&mut out, format, rows)?;
    // Explicit flush: BufWriter's drop-based flush silently swallows I/O errors.
    out.flush()?;
    Ok(())
}

/// Maps a run result (the number of failed rows) to the process exit code:
/// `0` when every row succeeded, `1` otherwise. Fatal errors are printed to stderr.
pub fn finish(result: anyhow::Result<usize>) -> ExitCode {
    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// clap value parser for `--format`.
pub fn parse_format(s: &str) -> Result<OutputFormat, String> {
    s.parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Serialize)]
    struct Row {
        a: String,
        b: String,
        error: String,
    }

    impl Record for Row {
        const HEADER: &'static [&'static str] = &["a", "b", "error"];
        fn row(&self) -> Vec<String> {
            vec![self.a.clone(), self.b.clone(), self.error.clone()]
        }
    }

    fn rows() -> Vec<Row> {
        vec![
            Row {
                a: "x".into(),
                b: "y".into(),
                error: String::new(),
            },
            Row {
                a: "z".into(),
                b: "w".into(),
                error: "boom".into(),
            },
        ]
    }

    #[test]
    fn format_parsing() {
        assert_eq!("csv".parse::<OutputFormat>().unwrap(), OutputFormat::Csv);
        assert_eq!(
            "jsonl".parse::<OutputFormat>().unwrap(),
            OutputFormat::NdJson
        );
        assert_eq!(
            "JSONSEQ".parse::<OutputFormat>().unwrap(),
            OutputFormat::JsonSeq
        );
        assert!("bogus".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn csv_output_has_header_and_rows() {
        let mut buf = Vec::new();
        emit(&mut buf, OutputFormat::Csv, &rows()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "a,b,error");
        assert_eq!(lines[1], "x,y,");
        assert_eq!(lines[2], "z,w,boom");
    }

    #[test]
    fn json_output_is_an_array() {
        let mut buf = Vec::new();
        emit(&mut buf, OutputFormat::Json, &rows()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["error"], "");
        assert_eq!(v[1]["error"], "boom");
    }

    #[test]
    fn ndjson_output_is_one_object_per_line() {
        let mut buf = Vec::new();
        emit(&mut buf, OutputFormat::NdJson, &rows()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.is_object());
        }
    }

    #[test]
    fn jsonseq_output_uses_rfc7464_separators() {
        let mut buf = Vec::new();
        emit(&mut buf, OutputFormat::JsonSeq, &rows()).unwrap();
        assert_eq!(buf[0], 0x1f);
        // exactly one 0x1E separator between the two records
        assert_eq!(buf.iter().filter(|&&b| b == 0x1e).count(), 1);
        let first = &buf[1..buf.iter().position(|&b| b == 0x1e).unwrap()];
        let second = &buf[buf.iter().position(|&b| b == 0x1e).unwrap() + 1..];
        assert!(serde_json::from_slice::<serde_json::Value>(first).is_ok());
        assert!(serde_json::from_slice::<serde_json::Value>(second).is_ok());
    }

    #[test]
    fn jsonseq_output_empty_is_empty() {
        let mut buf = Vec::new();
        emit(&mut buf, OutputFormat::JsonSeq, &[] as &[Row]).unwrap();
        assert!(buf.is_empty());
    }
}
