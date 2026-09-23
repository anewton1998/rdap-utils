//! Reads a list of items (IP addresses or domain names) from a plain text file,
//! a CSV file, or standard input.

use std::io::Read;

use anyhow::{Context, Result, bail};

/// A single input row: either the item to process, or the error message for a
/// row that could not yield an item (e.g. an empty or short CSV row). Callers
/// must emit an output row for every entry so no input row is silently dropped.
pub type InputEntry = Result<String, String>;

/// Reads the list of items from `path`.
///
/// * `path` - a file path, or `"-"` to read standard input.
/// * `column` - for CSV input: the header name (case-insensitive) or 1-based
///   column index holding the item. Ignored for plain text input; required
///   when the input is detected as CSV.
///
/// Input is treated as CSV when a `column` is given or the path ends in `.csv`;
/// otherwise it is parsed as plain text (one item per line).
pub fn read_items(path: &str, column: Option<&str>) -> Result<Vec<InputEntry>> {
    let content = if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("failed to read standard input")?;
        s
    } else {
        std::fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?
    };

    let is_csv = column.is_some() || path.to_ascii_lowercase().ends_with(".csv");
    if is_csv {
        parse_csv(&content, column)
    } else {
        Ok(parse_text(&content).into_iter().map(Ok).collect())
    }
}

/// Plain text: one item per line; blank lines and `#` comments are skipped.
fn parse_text(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// CSV: returns one entry per data row. Rows whose selected column is missing
/// or empty become `Err` entries (with the line number) instead of being
/// silently dropped, so callers can emit an error row for them.
fn parse_csv(content: &str, column: Option<&str>) -> Result<Vec<InputEntry>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        // tolerate rows with a different field count than the header so each
        // bad row becomes a per-row error entry instead of aborting the run
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .context("CSV input has no header row")?
        .into_iter()
        .map(|h| h.to_string())
        .collect();

    let (idx, col_label) = match column {
        Some(c) if c.parse::<usize>().is_err() => {
            let pos = headers
                .iter()
                .position(|h| h.eq_ignore_ascii_case(c))
                .with_context(|| {
                    format!(
                        "column '{c}' not found in CSV header: {}",
                        headers.join(", ")
                    )
                })?;
            (pos, headers[pos].clone())
        }
        Some(c) => {
            let i = c.parse::<usize>().context("invalid column index")?;
            if i == 0 {
                bail!("column index must be >= 1 (got '0')");
            }
            (i - 1, format!("{i}"))
        }
        None => bail!("CSV input requires --column <name|index>"),
    };

    if idx >= headers.len() {
        bail!(
            "column index {} is out of range (CSV has {} columns: {})",
            idx + 1,
            headers.len(),
            headers.join(", ")
        );
    }

    let mut items = Vec::new();
    for (i, row) in reader.records().enumerate() {
        let line = i + 2; // 1-based line number, accounting for the header row
        let row = row.with_context(|| format!("failed to parse CSV line {line}"))?;
        match row.get(idx) {
            Some(v) if !v.trim().is_empty() => items.push(Ok(v.trim().to_string())),
            Some(_) => items.push(Err(format!(
                "CSV line {line}: empty value in column '{col_label}'"
            ))),
            None => items.push(Err(format!(
                "CSV line {line}: row has {} column(s), need at least {} for column '{col_label}'",
                row.len(),
                idx + 1
            ))),
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_parsing_skips_blanks_and_comments() {
        let items = parse_text("  iana.org \n\n# a comment\nicann.org\n");
        assert_eq!(items, vec!["iana.org", "icann.org"]);
    }

    #[test]
    fn csv_by_header_name_empty_cell_is_an_error_entry() {
        let items = parse_csv(
            "id,domain,note\n1,foo.com,x\n2,,y\n3,bar.net,z\n",
            Some("domain"),
        )
        .unwrap();
        assert_eq!(
            items,
            vec![
                Ok("foo.com".to_string()),
                Err("CSV line 3: empty value in column 'domain'".to_string()),
                Ok("bar.net".to_string()),
            ]
        );
    }

    #[test]
    fn csv_by_index() {
        let items = parse_csv("id,domain,note\n1,foo.com,x\n2,bar.net,y\n", Some("2")).unwrap();
        assert_eq!(
            items,
            vec![Ok("foo.com".to_string()), Ok("bar.net".to_string())]
        );
    }

    #[test]
    fn csv_short_row_is_an_error_entry() {
        let items = parse_csv("id,domain,note\n1\n", Some("2")).unwrap();
        assert_eq!(
            items,
            vec![Err(
                "CSV line 2: row has 1 column(s), need at least 2 for column '2'".to_string()
            )]
        );
    }

    #[test]
    fn csv_missing_column_errors() {
        assert!(parse_csv("a,b\n1,2\n", Some("nope")).is_err());
        assert!(parse_csv("a,b\n1,2\n", None).is_err());
        assert!(parse_csv("a,b\n1,2\n", Some("9")).is_err());
        // index 0 is not a valid 1-based column index and must not panic
        assert!(parse_csv("a,b\n1,2\n", Some("0")).is_err());
    }

    #[test]
    fn csv_header_match_is_case_insensitive() {
        let items = parse_csv("ID,Domain\n1,foo.com\n", Some("domain")).unwrap();
        assert_eq!(items, vec![Ok("foo.com".to_string())]);
    }
}
