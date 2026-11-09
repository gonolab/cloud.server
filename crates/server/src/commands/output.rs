//! Plain-text output helpers for the management commands.

/// Prints rows as left-aligned columns under a header line.
pub fn print_table(header: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: &mut dyn Iterator<Item = &str>| {
        let mut out = String::new();
        for (index, (cell, width)) in cells.zip(&widths).enumerate() {
            if index + 1 == widths.len() {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<width$}  "));
            }
        }
        println!("{}", out.trim_end());
    };
    line(&mut header.iter().copied());
    for row in rows {
        line(&mut row.iter().map(String::as_str));
    }
}

/// Formats UNIX seconds as `YYYY-MM-DD HH:MM UTC`.
pub fn format_time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Formats an optional timestamp, with `none` for `None`.
pub fn format_optional_time(secs: Option<i64>, none: &str) -> String {
    secs.map_or_else(|| none.to_owned(), format_time)
}

/// Converts days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(format_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_optional_time(None, "never"), "never");
    }
}
