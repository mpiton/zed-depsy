//! Shared helpers for span-aware JSON parsing.
//!
//! Used by the npm (`package-lock.json`) and PHP (`composer.lock`) lockfile parsers
//! to convert byte-range information returned by the JSON parser into [`super::Span`]
//! values that the LSP layer can attach to diagnostic and inlay-hint positions.
//!
//! The key types are:
//! - `LineIndex` — pre-computes line-start byte offsets so that O(log n)
//!   `position()` calls can convert any byte offset to a `(line, column)` pair.
//! - `span_to_span` / `string_inner_to_span` — convert raw byte ranges into
//!   [`super::Span`] instances, returning `None` for multi-line ranges.

use super::Span;

/// Pre-computed byte offsets of each line start in a source string.
///
/// Constructed in O(n); each `position` query is O(log n) via binary search.
pub(crate) struct LineIndex {
    /// `offsets[i]` is the byte offset where line `i` starts.
    offsets: Vec<usize>,
}

impl std::fmt::Debug for LineIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineIndex")
            .field("lines", &self.offsets.len())
            .finish()
    }
}

impl LineIndex {
    /// Build a `LineIndex` from `content`. Always contains at least one entry (`0`).
    pub(crate) fn new(content: &str) -> Self {
        let mut offsets = Vec::with_capacity(content.len() / 32 + 1);
        offsets.push(0);
        for (i, byte) in content.bytes().enumerate() {
            if byte == b'\n' {
                offsets.push(i + 1);
            }
        }
        Self { offsets }
    }

    /// Convert a byte offset to a `(line, column)` pair, both 0-indexed.
    /// Columns are byte offsets within the line.
    /// Offsets past the end clamp to the last line.
    pub(crate) fn position(&self, byte_offset: usize) -> (u32, u32) {
        let line = self
            .offsets
            .partition_point(|&start| start <= byte_offset)
            .saturating_sub(1);
        let col = byte_offset - self.offsets[line];
        (line as u32, col as u32)
    }
}

/// Convert a byte range `[start, end)` to a `Span` if it fits on a single line.
/// Returns `None` if the range straddles a line boundary.
pub(crate) fn span_to_span(line_index: &LineIndex, start: usize, end: usize) -> Option<Span> {
    let (line_start, col_start) = line_index.position(start);
    let (line_end, col_end) = line_index.position(end);
    if line_start != line_end {
        return None;
    }
    Some(Span {
        line: line_start,
        line_start: col_start,
        line_end: col_end,
    })
}

/// Convert the outer (quote-inclusive) byte bounds of a JSON string to a
/// `Span` covering only its inner content.
///
/// **Precondition**: `(start, end)` must be a valid JSON string span, i.e.
/// `end >= start + 2` (covering at least the two surrounding quotes).
/// Returns `None` if the resulting inner range straddles a line boundary.
pub(crate) fn string_inner_to_span(
    line_index: &LineIndex,
    start: usize,
    end: usize,
) -> Option<Span> {
    if end < start + 2 {
        return None;
    }
    span_to_span(line_index, start + 1, end - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_empty_content() {
        let idx = LineIndex::new("");
        assert_eq!(idx.position(0), (0, 0));
    }

    #[test]
    fn line_index_first_line() {
        let idx = LineIndex::new("hello\nworld");
        assert_eq!(idx.position(0), (0, 0));
        assert_eq!(idx.position(4), (0, 4));
    }

    #[test]
    fn line_index_after_newline() {
        let idx = LineIndex::new("hello\nworld");
        assert_eq!(idx.position(6), (1, 0));
        assert_eq!(idx.position(10), (1, 4));
    }

    #[test]
    fn line_index_three_lines() {
        let idx = LineIndex::new("a\nbb\nccc");
        assert_eq!(idx.position(0), (0, 0));
        assert_eq!(idx.position(2), (1, 0));
        assert_eq!(idx.position(5), (2, 0));
        assert_eq!(idx.position(7), (2, 2));
    }

    #[test]
    fn line_index_offset_past_end_clamps_to_last_line() {
        let idx = LineIndex::new("ab");
        let (line, _col) = idx.position(99);
        assert_eq!(line, 0);
    }

    #[test]
    fn line_index_multibyte_utf8_byte_columns() {
        // "é" is 2 bytes in UTF-8. Columns are byte offsets.
        let content = "ab\néd";
        let idx = LineIndex::new(content);
        assert_eq!(idx.position(3), (1, 0)); // 'é' start
        assert_eq!(idx.position(5), (1, 2)); // 'd' (after 2-byte 'é')
    }

    #[test]
    fn span_to_span_single_line() {
        let idx = LineIndex::new("hello world");
        let s = span_to_span(&idx, 6, 11).unwrap();
        assert_eq!(s.line, 0);
        assert_eq!(s.line_start, 6);
        assert_eq!(s.line_end, 11);
    }

    #[test]
    fn span_to_span_multi_line_returns_none() {
        let idx = LineIndex::new("hello\nworld");
        assert!(span_to_span(&idx, 4, 8).is_none());
    }

    #[test]
    fn string_inner_to_span_strips_quotes() {
        // `"abc"` at bytes 0..5 — inner content `abc` is bytes 1..4.
        let idx = LineIndex::new(r#""abc""#);
        let s = string_inner_to_span(&idx, 0, 5).unwrap();
        assert_eq!(s.line, 0);
        assert_eq!(s.line_start, 1);
        assert_eq!(s.line_end, 4);
    }

    #[test]
    fn string_inner_to_span_empty_string() {
        // `""` at bytes 0..2 — inner is the empty range 1..1.
        let idx = LineIndex::new(r#""""#);
        let s = string_inner_to_span(&idx, 0, 2).unwrap();
        assert_eq!(s.line, 0);
        assert_eq!(s.line_start, 1);
        assert_eq!(s.line_end, 1);
    }

    #[test]
    fn string_inner_to_span_rejects_undersized_span() {
        // A span shorter than the two quotes is not a valid JSON string span.
        let idx = LineIndex::new("");
        assert!(string_inner_to_span(&idx, 0, 0).is_none());
        assert!(string_inner_to_span(&idx, 0, 1).is_none());
    }
}
