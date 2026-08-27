//! Regression tests for malformed `Cargo.toml` inputs that previously
//! crashed [`CargoParser`] or produced spans outside their reported line.

use depsy_lsp::parsers::Parser;
use depsy_lsp::parsers::cargo::CargoParser;

/// Asserts that every dependency's [`Span`] sits inside the corresponding
/// content line. Matches the invariant enforced by `fuzz_targets/fuzz_cargo.rs`,
/// so the same input either passes both or fails both.
fn assert_spans_within_lines(content: &str) {
    let deps = CargoParser::new().parse(content);
    let lines: Vec<&str> = content.lines().collect();

    for dep in &deps {
        for span in [&dep.name_span, &dep.version_span] {
            assert!((span.line as usize) < lines.len(), "span.line out of range");
            let line = lines[span.line as usize];
            let line_len = line.len() as u32;
            assert!(span.line_start <= span.line_end);
            assert!(span.line_start <= line_len);
            assert!(span.line_end <= line_len);
        }
    }
}

/// Fuzz crash `56ee2249d56fe0b2e7564f6d7425e3104762e094`: an unterminated
/// basic-string value extends across multiple lines (the bytes between `}`
/// and `d-e_f"` are NUL padding produced by libFuzzer). The resulting
/// `Str` token spans several `line_ranges`, which used to make
/// `find_range_span` perform `needle.start() - line_range.start()` with
/// `needle.start() < line_range.start()`, triggering a `TextSize`
/// subtraction overflow.
#[test]
fn malformed_multiline_string_does_not_panic() {
    let bytes = include_bytes!("fixtures/cargo_text_size_underflow.bin");
    let content = std::str::from_utf8(bytes).expect("fixture is valid UTF-8");
    assert_spans_within_lines(content);
}

/// Fuzz crash `6194e2869128e7d3c2ff0e91bcc40bc828f5778f`: a basic string
/// whose content is `\n` (i.e. `"\n"` straddling two physical lines).
/// `line_ranges` used to extend through the trailing newline byte, so
/// `find_range_span` accepted a needle whose `end` pointed at the `\n`
/// position. The returned span had `line_end == line.len() + 1`,
/// outside the visible line content and tripping the fuzz invariant.
#[test]
fn newline_only_string_value_keeps_span_within_line() {
    let bytes = include_bytes!("fixtures/cargo_span_past_line_end.bin");
    let content = std::str::from_utf8(bytes).expect("fixture is valid UTF-8");
    assert_spans_within_lines(content);
}
