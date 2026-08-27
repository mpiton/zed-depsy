#![no_main]

use depsy_lsp::parsers::Parser;
use depsy_lsp::parsers::npm::NpmParser;
use libfuzzer_sys::fuzz_target;
use std::panic::AssertUnwindSafe;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let parser = NpmParser::new();

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));

        if let Ok(deps) = result {
            let lines: Vec<&str> = content.lines().collect();

            for dep in &deps {
                for span in [&dep.name_span, &dep.version_span] {
                    assert!((span.line as usize) < lines.len(), "span.line out of range");

                    let line = lines[span.line as usize];
                    let line_len = line.len() as u32;

                    assert!(
                        span.line_start <= span.line_end,
                        "line_start must be <= line_end"
                    );
                    assert!(
                        span.line_start <= line_len,
                        "line_start must be within line bounds"
                    );
                    assert!(
                        span.line_end <= line_len,
                        "line_end must be within line bounds"
                    );
                }
            }
        }
    }
});
