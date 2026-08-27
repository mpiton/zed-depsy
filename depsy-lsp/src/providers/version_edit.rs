use crate::file_types::FileType;
use crate::parsers::Dependency;

#[derive(Clone, Copy)]
struct Operator {
    text: &'static str,
    preserves_precision: bool,
    minimum_components: usize,
}

pub(crate) fn render_version_update(
    dependency: &Dependency,
    latest: &str,
    file_type: FileType,
) -> Option<String> {
    if dependency.has_additional_version_constraints {
        return None;
    }

    let original = dependency.version.as_str();
    let trimmed_start = original.trim_start();
    let leading_len = original.len().checked_sub(trimmed_start.len())?;
    let core = trimmed_start.trim_end();
    let trailing_start = leading_len.checked_add(core.len())?;
    let leading = original.get(..leading_len)?;
    let trailing = original.get(trailing_start..)?;
    if core.is_empty() || !is_horizontal_whitespace(leading) || !is_horizontal_whitespace(trailing)
    {
        return None;
    }

    let rendered = match file_type {
        FileType::Cargo => render_with_operators(
            core,
            latest,
            file_type,
            &[
                operator(">=", false),
                operator("<=", false),
                operator("^", true),
                operator("~", true),
                operator("=", false),
            ],
            true,
        ),
        FileType::Npm => render_with_operators(
            core,
            latest,
            file_type,
            &[
                operator(">=", false),
                operator("<=", false),
                operator("^", true),
                operator("~", true),
                operator("=", false),
            ],
            true,
        ),
        FileType::Python => render_with_operators(
            core,
            latest,
            file_type,
            &[
                operator("===", false),
                Operator {
                    text: "~=",
                    preserves_precision: true,
                    minimum_components: 2,
                },
                operator("==", false),
                operator(">=", false),
                operator("<=", false),
                operator("^", true),
                operator("~", true),
            ],
            false,
        ),
        FileType::Php => render_with_operators(
            core,
            latest,
            file_type,
            &[
                operator("==", false),
                operator(">=", false),
                operator("<=", false),
                operator("^", true),
                operator("~", true),
                operator("=", false),
            ],
            false,
        ),
        FileType::Dart => render_with_operators(
            core,
            latest,
            file_type,
            &[
                operator(">=", false),
                operator("<=", false),
                operator("^", true),
            ],
            false,
        ),
        FileType::Csharp => render_nuget(core, latest),
        FileType::Ruby => render_with_operators(
            core,
            latest,
            file_type,
            &[
                operator("~>", true),
                operator("==", false),
                operator(">=", false),
                operator("<=", false),
                operator("=", false),
            ],
            false,
        ),
        FileType::Go => render_go(core, latest),
        FileType::Maven => render_bare(core, latest, file_type),
    }?;

    let updated = format!("{leading}{rendered}{trailing}");
    (updated != original).then_some(updated)
}

const fn operator(text: &'static str, preserves_precision: bool) -> Operator {
    Operator {
        text,
        preserves_precision,
        minimum_components: 1,
    }
}

fn is_horizontal_whitespace(value: &str) -> bool {
    value.bytes().all(|byte| matches!(byte, b' ' | b'\t'))
}

fn render_with_operators(
    original: &str,
    latest: &str,
    file_type: FileType,
    operators: &[Operator],
    preserve_bare_precision: bool,
) -> Option<String> {
    let latest = validate_latest(latest, file_type)?;

    for operator in operators {
        let Some(rest) = original.strip_prefix(operator.text) else {
            continue;
        };
        let operand = rest.trim_start_matches([' ', '\t']);
        let whitespace_len = rest.len().checked_sub(operand.len())?;
        let whitespace = rest.get(..whitespace_len)?;
        if !is_version_token(operand, file_type) {
            return None;
        }

        let component_count = release_parts(operand, file_type)?.components.len();
        if component_count < operator.minimum_components {
            return None;
        }
        let target = if operator.preserves_precision {
            preserve_precision(operand, latest, file_type)?
        } else {
            latest.to_string()
        };
        return Some(format!("{}{whitespace}{target}", operator.text));
    }

    if !is_version_token(original, file_type) {
        return None;
    }
    let target = if preserve_bare_precision {
        preserve_precision(original, latest, file_type)?
    } else {
        latest.to_string()
    };
    Some(target)
}

fn render_bare(original: &str, latest: &str, file_type: FileType) -> Option<String> {
    let latest = validate_latest(latest, file_type)?;
    is_version_token(original, file_type).then(|| latest.to_string())
}

fn render_nuget(original: &str, latest: &str) -> Option<String> {
    let latest = validate_latest(latest, FileType::Csharp)?;
    if let Some(inner) = original
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return is_version_token(inner, FileType::Csharp).then(|| format!("[{latest}]"));
    }
    is_version_token(original, FileType::Csharp).then(|| latest.to_string())
}

fn render_go(original: &str, latest: &str) -> Option<String> {
    let original = original.strip_prefix('v')?;
    if original.starts_with('v') || !is_version_token(original, FileType::Go) {
        return None;
    }
    let latest = latest.strip_prefix('v').unwrap_or(latest);
    if latest.starts_with('v') || !is_version_token(latest, FileType::Go) {
        return None;
    }
    semver::Version::parse(latest).ok()?;
    Some(format!("v{latest}"))
}

fn validate_latest(latest: &str, file_type: FileType) -> Option<&str> {
    if latest.trim() != latest || !is_version_token(latest, file_type) {
        return None;
    }
    if matches!(file_type, FileType::Cargo | FileType::Npm | FileType::Dart) {
        semver::Version::parse(latest).ok()?;
    }
    Some(latest)
}

fn is_version_token(token: &str, file_type: FileType) -> bool {
    if token.is_empty()
        || (!matches!(file_type, FileType::Go | FileType::Python) && token.starts_with('v'))
        || token.contains("..")
        || token.ends_with(['.', '-', '+', '_', '!'])
        || token.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b',' | b'|'
                        | b'*'
                        | b'^'
                        | b'~'
                        | b'<'
                        | b'>'
                        | b'='
                        | b'['
                        | b']'
                        | b'('
                        | b')'
                        | b'{'
                        | b'}'
                        | b':'
                        | b'/'
                        | b'\\'
                        | b'@'
                        | b'$'
                        | b';'
                        | b'\''
                        | b'"'
                )
        })
    {
        return false;
    }

    if !token.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_' | b'!')
    }) {
        return false;
    }

    let without_v = token.strip_prefix('v').unwrap_or(token);
    if without_v.starts_with('v') || !without_v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return false;
    }

    let mut bang_parts = without_v.split('!');
    let first = bang_parts.next().unwrap_or_default();
    if let Some(release) = bang_parts.next()
        && (file_type != FileType::Python
            || bang_parts.next().is_some()
            || first.is_empty()
            || !first.bytes().all(|byte| byte.is_ascii_digit())
            || !release.as_bytes().first().is_some_and(u8::is_ascii_digit))
    {
        return false;
    }

    !without_v.split('.').any(|segment| {
        if segment.eq_ignore_ascii_case("x") || segment.eq_ignore_ascii_case("any") {
            return true;
        }
        if !matches!(file_type, FileType::Npm | FileType::Php) {
            return false;
        }
        let marker = segment
            .split(['-', '+', '_', '!'])
            .next()
            .unwrap_or(segment);
        marker.eq_ignore_ascii_case("x") || marker.eq_ignore_ascii_case("any")
    })
}

struct ReleaseParts<'a> {
    prefix: &'a str,
    components: Vec<&'a str>,
    suffix: &'a str,
}

fn release_parts(token: &str, file_type: FileType) -> Option<ReleaseParts<'_>> {
    let mut release_start = usize::from(token.starts_with('v'));
    if file_type == FileType::Python
        && let Some(epoch_end) = token.get(release_start..)?.find('!')
    {
        release_start = release_start.checked_add(epoch_end)?.checked_add(1)?;
    }

    let release = token.get(release_start..)?;
    let bytes = release.as_bytes();
    let mut cursor = 0;
    let mut components = Vec::with_capacity(3);
    loop {
        let component_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == component_start {
            return None;
        }
        components.push(release.get(component_start..cursor)?);

        if bytes.get(cursor) == Some(&b'.') && bytes.get(cursor + 1).is_some_and(u8::is_ascii_digit)
        {
            cursor += 1;
            continue;
        }
        break;
    }

    Some(ReleaseParts {
        prefix: token.get(..release_start)?,
        components,
        suffix: release.get(cursor..)?,
    })
}

fn preserve_precision(original: &str, latest: &str, file_type: FileType) -> Option<String> {
    let original_parts = release_parts(original, file_type)?;
    let latest_parts = release_parts(latest, file_type)?;
    match latest_parts
        .components
        .len()
        .cmp(&original_parts.components.len())
    {
        core::cmp::Ordering::Less => None,
        core::cmp::Ordering::Equal => Some(latest.to_string()),
        core::cmp::Ordering::Greater if latest_parts.suffix.is_empty() => Some(format!(
            "{}{}",
            latest_parts.prefix,
            latest_parts.components[..original_parts.components.len()].join(".")
        )),
        core::cmp::Ordering::Greater => None,
    }
}

#[cfg(test)]
mod tests {
    use super::render_version_update;
    use crate::file_types::FileType;
    use crate::parsers::{Dependency, Span};

    fn dependency(version: &str) -> Dependency {
        Dependency {
            name: "package".to_string(),
            version: version.to_string(),
            name_span: Span {
                line: 0,
                line_start: 0,
                line_end: 7,
            },
            version_span: Span {
                line: 0,
                line_start: 10,
                line_end: 10 + version.len() as u32,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        }
    }

    #[test]
    fn renders_recognized_constraints_for_every_ecosystem() {
        let cases = [
            (FileType::Cargo, "1.2", "2.3.4", "2.3"),
            (FileType::Cargo, "^4.0.2", "5.1.0", "^5.1.0"),
            (FileType::Cargo, "~ 1.2", "2.3.4", "~ 2.3"),
            (FileType::Cargo, "=1.2", "2.3.4", "=2.3.4"),
            (FileType::Cargo, ">= 1.2", "2.3.4", ">= 2.3.4"),
            (FileType::Cargo, "<=1.2", "2.3.4", "<=2.3.4"),
            (FileType::Npm, "1", "2.3.4", "2"),
            (FileType::Npm, "^1.2", "2.3.4", "^2.3"),
            (FileType::Npm, "~1.2.3", "2.3.4", "~2.3.4"),
            (FileType::Npm, "= 1.2.3", "2.3.4", "= 2.3.4"),
            (FileType::Npm, ">=1.2", "2.3.4", ">=2.3.4"),
            (FileType::Npm, "<= 1.2", "2.3.4", "<= 2.3.4"),
            (FileType::Python, "=== 1.2", "2.3.4", "=== 2.3.4"),
            (FileType::Python, "~=14.2", "14.3.3", "~=14.3"),
            (FileType::Python, "== 1.2", "2.3.4", "== 2.3.4"),
            (FileType::Python, ">=1.2", "2.3.4", ">=2.3.4"),
            (FileType::Python, "<= 1.2", "2.3.4", "<= 2.3.4"),
            (FileType::Python, "^1.2", "2.3.4", "^2.3"),
            (FileType::Python, "~ 1.2", "2.3.4", "~ 2.3"),
            (FileType::Python, "1.2", "2.3.4", "2.3.4"),
            (FileType::Php, "1.2", "2.3.4", "2.3.4"),
            (FileType::Php, "^1.2", "2.3.4", "^2.3"),
            (FileType::Php, "~ 1.2", "2.3.4", "~ 2.3"),
            (FileType::Php, "=1.2", "2.3.4", "=2.3.4"),
            (FileType::Php, "== 1.2", "2.3.4", "== 2.3.4"),
            (FileType::Php, ">=1.2", "2.3.4", ">=2.3.4"),
            (FileType::Php, "<= 1.2", "2.3.4", "<= 2.3.4"),
            (FileType::Dart, "1.2", "2.3.4", "2.3.4"),
            (FileType::Dart, "^1.2", "2.3.4", "^2.3"),
            (FileType::Dart, ">= 1.2", "2.3.4", ">= 2.3.4"),
            (FileType::Dart, "<=1.2", "2.3.4", "<=2.3.4"),
            (FileType::Csharp, "1.2", "2.3.4", "2.3.4"),
            (FileType::Csharp, "[1.2]", "2.3.4", "[2.3.4]"),
            (FileType::Ruby, "1.2", "2.3.4", "2.3.4"),
            (FileType::Ruby, "~> 7.0", "8.1.4", "~> 8.1"),
            (FileType::Ruby, "=1.2", "2.3.4", "=2.3.4"),
            (FileType::Ruby, "== 1.2", "2.3.4", "== 2.3.4"),
            (FileType::Ruby, ">=1.2", "2.3.4", ">=2.3.4"),
            (FileType::Ruby, "<= 1.2", "2.3.4", "<= 2.3.4"),
            (FileType::Go, "v1.2.3", "1.3.0", "v1.3.0"),
            (FileType::Go, "v1.2.3", "v1.4.0", "v1.4.0"),
            (FileType::Maven, "1.0.0.Final", "2.0.0-RC1", "2.0.0-RC1"),
            (FileType::Maven, "1.x-dev", "2.0.0", "2.0.0"),
        ];

        for (file_type, original, latest, expected) in cases {
            assert_eq!(
                render_version_update(&dependency(original), latest, file_type),
                Some(expected.to_string()),
                "failed for {file_type:?} {original:?}"
            );
        }
    }

    #[test]
    fn preserves_outer_and_operator_whitespace() {
        assert_eq!(
            render_version_update(&dependency("  ^\t4.0.2  "), "5.1.0", FileType::Npm),
            Some("  ^\t5.1.0  ".to_string())
        );
    }

    #[test]
    fn preserves_full_target_qualifiers_when_precision_is_unchanged() {
        let cases = [
            (
                FileType::Npm,
                "^1.2.3-beta.1+old",
                "2.0.0-rc.1+build.5",
                "^2.0.0-rc.1+build.5",
            ),
            (
                FileType::Python,
                "==1!2.0.0rc1",
                "2!3.0.0.post1",
                "==2!3.0.0.post1",
            ),
            (FileType::Ruby, "~> 1.2.3.pre", "2.0.0.pre", "~> 2.0.0.pre"),
            (
                FileType::Go,
                "v0.0.0-20240101000000-abcdef123456",
                "0.0.0-20250101000000-fedcba654321",
                "v0.0.0-20250101000000-fedcba654321",
            ),
        ];

        for (file_type, original, latest, expected) in cases {
            assert_eq!(
                render_version_update(&dependency(original), latest, file_type),
                Some(expected.to_string()),
                "failed for {file_type:?} {original:?}"
            );
        }
    }

    #[test]
    fn rejects_ineligible_constraint_shapes() {
        let cases = [
            (FileType::Python, ">=5.2,<5.3"),
            (FileType::Npm, ">=1 <2"),
            (FileType::Csharp, "[1,2)"),
            (FileType::Npm, "1 || 2"),
            (FileType::Npm, "1.0 - 2.0"),
            (FileType::Cargo, "*"),
            (FileType::Npm, "1.x"),
            (FileType::Php, "1.0.x-dev"),
            (FileType::Npm, "X"),
            (FileType::Dart, "any"),
            (FileType::Cargo, "<2"),
            (FileType::Ruby, "> 1"),
            (FileType::Python, "!=1"),
            (FileType::Npm, "npm:foo@^1"),
            (FileType::Npm, "workspace:^"),
            (FileType::Npm, "file:../foo"),
            (FileType::Npm, "link:../foo"),
            (FileType::Npm, "catalog:"),
            (FileType::Maven, "${revision}"),
            (FileType::Npm, "https://example.com/pkg.tgz"),
            (FileType::Cargo, "git+https://example.com/pkg"),
            (FileType::Npm, "latest"),
            (FileType::Npm, "next"),
            (FileType::Maven, "RELEASE"),
            (FileType::Go, "1.2.3"),
            (FileType::Go, "vv1.2.3"),
            (FileType::Csharp, "(1.0,2.0]"),
            (FileType::Python, "~=1"),
        ];

        for (file_type, original) in cases {
            assert_eq!(
                render_version_update(&dependency(original), "9.8.7", file_type),
                None,
                "unexpectedly rendered {file_type:?} {original:?}"
            );
        }
    }

    #[test]
    fn renders_python_v_prefixed_constraint() {
        assert_eq!(
            render_version_update(&dependency("==v1.2"), "2.3.4", FileType::Python),
            Some("==2.3.4".to_string())
        );
    }

    #[test]
    fn rejects_v_prefixed_versions_outside_go_and_python() {
        let cases = [
            (FileType::Cargo, "^v1.2"),
            (FileType::Npm, "^v1.2"),
            (FileType::Php, "^v1.2"),
            (FileType::Dart, "^v1.2"),
            (FileType::Csharp, "[v1.2]"),
            (FileType::Ruby, "~> v1.2"),
            (FileType::Maven, "v1.2"),
        ];

        for (file_type, original) in cases {
            assert_eq!(
                render_version_update(&dependency(original), "2.3.4", file_type),
                None,
                "unexpectedly rendered {file_type:?} {original:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_latest_versions() {
        let cases = [
            "",
            " ",
            "latest",
            "^2.0.0",
            "2.0.0 || 3.0.0",
            "2.0.0,3.0.0",
            "https://example.com/release",
            "2.0.0/other",
            "2..0",
            "2.0.",
            "2.0.0+build+again",
            "v2.0.0",
        ];

        for latest in cases {
            assert_eq!(
                render_version_update(&dependency("^1.0.0"), latest, FileType::Npm),
                None,
                "unexpectedly accepted latest {latest:?}"
            );
        }
    }

    #[test]
    fn rejects_truncation_that_would_drop_a_target_qualifier() {
        assert_eq!(
            render_version_update(&dependency("^1.2"), "2.3.4-beta.1", FileType::Npm),
            None
        );
    }

    #[test]
    fn rejects_updates_that_render_the_original_constraint_unchanged() {
        assert_eq!(
            render_version_update(&dependency("1.2"), "1.2.4", FileType::Cargo),
            None
        );
    }

    #[test]
    fn rejects_declarations_with_hidden_additional_constraints() {
        let mut dep = dependency(">= 1");
        dep.has_additional_version_constraints = true;

        assert_eq!(render_version_update(&dep, "2.0.0", FileType::Ruby), None);
    }
}
