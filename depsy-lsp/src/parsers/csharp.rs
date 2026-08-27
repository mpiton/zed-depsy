//! Parser for concrete NuGet items in .NET/MSBuild manifests.
//!
//! Supported items use `PackageReference`, `PackageVersion`, or
//! `GlobalPackageReference` with literal package names and versions.
//!
//! ```xml
//! <PackageReference Include="Serilog" Version="3.1.1" />
//! <PackageVersion Include="Serilog" Version="3.1.1" />
//! <PackageVersion Include="Serilog"><Version>3.1.1</Version></PackageVersion>
//! ```

use super::{Dependency, Parser, Span};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesDecl, BytesRef, BytesStart, BytesText, Event};
use quick_xml::{Reader, XmlVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NugetItemKind {
    PackageReference,
    PackageVersion,
    GlobalPackageReference,
}

impl NugetItemKind {
    fn from_local_name(name: &[u8]) -> Option<Self> {
        match name {
            b"PackageReference" => Some(Self::PackageReference),
            b"PackageVersion" => Some(Self::PackageVersion),
            b"GlobalPackageReference" => Some(Self::GlobalPackageReference),
            _ => None,
        }
    }

    fn is_development(self) -> bool {
        self == Self::GlobalPackageReference
    }
}

#[derive(Debug)]
struct LocatedValue {
    value: String,
    absolute_start: usize,
    absolute_end: usize,
}

#[derive(Debug)]
struct PendingItem {
    kind: NugetItemKind,
    name: Option<LocatedValue>,
    version: Option<LocatedValue>,
}

impl PendingItem {
    fn from_event(
        kind: NugetItemKind,
        event: &BytesStart<'_>,
        event_start: usize,
    ) -> Result<Self, ()> {
        let mut include = None;
        let mut update = None;
        let mut version = None;

        for attribute in event.attributes() {
            let attribute = attribute.map_err(|_| ())?;
            let key = attribute.key.as_ref();
            if !matches!(key, b"Include" | b"Update" | b"Version") {
                continue;
            }

            let raw_value = attribute.value.as_ref();
            let (relative_start, relative_end) =
                attribute_value_range(event, raw_value).ok_or(())?;
            let value = LocatedValue {
                value: attribute
                    .decoded_and_normalized_value(XmlVersion::Implicit1_0, event.decoder())
                    .map_err(|_| ())?
                    .into_owned(),
                absolute_start: event_start.checked_add(relative_start).ok_or(())?,
                absolute_end: event_start.checked_add(relative_end).ok_or(())?,
            };
            match key {
                b"Include" => include = Some(value),
                b"Update" => update = Some(value),
                b"Version" => version = Some(value),
                _ => {}
            }
        }

        let name = match kind {
            NugetItemKind::PackageVersion => include.or(update),
            NugetItemKind::PackageReference | NugetItemKind::GlobalPackageReference => {
                if update.is_some() { None } else { include }
            }
        };

        Ok(Self {
            kind,
            name,
            version,
        })
    }
}

#[derive(Debug)]
struct ActiveItem {
    item: PendingItem,
    item_depth: usize,
    version_depth: Option<usize>,
    invalid_child_version: bool,
}

impl ActiveItem {
    fn new(item: PendingItem, item_depth: usize) -> Self {
        Self {
            item,
            item_depth,
            version_depth: None,
            invalid_child_version: false,
        }
    }

    fn begin_child_version(&mut self, local_name: &[u8], event_depth: usize) {
        if local_name == b"Version"
            && self.item.version.is_none()
            && self.item_depth.checked_add(1) == Some(event_depth)
        {
            self.version_depth = Some(event_depth);
        }
    }

    fn mark_fragmented_version(&mut self) {
        if self.version_depth.is_some() {
            self.invalid_child_version = true;
        }
    }

    fn record_version_text(&mut self, value: Option<LocatedValue>) {
        if value.is_some() && self.item.version.is_some() {
            self.invalid_child_version = true;
        } else if value.is_some() {
            self.item.version = value;
        }
    }

    fn is_version_text_depth(&self, depth: usize) -> bool {
        self.version_depth.and_then(|depth| depth.checked_add(1)) == Some(depth)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentPhase {
    Start,
    Prolog,
    Root,
}

struct ParseState<'a> {
    content: &'a str,
    newline_starts: Vec<usize>,
    dependencies: Vec<Dependency>,
    active: Option<ActiveItem>,
    depth: usize,
    document_phase: DocumentPhase,
}

impl<'a> ParseState<'a> {
    fn new(content: &'a str) -> Self {
        Self {
            content,
            newline_starts: newline_starts(content),
            dependencies: Vec::new(),
            active: None,
            depth: 0,
            document_phase: DocumentPhase::Start,
        }
    }

    fn register_root_element(&mut self) -> Result<(), ()> {
        if self.depth != 0 {
            return Ok(());
        }
        if self.document_phase == DocumentPhase::Root {
            return Err(());
        }
        self.document_phase = DocumentPhase::Root;
        Ok(())
    }

    fn handle_empty(&mut self, event: &BytesStart<'_>, event_end: u64) -> Result<(), ()> {
        let kind = self
            .active
            .is_none()
            .then(|| NugetItemKind::from_local_name(event.local_name().as_ref()))
            .flatten();
        let item = if let Some(kind) = kind {
            let event_start = event_content_start(event_end, event, true).ok_or(())?;
            Some(PendingItem::from_event(kind, event, event_start)?)
        } else {
            validate_attributes(event)?;
            None
        };
        self.register_root_element()?;

        if let Some(active) = self.active.as_mut() {
            active.mark_fragmented_version();
            return Ok(());
        }
        if let Some(item) = item {
            self.push_dependency(item);
        }
        Ok(())
    }

    fn handle_start(&mut self, event: &BytesStart<'_>, event_end: u64) -> Result<(), ()> {
        let kind = self
            .active
            .is_none()
            .then(|| NugetItemKind::from_local_name(event.local_name().as_ref()))
            .flatten();
        let item = if let Some(kind) = kind {
            let event_start = event_content_start(event_end, event, false).ok_or(())?;
            Some(PendingItem::from_event(kind, event, event_start)?)
        } else {
            validate_attributes(event)?;
            None
        };
        self.register_root_element()?;

        let event_depth = self.depth;
        if let Some(active) = self.active.as_mut() {
            active.mark_fragmented_version();
            active.begin_child_version(event.local_name().as_ref(), event_depth);
        } else if let Some(item) = item {
            self.active = Some(ActiveItem::new(item, event_depth));
        }

        self.depth = self.depth.checked_add(1).ok_or(())?;
        Ok(())
    }

    fn handle_text(&mut self, text: &BytesText<'_>, event_end: u64) -> Result<(), ()> {
        if self.depth == 0 && self.document_phase == DocumentPhase::Start {
            self.document_phase = DocumentPhase::Prolog;
        }
        if self.depth == 0 && !is_xml_whitespace(text.as_ref()) {
            return Err(());
        }
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        if !active.is_version_text_depth(self.depth) {
            return Ok(());
        }
        let value = located_text(text, event_end, self.content)?;
        active.record_version_text(value);
        Ok(())
    }

    fn handle_fragmented_content(&mut self, invalid_outside_root: bool) -> Result<(), ()> {
        if invalid_outside_root && self.depth == 0 {
            return Err(());
        }
        if self.depth == 0 && self.document_phase == DocumentPhase::Start {
            self.document_phase = DocumentPhase::Prolog;
        }
        if let Some(active) = self.active.as_mut() {
            active.mark_fragmented_version();
        }
        Ok(())
    }

    fn handle_general_reference(&mut self, reference: &BytesRef<'_>) -> Result<(), ()> {
        if !is_supported_xml_reference(reference) {
            return Err(());
        }
        self.handle_fragmented_content(true)
    }

    fn handle_declaration(&mut self, declaration: &BytesDecl<'_>) -> Result<(), ()> {
        if self.depth != 0 || self.document_phase != DocumentPhase::Start {
            return Err(());
        }
        validate_xml_declaration(declaration)?;
        self.document_phase = DocumentPhase::Prolog;
        Ok(())
    }

    fn handle_end(&mut self, local_name: &[u8]) -> Result<(), ()> {
        let event_depth = self.depth.checked_sub(1).ok_or(())?;
        self.depth = event_depth;

        if self.active.as_ref().and_then(|active| active.version_depth) == Some(event_depth) {
            if local_name != b"Version" {
                return Err(());
            }
            self.active.as_mut().ok_or(())?.version_depth = None;
        }

        if self
            .active
            .as_ref()
            .is_some_and(|active| active.item_depth == event_depth)
        {
            let active = self.active.take().ok_or(())?;
            if NugetItemKind::from_local_name(local_name) != Some(active.item.kind) {
                return Err(());
            }
            if !active.invalid_child_version {
                self.push_dependency(active.item);
            }
        }
        Ok(())
    }

    fn push_dependency(&mut self, item: PendingItem) {
        if let Some(dependency) = build_dependency(item, self.content, &self.newline_starts) {
            self.dependencies.push(dependency);
        }
    }

    fn finish(self) -> Result<Vec<Dependency>, ()> {
        if self.document_phase == DocumentPhase::Root && self.depth == 0 && self.active.is_none() {
            Ok(self.dependencies)
        } else {
            Err(())
        }
    }
}

/// Parser for NuGet items in .NET/MSBuild manifests.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::csharp::CsharpParser;
/// let parser = CsharpParser::new();
/// let content = r#"<Project><ItemGroup><PackageReference Include="Serilog" Version="3.1.1" /></ItemGroup></Project>"#;
/// let deps = parser.parse(content);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "Serilog");
/// assert_eq!(deps[0].version, "3.1.1");
/// ```
#[derive(Debug, Default)]
pub struct CsharpParser;

impl CsharpParser {
    /// Creates a new [`CsharpParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for CsharpParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        parse_xml(content).unwrap_or_default()
    }
}

fn parse_xml(content: &str) -> Result<Vec<Dependency>, ()> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().check_comments = true;
    let mut state = ParseState::new(content);

    loop {
        match reader.read_event().map_err(|_| ())? {
            Event::Empty(event) => state.handle_empty(&event, reader.buffer_position())?,
            Event::Start(event) => state.handle_start(&event, reader.buffer_position())?,
            Event::Text(text) => state.handle_text(&text, reader.buffer_position())?,
            Event::Comment(_) | Event::PI(_) => state.handle_fragmented_content(false)?,
            Event::CData(_) => state.handle_fragmented_content(true)?,
            Event::GeneralRef(reference) => {
                state.handle_general_reference(&reference)?;
            }
            Event::Decl(declaration) => state.handle_declaration(&declaration)?,
            Event::DocType(_) => return Err(()),
            Event::End(event) => state.handle_end(event.local_name().as_ref())?,
            Event::Eof => return state.finish(),
        }
    }
}

fn is_xml_whitespace(value: &[u8]) -> bool {
    value.iter().all(u8::is_ascii_whitespace)
}

fn validate_xml_declaration(declaration: &BytesDecl<'_>) -> Result<(), ()> {
    let raw = std::str::from_utf8(declaration.as_ref()).map_err(|_| ())?;
    if !raw.as_bytes().get(3).is_some_and(u8::is_ascii_whitespace) {
        return Err(());
    }

    let event = BytesStart::from_content(raw, 3);
    let mut attribute_position = 0usize;
    for attribute in event.attributes() {
        let attribute = attribute.map_err(|_| ())?;
        let key = attribute.key.as_ref();
        let value = attribute.value.as_ref();
        attribute_position = match (attribute_position, key) {
            (0, b"version") if matches!(value, b"1.0" | b"1.1") => 1,
            (1, b"encoding") if is_valid_xml_encoding(value) => 2,
            (1 | 2, b"standalone") if matches!(value, b"yes" | b"no") => 3,
            _ => return Err(()),
        };
    }

    if attribute_position == 0 {
        Err(())
    } else {
        Ok(())
    }
}

fn is_valid_xml_encoding(value: &[u8]) -> bool {
    value.first().is_some_and(u8::is_ascii_alphabetic)
        && value
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_supported_xml_reference(reference: &BytesRef<'_>) -> bool {
    match reference.resolve_char_ref() {
        Ok(Some(character)) => matches!(
            u32::from(character),
            0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
        ),
        Ok(None) => reference
            .decode()
            .is_ok_and(|entity| resolve_xml_entity(&entity).is_some()),
        Err(_) => false,
    }
}

fn contains_msbuild_expression(value: &str) -> bool {
    ["$(", "@(", "%("]
        .iter()
        .any(|expression| value.contains(expression))
}

fn build_dependency(
    pending: PendingItem,
    content: &str,
    newline_starts: &[usize],
) -> Option<Dependency> {
    let name = pending.name?;
    let version = pending.version?;
    if name.value.trim().is_empty()
        || contains_msbuild_expression(&name.value)
        || version.value.trim().is_empty()
        || contains_msbuild_expression(&version.value)
    {
        return None;
    }
    let name_span = span_from_absolute(
        content,
        newline_starts,
        name.absolute_start,
        name.absolute_end,
    )?;
    let version_span = span_from_absolute(
        content,
        newline_starts,
        version.absolute_start,
        version.absolute_end,
    )?;
    Some(Dependency {
        name: name.value,
        version: version.value,
        name_span,
        version_span,
        dev: pending.kind.is_development(),
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
    })
}

fn newline_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(
        content
            .bytes()
            .enumerate()
            .filter_map(|(offset, byte)| (byte == b'\n').then_some(offset + 1)),
    );
    starts
}

fn span_from_absolute(
    content: &str,
    newline_starts: &[usize],
    absolute_start: usize,
    absolute_end: usize,
) -> Option<Span> {
    let value = content.get(absolute_start..absolute_end)?;
    if value.is_empty() || value.bytes().any(|byte| matches!(byte, b'\n' | b'\r')) {
        return None;
    }

    let line_index = newline_starts
        .partition_point(|line_start| *line_start <= absolute_start)
        .checked_sub(1)?;
    let line_absolute_start = *newline_starts.get(line_index)?;

    Some(Span {
        line: u32::try_from(line_index).ok()?,
        line_start: u32::try_from(absolute_start.checked_sub(line_absolute_start)?).ok()?,
        line_end: u32::try_from(absolute_end.checked_sub(line_absolute_start)?).ok()?,
    })
}

fn event_content_start(event_end: u64, event: &BytesStart<'_>, is_empty: bool) -> Option<usize> {
    let event_end = usize::try_from(event_end).ok()?;
    let event_raw: &[u8] = event.as_ref();
    let closing_delimiter_len = if is_empty { 2 } else { 1 };
    event_end
        .checked_sub(event_raw.len())?
        .checked_sub(closing_delimiter_len)
}

fn validate_attributes(event: &BytesStart<'_>) -> Result<(), ()> {
    for attribute in event.attributes() {
        attribute.map_err(|_| ())?;
    }
    Ok(())
}

fn located_text(
    text: &BytesText<'_>,
    event_end: u64,
    content: &str,
) -> Result<Option<LocatedValue>, ()> {
    let event_end = usize::try_from(event_end).map_err(|_| ())?;
    let raw_text: &[u8] = text.as_ref();
    let raw_start = event_end.checked_sub(raw_text.len()).ok_or(())?;
    let raw = content.get(raw_start..event_end).ok_or(())?;
    let raw_without_leading = raw.trim_start();
    let leading_len = raw.len().checked_sub(raw_without_leading.len()).ok_or(())?;
    let trimmed_raw = raw_without_leading.trim_end();
    if trimmed_raw.is_empty() {
        return Ok(None);
    }

    let absolute_start = raw_start.checked_add(leading_len).ok_or(())?;
    let absolute_end = absolute_start.checked_add(trimmed_raw.len()).ok_or(())?;
    let value = text.decode().map_err(|_| ())?.trim().to_string();

    Ok(Some(LocatedValue {
        value,
        absolute_start,
        absolute_end,
    }))
}

fn attribute_value_range(event: &BytesStart<'_>, value: &[u8]) -> Option<(usize, usize)> {
    let raw: &[u8] = event.as_ref();
    let start = (value.as_ptr() as usize).checked_sub(raw.as_ptr() as usize)?;
    let end = start.checked_add(value.len())?;
    raw.get(start..end)?;
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_text(content: &str, span: Span) -> &str {
        let line = content.lines().nth(span.line as usize).unwrap();
        &line[span.line_start as usize..span.line_end as usize]
    }

    fn assert_dependency(
        content: &str,
        dependency: &Dependency,
        name: &str,
        version: &str,
        dev: bool,
    ) {
        assert_eq!(dependency.name, name);
        assert_eq!(dependency.version, version);
        assert_eq!(span_text(content, dependency.name_span), name);
        assert_eq!(span_text(content, dependency.version_span), version);
        assert_eq!(dependency.dev, dev);
        assert!(!dependency.optional);
        assert_eq!(dependency.registry, None);
        assert_eq!(dependency.resolved_version, None);
        assert!(!dependency.has_additional_version_constraints);
    }

    #[test]
    fn test_parse_attribute_forms() {
        let cases = [
            (
                r#"<Project><PackageReference Include="Package" Version="1.2.3" /></Project>"#,
                false,
            ),
            (
                r#"<Project><PackageVersion Include="Package" Version="1.2.3" /></Project>"#,
                false,
            ),
            (
                r#"<Project><PackageVersion Update="Package" Version="1.2.3" /></Project>"#,
                false,
            ),
            (
                r#"<Project><PackageVersion Include="Package" Update="Other" Version="1.2.3" /></Project>"#,
                false,
            ),
            (
                r#"<Project><GlobalPackageReference Include="Package" Version="1.2.3" /></Project>"#,
                true,
            ),
            (
                r#"<Project><PackageVersion Include = 'Package' Version = '1.2.3' /></Project>"#,
                false,
            ),
            (
                r#"<Project><PackageVersion Version="1.2.3" Include="Package" /></Project>"#,
                false,
            ),
        ];

        let parser = CsharpParser::new();
        for (content, dev) in cases {
            let dependencies = parser.parse(content);
            assert_eq!(dependencies.len(), 1, "failed to parse {content}");
            assert_dependency(content, &dependencies[0], "Package", "1.2.3", dev);
        }
    }

    #[test]
    fn test_parse_multiline_start_tag() {
        let content = r#"<Project>
  <PackageVersion
    Include="Package"
    Version="1.2.3" />
</Project>"#;

        let dependencies = CsharpParser::new().parse(content);

        assert_eq!(dependencies.len(), 1);
        assert_dependency(content, &dependencies[0], "Package", "1.2.3", false);
    }

    #[test]
    fn test_ignore_package_declaration_in_comment() {
        let content =
            r#"<Project><!-- <PackageReference Include="Package" Version="1.2.3" /> --></Project>"#;

        assert!(CsharpParser::new().parse(content).is_empty());
    }

    #[test]
    fn test_skip_empty_or_multiline_attribute_values() {
        for content in [
            r#"<Project><PackageReference Include="" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageReference Include="Package" Version="" /></Project>"#,
            "<Project><PackageReference Include=\"Package\" Version=\"1.2\n.3\" /></Project>",
        ] {
            assert!(
                CsharpParser::new().parse(content).is_empty(),
                "unexpected dependency from {content}"
            );
        }
    }

    #[test]
    fn test_attribute_value_positions() {
        let content = r#"<PackageVersion Include="Package" Version="1.2.3" />"#;

        let dependencies = CsharpParser::new().parse(content);

        assert_eq!(dependencies.len(), 1);
        let dependency = &dependencies[0];
        assert_eq!(dependency.name_span.line, 0);
        assert_eq!(dependency.name_span.line_start, 25);
        assert_eq!(dependency.name_span.line_end, 32);
        assert_eq!(dependency.version_span.line, 0);
        assert_eq!(dependency.version_span.line_start, 43);
        assert_eq!(dependency.version_span.line_end, 48);
        assert_dependency(content, dependency, "Package", "1.2.3", false);
    }

    #[test]
    fn test_parse_self_closing() {
        let content = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
"#;
        let parser = CsharpParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);

        let newtonsoft = deps.iter().find(|d| d.name == "Newtonsoft.Json").unwrap();
        assert_eq!(newtonsoft.version, "13.0.3");

        let serilog = deps.iter().find(|d| d.name == "Serilog").unwrap();
        assert_eq!(serilog.version, "3.1.1");
    }

    #[test]
    fn test_parse_expanded_format() {
        let content = r#"<Project>
  <PackageReference Include="Package">
    <Version>1.2.3</Version>
  </PackageReference>
  <PackageVersion Update="Central.Package">
    <Version>
      2.3.4
    </Version>
  </PackageVersion>
  <GlobalPackageReference Include="Global.Package">
    <Version>3.4.5</Version>
  </GlobalPackageReference>
  <PackageVersion Include="Attribute.Package" Version="4.5.6"></PackageVersion>
</Project>"#;

        let dependencies = CsharpParser::new().parse(content);

        assert_eq!(dependencies.len(), 4);
        assert_dependency(content, &dependencies[0], "Package", "1.2.3", false);
        assert_dependency(content, &dependencies[1], "Central.Package", "2.3.4", false);
        assert_dependency(content, &dependencies[2], "Global.Package", "3.4.5", true);
        assert_dependency(
            content,
            &dependencies[3],
            "Attribute.Package",
            "4.5.6",
            false,
        );
        assert_eq!(dependencies[1].version_span.line, 6);
        assert_eq!(dependencies[1].version_span.line_start, 6);
        assert_eq!(dependencies[1].version_span.line_end, 11);
    }

    #[test]
    fn test_skip_unsafe_declarations() {
        for content in [
            r#"<Project><PackageReference Include="Package" /></Project>"#,
            r#"<Project><PackageVersion Include="Package" /></Project>"#,
            r#"<Project><PackageReference Version="1.2.3" /></Project>"#,
            r#"<Project><PackageVersion Version="1.2.3" /></Project>"#,
            r#"<Project><PackageVersion Include="" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageVersion Update="" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageVersion Include="Package" Version="" /></Project>"#,
            r#"<Project><PackageVersion Include="Package" Version="   " /></Project>"#,
            r#"<Project><PackageReference Update="Package" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageReference Include="Package" Update="Other" Version="1.2.3" /></Project>"#,
            r#"<Project><GlobalPackageReference Include="Package" Update="Other" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageReference Include="Package" Version="$(PackageVersion)" /></Project>"#,
            r#"<Project><PackageReference Include="Package" Version="@(PackageVersions)" /></Project>"#,
            r#"<Project><PackageReference Include="Package" Version="%(Version)" /></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>$(PackageVersion)</Version></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Metadata><Version>1.2.3</Version></Metadata></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>  </Version></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>1<!-- split -->.2.3</Version></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>1&#46;2.3</Version></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>1<Metadata/>.2.3</Version></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>1<![CDATA[.2]]>.3</Version></PackageReference></Project>"#,
            r#"<Project><PackageReference Include="Package"><Version>1<?split data?>.2.3</Version></PackageReference></Project>"#,
        ] {
            assert!(
                CsharpParser::new().parse(content).is_empty(),
                "unexpected dependency from {content}"
            );
        }
    }

    #[test]
    fn test_skip_indirect_package_names() {
        for content in [
            r#"<Project><PackageReference Include="$(PackageName)" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageReference Include="@(PackageNames)" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageReference Include="%(Identity)" Version="1.2.3" /></Project>"#,
            r#"<Project><PackageVersion Update="$(PackageName)" Version="1.2.3" /></Project>"#,
        ] {
            assert!(
                CsharpParser::new().parse(content).is_empty(),
                "unexpected dependency from {content}"
            );
        }
    }

    #[test]
    fn test_malformed_xml_returns_no_partial_dependencies() {
        let unclosed = r#"<Project>
  <PackageVersion Include="First" Version="1.0.0" />
  <PackageVersion Include="Second" Version="2.0.0">"#;
        let malformed_attribute = r#"<Project broken=unquoted>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let malformed_package_attribute = r#"<Project>
  <PackageVersion Include="First" Version="1.0.0" broken=unquoted />
</Project>"#;
        let duplicate_package_attribute = r#"<Project>
  <PackageVersion Include="First" Include="Second" Version="1.0.0" />
</Project>"#;
        let multiple_roots = r#"<Project>
  <PackageVersion Include="First" Version="1.0.0" />
</Project><Extra />"#;
        let invalid_comment = r#"<Project>
  <!-- invalid -- comment -->
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let declaration_in_version = r#"<Project>
  <PackageVersion Include="First"><Version>1.0<?xml version="1.0"?>.0</Version></PackageVersion>
</Project>"#;
        let doctype_in_version = r#"<Project>
  <PackageVersion Include="First"><Version>1.0<!DOCTYPE Project>.0</Version></PackageVersion>
</Project>"#;
        let duplicate_doctype = r#"<!DOCTYPE Project><!DOCTYPE Project><Project>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let declaration_after_whitespace = r#"
<?xml version="1.0"?><Project>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let undefined_entity = r#"<Project>&undefined;
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let uppercase_hex_reference = r#"<Project><Description>&#X41;</Description>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let signed_character_reference = r#"<Project><Description>&#+65;</Description>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let illegal_xml_character = r#"<Project><Description>&#1;</Description>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let incomplete_declaration = r#"<?xml?><Project>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let invalid_declaration_value = r#"<?xml version="1.0" standalone="maybe"?><Project>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;
        let unsupported_doctype = r#"<!DOCTYPE Project><Project>
  <PackageVersion Include="First" Version="1.0.0" />
</Project>"#;

        for content in [
            unclosed,
            malformed_attribute,
            malformed_package_attribute,
            duplicate_package_attribute,
            multiple_roots,
            invalid_comment,
            declaration_in_version,
            doctype_in_version,
            duplicate_doctype,
            declaration_after_whitespace,
            undefined_entity,
            uppercase_hex_reference,
            signed_character_reference,
            illegal_xml_character,
            incomplete_declaration,
            invalid_declaration_value,
            unsupported_doctype,
        ] {
            assert!(
                CsharpParser::new().parse(content).is_empty(),
                "unexpected dependency from malformed XML: {content}"
            );
        }
    }

    #[test]
    fn test_accept_valid_xml_prolog() {
        let content = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Project>
  <Description>&amp;&#46;&#x2E;</Description>
  <PackageVersion Include="Package" Version="1.2.3" />
</Project>"#;

        let dependencies = CsharpParser::new().parse(content);

        assert_eq!(dependencies.len(), 1);
        assert_dependency(content, &dependencies[0], "Package", "1.2.3", false);
    }

    #[test]
    fn test_preserve_conditional_declarations_in_source_order() {
        let content = r#"<Project>
  <ItemGroup Condition="'$(TargetFramework)' == 'net8.0'">
    <PackageVersion Include="Package" Version="1.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net9.0'">
    <PackageVersion Include="Package" Version="2.0.0" />
  </ItemGroup>
</Project>"#;

        let dependencies = CsharpParser::new().parse(content);

        assert_eq!(dependencies.len(), 2);
        assert_dependency(content, &dependencies[0], "Package", "1.0.0", false);
        assert_dependency(content, &dependencies[1], "Package", "2.0.0", false);
    }

    #[test]
    fn test_version_positions() {
        let content = r#"
<Project>
  <ItemGroup>
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
"#;
        let parser = CsharpParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert!(dep.version_span.line_start > dep.name_span.line_end);
    }

    #[test]
    fn test_skip_no_version() {
        let content = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
"#;
        let parser = CsharpParser::new();
        let deps = parser.parse(content);

        // Should only find Serilog (Newtonsoft.Json has no version)
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Serilog");
    }

    #[test]
    fn test_multiple_item_groups() {
        let content = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Package1" Version="1.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(Configuration)'=='Debug'">
    <PackageReference Include="Package2" Version="2.0.0" />
  </ItemGroup>
</Project>
"#;
        let parser = CsharpParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);
    }
}
