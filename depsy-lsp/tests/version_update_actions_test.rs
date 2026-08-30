use depsy_lsp::cache::{MemoryCache, WriteCache};
use depsy_lsp::file_types::FileType;
use depsy_lsp::parsers::Parser;
use depsy_lsp::parsers::cargo::CargoParser;
use depsy_lsp::parsers::csharp::CsharpParser;
use depsy_lsp::parsers::dart::DartParser;
use depsy_lsp::parsers::go::GoParser;
use depsy_lsp::parsers::maven::MavenParser;
use depsy_lsp::parsers::npm::NpmParser;
use depsy_lsp::parsers::php::PhpParser;
use depsy_lsp::parsers::python::PythonParser;
use depsy_lsp::parsers::ruby::RubyParser;
use depsy_lsp::providers::code_actions::create_code_actions;
use depsy_lsp::registries::VersionInfo;
use tower_lsp::lsp_types::{CodeActionOrCommand, Position, Range, TextEdit, Url};

struct UpdateCase {
    parser: Box<dyn Parser>,
    file_type: FileType,
    uri: &'static str,
    package: &'static str,
    manifest: &'static str,
    latest: &'static str,
    expected: &'static str,
}

fn position_offset(content: &str, position: Position) -> Option<usize> {
    let line_offset: usize = content
        .split_inclusive('\n')
        .take(position.line as usize)
        .map(str::len)
        .sum();
    let offset = line_offset.checked_add(position.character as usize)?;
    (offset <= content.len()).then_some(offset)
}

fn apply_text_edit(content: &str, edit: &TextEdit) -> Option<String> {
    let start = position_offset(content, edit.range.start)?;
    let end = position_offset(content, edit.range.end)?;
    let mut updated = String::with_capacity(content.len() + edit.new_text.len());
    updated.push_str(content.get(..start)?);
    updated.push_str(&edit.new_text);
    updated.push_str(content.get(end..)?);
    Some(updated)
}

async fn apply_individual_update(case: &UpdateCase) -> Option<String> {
    let dependencies = case.parser.parse(case.manifest);
    let dependency = dependencies.iter().find(|dep| dep.name == case.package)?;
    let cache = MemoryCache::new();
    cache
        .insert(
            format!("test:{}", case.package),
            VersionInfo {
                latest: Some(case.latest.to_string()),
                ..Default::default()
            },
        )
        .await;
    let uri = Url::parse(case.uri).ok()?;
    let range = Range {
        start: Position::new(dependency.version_span.line, 0),
        end: Position::new(dependency.version_span.line, u32::MAX),
    };
    let actions = create_code_actions(
        &dependencies,
        &cache,
        &uri,
        range,
        case.file_type,
        |name| format!("test:{name}"),
        &[],
        None,
        None,
    )
    .await;
    let edit = actions.into_iter().find_map(|action| {
        let CodeActionOrCommand::CodeAction(action) = action else {
            return None;
        };
        let changes = action.edit?.changes?;
        changes.get(&uri)?.first().cloned()
    })?;
    apply_text_edit(case.manifest, &edit)
}

#[tokio::test]
async fn parsed_manifests_keep_safe_constraint_shapes_when_updated() {
    let cases = [
        UpdateCase {
            parser: Box::new(CargoParser::new()),
            file_type: FileType::Cargo,
            uri: "file:///test/Cargo.toml",
            package: "package",
            manifest: "[dependencies]\npackage = \"^4.0.2\"\n",
            latest: "5.1.0",
            expected: "[dependencies]\npackage = \"^5.1.0\"\n",
        },
        UpdateCase {
            parser: Box::new(CargoParser::new()),
            file_type: FileType::Cargo,
            uri: "file:///test/Cargo.toml",
            package: "package",
            manifest: "[target.'cfg(unix)'.dependencies]\npackage = \"^4.0.2\"\n",
            latest: "5.1.0",
            expected: "[target.'cfg(unix)'.dependencies]\npackage = \"^5.1.0\"\n",
        },
        UpdateCase {
            parser: Box::new(NpmParser::new()),
            file_type: FileType::Npm,
            uri: "file:///test/package.json",
            package: "package",
            manifest: "{\n  \"dependencies\": {\n    \"package\": \"^4.0.2\"\n  }\n}\n",
            latest: "5.1.0",
            expected: "{\n  \"dependencies\": {\n    \"package\": \"^5.1.0\"\n  }\n}\n",
        },
        UpdateCase {
            parser: Box::new(PythonParser::new()),
            file_type: FileType::Python,
            uri: "file:///test/requirements.txt",
            package: "package",
            manifest: "package~=14.2\n",
            latest: "14.3.3",
            expected: "package~=14.3\n",
        },
        UpdateCase {
            parser: Box::new(PhpParser::new()),
            file_type: FileType::Php,
            uri: "file:///test/composer.json",
            package: "vendor/package",
            manifest: "{\"require\": {\"vendor/package\": \"^1.2\"}}\n",
            latest: "2.3.4",
            expected: "{\"require\": {\"vendor/package\": \"^2.3\"}}\n",
        },
        UpdateCase {
            parser: Box::new(DartParser::new()),
            file_type: FileType::Dart,
            uri: "file:///test/pubspec.yaml",
            package: "package",
            manifest: "name: app\ndependencies:\n  package: ^1.2\n",
            latest: "2.3.4",
            expected: "name: app\ndependencies:\n  package: ^2.3\n",
        },
        UpdateCase {
            parser: Box::new(CsharpParser::new()),
            file_type: FileType::Csharp,
            uri: "file:///test/App.csproj",
            package: "Package",
            manifest: "<Project><ItemGroup><PackageReference Include=\"Package\" Version=\"[1.0]\" /></ItemGroup></Project>\n",
            latest: "2.0",
            expected: "<Project><ItemGroup><PackageReference Include=\"Package\" Version=\"[2.0]\" /></ItemGroup></Project>\n",
        },
        UpdateCase {
            parser: Box::new(CsharpParser::new()),
            file_type: FileType::Csharp,
            uri: "file:///test/Directory.Packages.props",
            package: "Package",
            manifest: "<Project><ItemGroup><PackageVersion Include=\"Package\" Version=\"[1.0]\" /></ItemGroup></Project>\n",
            latest: "2.0",
            expected: "<Project><ItemGroup><PackageVersion Include=\"Package\" Version=\"[2.0]\" /></ItemGroup></Project>\n",
        },
        UpdateCase {
            parser: Box::new(CsharpParser::new()),
            file_type: FileType::Csharp,
            uri: "file:///test/Directory.Packages.props",
            package: "Package",
            manifest: "<Project>\n  <ItemGroup>\n    <PackageVersion Update=\"Package\">\n      <Version>[1.0]</Version>\n    </PackageVersion>\n  </ItemGroup>\n</Project>\n",
            latest: "2.0",
            expected: "<Project>\n  <ItemGroup>\n    <PackageVersion Update=\"Package\">\n      <Version>[2.0]</Version>\n    </PackageVersion>\n  </ItemGroup>\n</Project>\n",
        },
        UpdateCase {
            parser: Box::new(RubyParser::new()),
            file_type: FileType::Ruby,
            uri: "file:///test/Gemfile",
            package: "package",
            manifest: "gem \"package\", \"~> 7.0\"\n",
            latest: "8.1.4",
            expected: "gem \"package\", \"~> 8.1\"\n",
        },
        UpdateCase {
            parser: Box::new(GoParser::new()),
            file_type: FileType::Go,
            uri: "file:///test/go.mod",
            package: "example.com/package",
            manifest: "module example.com/app\n\nrequire example.com/package v1.2.3\n",
            latest: "1.3.0",
            expected: "module example.com/app\n\nrequire example.com/package v1.3.0\n",
        },
        UpdateCase {
            parser: Box::new(MavenParser::new()),
            file_type: FileType::Maven,
            uri: "file:///test/pom.xml",
            package: "org.example:package",
            manifest: "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.example</groupId>\n      <artifactId>package</artifactId>\n      <version>1.0.0.Final</version>\n    </dependency>\n  </dependencies>\n</project>\n",
            latest: "2.0.0-RC1",
            expected: "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.example</groupId>\n      <artifactId>package</artifactId>\n      <version>2.0.0-RC1</version>\n    </dependency>\n  </dependencies>\n</project>\n",
        },
    ];

    for case in cases {
        assert_eq!(
            apply_individual_update(&case).await.as_deref(),
            Some(case.expected),
            "failed for {:?}",
            case.file_type
        );
    }
}

#[tokio::test]
async fn compound_python_and_ruby_declarations_have_no_update_action() {
    let cases = [
        UpdateCase {
            parser: Box::new(PythonParser::new()),
            file_type: FileType::Python,
            uri: "file:///test/requirements.txt",
            package: "package",
            manifest: "package>=1.0,<2.0\n",
            latest: "3.0.0",
            expected: "",
        },
        UpdateCase {
            parser: Box::new(RubyParser::new()),
            file_type: FileType::Ruby,
            uri: "file:///test/Gemfile",
            package: "package",
            manifest: "gem \"package\", \">= 1\", \"< 2\"\n",
            latest: "3.0.0",
            expected: "",
        },
    ];

    for case in cases {
        assert_eq!(
            apply_individual_update(&case).await,
            None,
            "unexpected update for {:?}",
            case.file_type
        );
    }
}

#[tokio::test]
async fn fragmented_csharp_child_version_has_no_update_action() {
    let case = UpdateCase {
        parser: Box::new(CsharpParser::new()),
        file_type: FileType::Csharp,
        uri: "file:///test/Directory.Packages.props",
        package: "Package",
        manifest: "<Project><PackageVersion Include=\"Package\"><Version>1<!-- split -->.2.3</Version></PackageVersion></Project>\n",
        latest: "2.0",
        expected: "",
    };

    assert_eq!(apply_individual_update(&case).await, None);
}
