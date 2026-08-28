//! Build LSP `WorkspaceEdit` payloads that modify `.zed/settings.json`
//! to add packages to the `depsy` ignore list.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tower_lsp::lsp_types::{
    CreateFile, CreateFileOptions, DocumentChangeOperation, DocumentChanges, OneOf,
    OptionalVersionedTextDocumentIdentifier, Position, Range, ResourceOp, TextDocumentEdit,
    TextEdit, Url, WorkspaceEdit,
};

const SETTINGS_REL_PATH: &str = ".zed/settings.json";

/// Build a `WorkspaceEdit` that adds `package_name` to the `depsy` ignore list
/// inside `<workspace_root>/.zed/settings.json`.
///
/// - If `current_settings_text` is `None`, the edit creates the file with the
///   minimal nested structure.
/// - If `current_settings_text` is `Some(s)` and parses as JSON, the edit replaces
///   the whole file with a pretty-printed version that has `package_name` appended
///   to `lsp.depsy.initialization_options.ignore` (deduplicated).
/// - If parsing fails, returns `Err` so the caller can silently skip the action.
pub fn build_ignore_workspace_edit(
    workspace_root: &Path,
    package_name: &str,
    current_settings_text: Option<&str>,
) -> Result<WorkspaceEdit> {
    let settings_path = workspace_root.join(SETTINGS_REL_PATH);
    let settings_uri = Url::from_file_path(&settings_path)
        .map_err(|()| anyhow::anyhow!("invalid settings.json path: {}", settings_path.display()))?;

    match current_settings_text {
        None => Ok(build_create_edit(settings_uri, package_name)),
        Some(text) => build_replace_edit(settings_uri, package_name, text),
    }
}

fn build_create_edit(settings_uri: Url, package_name: &str) -> WorkspaceEdit {
    let value = json!({
        "lsp": {
            "depsy": {
                "initialization_options": {
                    "ignore": [package_name]
                }
            }
        }
    });
    let text = serde_json::to_string_pretty(&value).unwrap_or_default() + "\n";

    let create = CreateFile {
        uri: settings_uri.clone(),
        options: Some(CreateFileOptions {
            overwrite: Some(false),
            ignore_if_exists: Some(true),
        }),
        annotation_id: None,
    };
    let text_edit = TextDocumentEdit {
        text_document: OptionalVersionedTextDocumentIdentifier {
            uri: settings_uri,
            version: None,
        },
        edits: vec![OneOf::Left(TextEdit {
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: u32::MAX,
                    character: u32::MAX,
                },
            },
            new_text: text,
        })],
    };

    WorkspaceEdit {
        changes: None,
        document_changes: Some(DocumentChanges::Operations(vec![
            DocumentChangeOperation::Op(ResourceOp::Create(create)),
            DocumentChangeOperation::Edit(text_edit),
        ])),
        change_annotations: None,
    }
}

fn build_replace_edit(
    settings_uri: Url,
    package_name: &str,
    current: &str,
) -> Result<WorkspaceEdit> {
    let mut root: Value =
        serde_json::from_str(current).with_context(|| "failed to parse .zed/settings.json")?;

    if !root.is_object() {
        anyhow::bail!(".zed/settings.json root must be a JSON object");
    }

    let lsp = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("root must be object"))?
        .entry("lsp")
        .or_insert_with(|| json!({}));
    let lsp_obj = lsp
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("'lsp' must be an object"))?;

    // Migrated users may still keep their ignore list under `lsp.dependi`. The extension
    // feeds that as the base and Zed replaces (not concatenates) arrays when merging
    // `lsp.depsy` over it, so the depsy list must carry those entries too.
    let legacy_ignore: Vec<Value> = lsp_obj
        .get("dependi")
        .and_then(|v| v.pointer("/initialization_options/ignore"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let depsy = lsp_obj.entry("depsy").or_insert_with(|| json!({}));
    let depsy_obj = depsy
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("'lsp.depsy' must be an object"))?;

    let init_opts = depsy_obj
        .entry("initialization_options")
        .or_insert_with(|| json!({}));
    let init_opts_obj = init_opts
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("'lsp.depsy.initialization_options' must be an object"))?;

    let ignore_array = init_opts_obj.entry("ignore").or_insert_with(|| json!([]));
    let arr = ignore_array
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("'ignore' must be an array"))?;

    for legacy in legacy_ignore {
        if !arr.contains(&legacy) {
            arr.push(legacy);
        }
    }

    let already_present = arr.iter().any(|v| v.as_str() == Some(package_name));
    if !already_present {
        arr.push(Value::String(package_name.to_string()));
    }

    let new_text = serde_json::to_string_pretty(&root).unwrap_or_default() + "\n";

    // NOTE: We pass `version: None` because .zed/settings.json is not tracked
    // as an open LSP document. Concurrent edits between read and apply are
    // possible but rare in practice; acceptable for a local dev tool.
    let text_edit = TextDocumentEdit {
        text_document: OptionalVersionedTextDocumentIdentifier {
            uri: settings_uri,
            version: None,
        },
        edits: vec![OneOf::Left(TextEdit {
            // Replace-whole-document: use u32::MAX for line/character to mean
            // "end of document" per the conventional LSP pattern. Avoids
            // off-by-one issues with line count vs. exclusive end-line.
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: u32::MAX,
                    character: u32::MAX,
                },
            },
            new_text,
        })],
    };

    Ok(WorkspaceEdit {
        changes: None,
        document_changes: Some(DocumentChanges::Edits(vec![text_edit])),
        change_annotations: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_edit_text_contains(edit: &WorkspaceEdit, needle: &str) {
        let dc = edit
            .document_changes
            .as_ref()
            .expect("expected document_changes");
        let text = match dc {
            DocumentChanges::Edits(edits) => edits
                .iter()
                .flat_map(|e| e.edits.iter())
                .filter_map(|e| match e {
                    OneOf::Left(te) => Some(te.new_text.clone()),
                    _ => None,
                })
                .collect::<String>(),
            DocumentChanges::Operations(ops) => ops
                .iter()
                .filter_map(|op| match op {
                    DocumentChangeOperation::Edit(te) => Some(
                        te.edits
                            .iter()
                            .filter_map(|e| match e {
                                OneOf::Left(t) => Some(t.new_text.clone()),
                                _ => None,
                            })
                            .collect::<String>(),
                    ),
                    _ => None,
                })
                .collect::<String>(),
        };
        assert!(
            text.contains(needle),
            "expected edit text to contain `{needle}`. Actual text:\n{text}"
        );
    }

    #[test]
    fn test_build_edit_creates_file_when_missing() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let edit = build_ignore_workspace_edit(&root, "lodash", None).unwrap();

        let dc = edit.document_changes.as_ref().unwrap();
        let DocumentChanges::Operations(ops) = dc else {
            panic!("expected Operations variant when creating file");
        };
        assert!(matches!(
            ops.first().unwrap(),
            DocumentChangeOperation::Op(ResourceOp::Create(_))
        ));
        assert_edit_text_contains(&edit, "\"lodash\"");
        assert_edit_text_contains(&edit, "\"ignore\"");
        assert_edit_text_contains(&edit, "\"depsy\"");
    }

    #[test]
    fn test_build_edit_inserts_into_empty_object() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let edit = build_ignore_workspace_edit(&root, "lodash", Some("{}")).unwrap();
        assert_edit_text_contains(&edit, "\"lodash\"");
        assert_edit_text_contains(&edit, "\"ignore\"");
    }

    #[test]
    fn test_build_edit_appends_to_existing_ignore_list() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let current = r#"{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": ["react"]
      }
    }
  }
}"#;
        let edit = build_ignore_workspace_edit(&root, "lodash", Some(current)).unwrap();
        assert_edit_text_contains(&edit, "\"lodash\"");
        assert_edit_text_contains(&edit, "\"react\"");
    }

    #[test]
    fn test_build_edit_dedupes_existing_package() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let current = r#"{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": ["lodash"]
      }
    }
  }
}"#;
        let edit = build_ignore_workspace_edit(&root, "lodash", Some(current)).unwrap();
        let dc = edit.document_changes.as_ref().unwrap();
        let DocumentChanges::Edits(edits) = dc else {
            panic!("expected Edits variant on update");
        };
        let text = &edits[0].edits[0];
        let OneOf::Left(te) = text else {
            panic!("expected TextEdit");
        };
        let count = te.new_text.matches("\"lodash\"").count();
        assert_eq!(count, 1, "package name should not be duplicated");
    }

    #[test]
    fn test_build_edit_folds_legacy_dependi_ignore_list() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let current = r#"{
  "lsp": {
    "dependi": {
      "initialization_options": {
        "ignore": ["react", "lodash"]
      }
    }
  }
}"#;
        let edit = build_ignore_workspace_edit(&root, "lodash", Some(current)).unwrap();
        let dc = edit.document_changes.as_ref().unwrap();
        let DocumentChanges::Edits(edits) = dc else {
            panic!("expected Edits variant on update");
        };
        let OneOf::Left(te) = &edits[0].edits[0] else {
            panic!("expected TextEdit");
        };
        let written: Value = serde_json::from_str(&te.new_text).unwrap();
        assert_eq!(
            written.pointer("/lsp/depsy/initialization_options/ignore"),
            Some(&json!(["react", "lodash"])),
            "legacy dependi entries must be folded into the depsy list, without duplicates"
        );
        assert_eq!(
            written.pointer("/lsp/dependi/initialization_options/ignore"),
            Some(&json!(["react", "lodash"])),
            "legacy dependi block must be left untouched"
        );
    }

    #[test]
    fn test_build_edit_preserves_other_settings() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let current = r#"{
  "theme": "One Dark",
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": []
      }
    }
  }
}"#;
        let edit = build_ignore_workspace_edit(&root, "lodash", Some(current)).unwrap();
        assert_edit_text_contains(&edit, "\"One Dark\"");
        assert_edit_text_contains(&edit, "\"theme\"");
        assert_edit_text_contains(&edit, "\"lodash\"");
    }

    #[test]
    fn test_build_edit_handles_invalid_json_returns_err() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let result = build_ignore_workspace_edit(&root, "lodash", Some("{ invalid"));
        assert!(result.is_err(), "invalid JSON should return Err");
    }

    #[test]
    fn test_build_edit_inserts_lsp_path_when_missing() {
        let root = std::path::PathBuf::from("/tmp/ws");
        let current = r#"{ "theme": "dark" }"#;
        let edit = build_ignore_workspace_edit(&root, "lodash", Some(current)).unwrap();
        assert_edit_text_contains(&edit, "\"lodash\"");
        assert_edit_text_contains(&edit, "\"depsy\"");
        assert_edit_text_contains(&edit, "\"theme\"");
    }
}
