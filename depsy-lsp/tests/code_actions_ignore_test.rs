//! End-to-end test for the "Ignore package" code action workflow.
//!
//! Verifies the full lifecycle:
//! 1. settings.json missing — edit creates the file with proper nested structure
//! 2. settings.json exists — edit appends a new package preserving existing entries
//! 3. settings.json exists with package already present — edit dedupes (no duplicate)

use depsy_lsp::settings_edit::build_ignore_workspace_edit;
use tempfile::tempdir;
use tower_lsp::lsp_types::{
    DocumentChangeOperation, DocumentChanges, OneOf, ResourceOp, WorkspaceEdit,
};

#[test]
fn test_create_then_append_then_dedupe_full_cycle() {
    let dir = tempdir().expect("tempdir");
    let workspace = dir.path();

    // Step 1: file does not exist — edit should be a CreateFile + insert
    let edit = build_ignore_workspace_edit(workspace, "lodash", None).unwrap();
    let dc = edit.document_changes.expect("document_changes");
    let DocumentChanges::Operations(ops) = dc else {
        panic!("expected Operations variant for create case")
    };
    assert!(matches!(
        ops.first().unwrap(),
        DocumentChangeOperation::Op(ResourceOp::Create(_))
    ));

    // Simulate Zed applying the edit: write the file
    let settings_path = workspace.join(".zed").join("settings.json");
    std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    let new_text = extract_inserted_text(&ops);
    assert!(
        new_text.contains("\"lodash\""),
        "create text should contain lodash"
    );
    assert!(
        new_text.contains("\"ignore\""),
        "create text should contain ignore key"
    );
    std::fs::write(&settings_path, &new_text).unwrap();

    // Step 2: file exists — edit should append "react"
    let current = std::fs::read_to_string(&settings_path).unwrap();
    let edit2 = build_ignore_workspace_edit(workspace, "react", Some(&current)).unwrap();
    let new_text2 = extract_replace_text(&edit2);
    assert!(
        new_text2.contains("\"lodash\""),
        "append should preserve lodash"
    );
    assert!(new_text2.contains("\"react\""), "append should add react");
    std::fs::write(&settings_path, &new_text2).unwrap();

    // Step 3: re-add lodash — should dedupe
    let current2 = std::fs::read_to_string(&settings_path).unwrap();
    let edit3 = build_ignore_workspace_edit(workspace, "lodash", Some(&current2)).unwrap();
    let new_text3 = extract_replace_text(&edit3);
    let lodash_count = new_text3.matches("\"lodash\"").count();
    assert_eq!(
        lodash_count, 1,
        "lodash should appear exactly once after dedupe, got {lodash_count}"
    );
    let react_count = new_text3.matches("\"react\"").count();
    assert_eq!(
        react_count, 1,
        "react should still appear exactly once, got {react_count}"
    );
}

#[test]
fn test_invalid_json_returns_err_does_not_corrupt() {
    let dir = tempdir().unwrap();
    let workspace = dir.path();
    let result = build_ignore_workspace_edit(workspace, "lodash", Some("{ broken"));
    assert!(result.is_err(), "invalid JSON should return Err");
}

#[test]
fn test_preserves_unrelated_settings_through_full_cycle() {
    let dir = tempdir().unwrap();
    let workspace = dir.path();

    // Start with a settings.json that has unrelated keys
    let initial = r#"{
  "theme": "One Dark",
  "buffer_font_size": 14,
  "lsp": {
    "other-server": {
      "settings": { "format_on_save": true }
    }
  }
}"#;

    let edit = build_ignore_workspace_edit(workspace, "lodash", Some(initial)).unwrap();
    let new_text = extract_replace_text(&edit);

    assert!(
        new_text.contains("\"One Dark\""),
        "theme should be preserved"
    );
    assert!(
        new_text.contains("\"buffer_font_size\""),
        "buffer_font_size should be preserved"
    );
    assert!(
        new_text.contains("\"other-server\""),
        "other LSP server should be preserved"
    );
    assert!(
        new_text.contains("\"format_on_save\""),
        "nested settings should be preserved"
    );
    assert!(new_text.contains("\"lodash\""), "lodash should be added");
    assert!(new_text.contains("\"depsy\""), "depsy key should be added");
}

fn extract_inserted_text(ops: &[DocumentChangeOperation]) -> String {
    for op in ops {
        if let DocumentChangeOperation::Edit(te) = op {
            for edit in &te.edits {
                if let OneOf::Left(t) = edit {
                    return t.new_text.clone();
                }
            }
        }
    }
    String::new()
}

fn extract_replace_text(edit: &WorkspaceEdit) -> String {
    let dc = edit.document_changes.as_ref().expect("document_changes");
    match dc {
        DocumentChanges::Edits(edits) => {
            let first = &edits[0].edits[0];
            let OneOf::Left(te) = first else {
                panic!("expected TextEdit")
            };
            te.new_text.clone()
        }
        _ => panic!("expected Edits variant on update"),
    }
}
