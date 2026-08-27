use std::collections::BTreeSet;

use toml::Value;

#[test]
fn depsy_lsp_uses_only_required_tokio_features() {
    let manifest: Value =
        toml::from_str(include_str!("../Cargo.toml")).expect("Cargo.toml is valid TOML");
    let features = manifest["dependencies"]["tokio"]["features"]
        .as_array()
        .expect("tokio declares explicit features")
        .iter()
        .map(|feature| feature.as_str().expect("tokio features are strings"))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        features,
        BTreeSet::from([
            "fs",
            "io-std",
            "io-util",
            "macros",
            "rt-multi-thread",
            "sync",
            "time",
        ])
    );
}
