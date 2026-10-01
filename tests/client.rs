use crowsi_windows_operation_contracts::{HelperIdentity, ReasonCode};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

#[test]
fn helper_is_fd_pinned_and_rejects_changed_digest() {
    let root = std::env::temp_dir().join(format!(
        "crowsi-operation-contract-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("root");
    let helper = root.join("helper");
    let body = b"#!/bin/sh\nexit 0\n";
    fs::write(&helper, body).expect("write");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("mode");
    let digest = format!("sha256:{:x}", Sha256::digest(body));
    HelperIdentity::new(&helper, &digest).expect("pinned");
    assert_eq!(
        HelperIdentity::new(&helper, format!("sha256:{}", "0".repeat(64)))
            .err()
            .map(|value| value.0),
        Some(ReasonCode::HelperRejected)
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn contract_has_no_authority_backend_or_generic_secret_surface() {
    let source = concat!(
        include_str!("../src/client.rs"),
        include_str!("../src/contract.rs"),
        include_str!("../src/lib.rs"),
    );
    for forbidden in [
        "CredentialAuthority",
        "FileAuthorityStore",
        "MemoryStore",
        "GetSecret",
        "ExportSecret",
        "execute_generic",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("/proc/self/fd/"));
    assert!(source.contains("env_clear()"));
}
