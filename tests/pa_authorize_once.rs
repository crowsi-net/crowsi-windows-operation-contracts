#[path = "pa_once/current.rs"]
mod current;
#[path = "pa_once/support.rs"]
mod support;

use crowsi_credential_authority_contracts::{
    ManagementCommandV2, fresh_uv_from_finish_exchange, identity_evidence_from_exchange,
};
use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA, decode_operation_authorize_once_request,
};

#[test]
fn pa_06_closed_target_sign_request_round_trips() {
    let expected = support::request();
    let wire = serde_json::to_vec(&expected).expect("wire");
    assert_eq!(decode_operation_authorize_once_request(&wire), Ok(expected));
}

#[test]
fn pa_06_finish_precedes_fresh_current_identity_and_target_proof() {
    let value = support::request();
    let current = identity_evidence_from_exchange(&value.current_identity_exchange)
        .expect("current identity");
    let fresh =
        fresh_uv_from_finish_exchange(&value.finish_exchange, &value.management_request.command)
            .expect("FreshUV");
    assert_ne!(fresh.identity_nonce, current.assertion.nonce);
    assert!(fresh.issued_at_epoch_s <= current.assertion.issued_at_epoch_s);
    assert!(current.assertion.issued_at_epoch_s <= value.target_device_proof.issued_at_epoch_s);
    let wire = serde_json::to_vec(&value).expect("wire");
    assert_eq!(decode_operation_authorize_once_request(&wire), Ok(value));
}

#[test]
fn pa_06_wire_carries_only_signed_approval_exchanges() {
    let value = serde_json::to_value(support::request()).expect("value");
    assert!(value.get("identity").is_none());
    assert!(value.get("fresh_uv").is_none());
    for field in [
        "selected_identity_exchange",
        "selected_begin_exchange",
        "finish_exchange",
        "current_identity_exchange",
    ] {
        assert!(value.get(field).is_some(), "missing {field}");
    }
}

#[test]
fn pa_06_unknown_trailing_oversize_and_legacy_shapes_fail_closed() {
    let value = support::request();
    let mut unknown = serde_json::to_value(&value).expect("value");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("secret".into(), true.into());
    assert!(
        decode_operation_authorize_once_request(&serde_json::to_vec(&unknown).expect("wire"))
            .is_err()
    );
    let mut trailing = serde_json::to_vec(&value).expect("wire");
    trailing.extend_from_slice(b" {}");
    assert!(decode_operation_authorize_once_request(&trailing).is_err());
    assert!(decode_operation_authorize_once_request(&vec![b' '; 65_537]).is_err());
    let mut legacy = serde_json::to_value(&value).expect("value");
    legacy["schema"] = "crowsi://policy-authority/operation-authorize-once-request/v1".into();
    assert!(
        decode_operation_authorize_once_request(&serde_json::to_vec(&legacy).expect("wire"))
            .is_err()
    );
}

#[test]
fn op_16_only_exact_target_approve_ed25519_proof_digest_is_accepted() {
    let base = support::request();
    let mut wrong_phase = base.clone();
    wrong_phase.management_request.command = ManagementCommandV2::TargetOptions {
        operation_id: base.prepared.operation_id.clone(),
        expected_state_revision: 8,
    };
    assert!(
        decode_operation_authorize_once_request(&serde_json::to_vec(&wrong_phase).expect("wire"))
            .is_err()
    );
    let mutations: [fn(&mut serde_json::Value); 3] = [
        |value: &mut serde_json::Value| {
            value["sign_intent"]["algorithm"] = "rsa-pkcs1-sha256".into();
        },
        |value: &mut serde_json::Value| {
            value["sign_intent"]["digest_sha256"] = format!("sha256:{}", "0".repeat(64)).into();
        },
        |value: &mut serde_json::Value| {
            value["target_device_proof"]["target_device_ref"] = "device-a".into();
        },
    ];
    for mutate in mutations {
        let mut changed = serde_json::to_value(&base).expect("value");
        mutate(&mut changed);
        assert!(
            decode_operation_authorize_once_request(&serde_json::to_vec(&changed).expect("wire"))
                .is_err()
        );
    }
    let mut provider = serde_json::to_value(base).expect("value");
    provider["sign_intent"] = serde_json::json!({
        "kind": "provider-operation", "provider": "github",
        "operation": "sign-app-jwt", "input_digest_sha256": format!("sha256:{}", "a".repeat(64))
    });
    assert!(
        decode_operation_authorize_once_request(&serde_json::to_vec(&provider).expect("wire"))
            .is_err()
    );
}

#[test]
fn schema_constant_is_current_only() {
    assert_eq!(
        OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA,
        "crowsi://policy-authority/operation-authorize-once-request/v2"
    );
}
