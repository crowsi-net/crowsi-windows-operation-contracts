#[path = "support/evidence.rs"]
mod evidence;
#[path = "support/exchange.rs"]
mod exchange;
#[path = "support/target.rs"]
mod target;

use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, endpoint_operation_digest,
    endpoint_operation_id, target_device_proof_digest,
};
use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA, OperationAuthorizeOnceRequestV2,
    OperationOnlyCredentialClass, OperationOnlySignIntentV1, SigningAlgorithm,
};

pub fn request() -> OperationAuthorizeOnceRequestV2 {
    let selected = evidence::selected_identity();
    let current = evidence::current_identity();
    let mut prepared = prepared();
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let operation_digest = endpoint_operation_digest(&prepared).expect("operation digest");
    let fresh = evidence::fresh_uv(&selected, &prepared, &operation_digest);
    let management_request = target::management(&prepared.operation_id);
    let target_proof = target::proof(&current, &prepared, &operation_digest);
    let proof_digest = target_device_proof_digest(&target_proof).expect("proof digest");
    OperationAuthorizeOnceRequestV2 {
        schema: OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA.into(),
        selected_identity_exchange: exchange::identity(&selected, "selected-identity", 7),
        selected_begin_exchange: exchange::begin(&selected, &prepared),
        finish_exchange: exchange::finish(&fresh, &management_request.command),
        current_identity_exchange: exchange::identity(&current, "current-identity", 8),
        prepared: prepared.clone(),
        management_request,
        target_device_proof: target_proof,
        sign_intent: OperationOnlySignIntentV1 {
            request_id: "custody-request-1".into(),
            credential_id: "custody-device-key-b".into(),
            expected_revision: target::revision(),
            credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
            algorithm: SigningAlgorithm::Ed25519,
            digest_sha256: format!("sha256:{}", hex::encode(proof_digest)),
        },
    }
}

fn prepared() -> EndpointPreparedOperationV2 {
    EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "a1".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: "session-a".into(),
        pairwise_subject: "psu_owner_pairwise".into(),
        opaque_owner_ref: "psa_owner_abcdefghijklmnopqrst".into(),
        source_identity_nonce: "source-identity-nonce".into(),
        nonce: "operation-nonce".into(),
        issued_at_epoch_s: 50,
        expires_at_epoch_s: 150,
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service:crowsi".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-transfer-1".into()],
            expected_snapshot_revision: 7,
            nonce: "transfer-nonce".into(),
        },
        revocation: None,
    }
}
