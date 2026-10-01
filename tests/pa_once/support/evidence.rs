use crowsi_credential_authority_contracts::EndpointPreparedOperationV2;
use ihat_identity_assertion_contracts::{
    AuthenticatorKindDto, CurrentDeviceStatusV1, DeviceIdentityAssertionV1, DevicePostureV1,
    FreshUvV1, IdentityEvidenceMetadata, RevocationEpochsV1,
};

pub(super) fn selected_identity() -> IdentityEvidenceMetadata {
    identity(60, 90, "selected-identity-nonce")
}

pub(super) fn current_identity() -> IdentityEvidenceMetadata {
    identity(112, 140, "submission-current-nonce")
}

fn identity(issued: u64, expires: u64, nonce: &str) -> IdentityEvidenceMetadata {
    let posture = DevicePostureV1 {
        state: "compliant".into(),
        revision: 4,
    };
    let epochs = RevocationEpochsV1 {
        subject: 2,
        service: 3,
        device: 5,
        session: 7,
    };
    let assertion = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "ihat-authority".into(),
        audience: "crowsi-windows-custody-provider".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "psu_owner_pairwise".into(),
        device_id: "device-b".into(),
        device_proof_key_ref: "proof-key-b".into(),
        session_ref: "session-b".into(),
        device_posture: posture.clone(),
        revocation_epochs: epochs.clone(),
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expires,
        nonce: nonce.into(),
        key_id: "identity-key-1".into(),
        signature: "11".repeat(64),
    };
    let current_status = CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: posture,
        revocation_epochs: epochs,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expires,
        nonce: nonce.into(),
        key_id: "status-key-1".into(),
        signature: "22".repeat(64),
    };
    IdentityEvidenceMetadata {
        assertion,
        current_status,
    }
}

pub(super) fn fresh_uv(
    selected: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    digest: &str,
) -> FreshUvV1 {
    let epochs = &selected.assertion.revocation_epochs;
    FreshUvV1 {
        schema: "ihat://identity/authority-host/fresh-uv/v1".into(),
        proof_id: "fresh-proof-1".into(),
        credential_id: "passkey-target-b".into(),
        authenticator_key_fingerprint: "a4".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: 110,
        expires_at_epoch_s: 135,
        challenge: "fresh-challenge-1".into(),
        attempt_id: "uv-attempt-1".into(),
        identity_nonce: selected.assertion.nonce.clone(),
        source_device_id: selected.assertion.device_id.clone(),
        service_id: selected.assertion.service_id.clone(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        session_ref: selected.assertion.session_ref.clone(),
        operation_digest_sha256: digest.into(),
        subject_epoch: epochs.subject,
        service_epoch: epochs.service,
        device_epoch: epochs.device,
        session_epoch: epochs.session,
        account_binding_sha256: "b2".repeat(32),
        key_id: "fresh-key-1".into(),
        signature: "33".repeat(64),
    }
}
