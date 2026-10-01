use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementCommandV2, SignedAuthorityExchangeV1,
    endpoint_operation_digest,
};
use ihat_identity_assertion_contracts::*;
pub(super) fn identity(
    value: &IdentityEvidenceMetadata,
    request_id: &str,
    generation: u64,
) -> SignedAuthorityExchangeV1 {
    let proof_id = format!("sender-{request_id}");
    let command = AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
        IssueCurrentDeviceIdentityEvidenceCommand {
            service_id: value.assertion.service_id.clone(),
            pairwise_subject: value.assertion.pairwise_subject.clone(),
            device_id: value.assertion.device_id.clone(),
            audience: value.assertion.audience.clone(),
            identity_nonce: value.assertion.nonce.clone(),
            ttl_seconds: 30,
            session_sender_key_fingerprint: "55".repeat(32),
            session_sender_proof_id: proof_id.clone(),
        },
    );
    let sender = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id,
        key_id: "session-sender-key-1".into(),
        issued_at_epoch_s: value.assertion.issued_at_epoch_s,
        expires_at_epoch_s: value.assertion.expires_at_epoch_s,
        binding_sha256: String::new(),
        signature: "44".repeat(64),
    };
    exchange(
        request_id,
        command,
        vec![AuthorityEvidence::Signed(sender)],
        AuthorityResult::IdentityEvidence(value.clone()),
        value.assertion.issued_at_epoch_s,
        generation,
    )
}
pub(super) fn begin(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
) -> SignedAuthorityExchangeV1 {
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let command = AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
        command_id: "begin-target-uv".into(),
        credential_id: "passkey-target-b".into(),
        identity_nonce: assertion.nonce.clone(),
        source_device_id: assertion.device_id.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        session_ref: assertion.session_ref.clone(),
        operation_digest_sha256: endpoint_operation_digest(prepared).expect("digest"),
        subject_epoch: epochs.subject,
        service_epoch: epochs.service,
        device_epoch: epochs.device,
        session_epoch: epochs.session,
    });
    let options = FreshUvRequestOptions {
        attempt_id: "uv-attempt-1".into(),
        challenge: "fresh-challenge-1".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: "passkey-target-b".into(),
        timeout_ms: 120_000,
        expires_at_epoch_s: 135,
        command_binding_sha256: String::new(),
    };
    exchange(
        "begin-target-uv",
        command,
        vec![],
        AuthorityResult::FreshUvBegun(options),
        65,
        7,
    )
}
pub(super) fn finish(
    fresh: &FreshUvV1,
    browser: &ManagementCommandV2,
) -> SignedAuthorityExchangeV1 {
    let ManagementCommandV2::TargetApprove { assertion, .. } = browser else {
        unreachable!()
    };
    let command = AuthorityCommand::FinishFreshUserVerification(FinishFreshUvCommand {
        command_id: "finish-target-uv".into(),
        attempt_id: fresh.attempt_id.clone(),
        credential_id: fresh.credential_id.clone(),
        client_data_json_base64url: assertion.client_data_json_base64url.clone(),
        authenticator_data_base64url: assertion.authenticator_data_base64url.clone(),
        signature_der_base64url: assertion.signature_der_base64url.clone(),
    });
    exchange(
        "finish-target-uv",
        command,
        vec![],
        AuthorityResult::FreshUvFinished {
            document: fresh.clone(),
        },
        110,
        8,
    )
}
fn exchange(
    request_id: &str,
    command: AuthorityCommand,
    evidence: Vec<AuthorityEvidence>,
    result: AuthorityResult,
    issued: u64,
    generation: u64,
) -> SignedAuthorityExchangeV1 {
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        command,
        evidence,
    };
    let digest = command_digest(&request).expect("command digest");
    for item in &mut request.evidence {
        if let AuthorityEvidence::Signed(value) = item {
            value.binding_sha256.clone_from(&digest);
        }
    }
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request_id.into(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: generation,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: issued + 30,
        outcome: ResponseOutcome::Committed { result },
        key_id: "authority-key-1".into(),
        signature: "66".repeat(64),
    };
    if let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut response.outcome
    {
        options
            .command_binding_sha256
            .clone_from(&response.command_digest);
    }
    SignedAuthorityExchangeV1 { request, response }
}
