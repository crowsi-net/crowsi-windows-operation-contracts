use crate::OperationAuthorizeOnceRequestV2;
use crowsi_credential_authority_contracts::{
    SignedAuthorityExchangeV1, endpoint_operation_digest, fresh_uv_from_finish_exchange,
    identity_evidence_from_exchange, validate_finish_uv_continuity,
};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, FreshUvV1, IdentityEvidenceMetadata,
};

pub(crate) struct ApprovalEvidence<'a> {
    pub selected: &'a IdentityEvidenceMetadata,
    pub current: &'a IdentityEvidenceMetadata,
    pub fresh: &'a FreshUvV1,
}
pub(crate) fn evidence(value: &OperationAuthorizeOnceRequestV2) -> Option<ApprovalEvidence<'_>> {
    let selected = identity_evidence_from_exchange(&value.selected_identity_exchange).ok()?;
    let current = identity_evidence_from_exchange(&value.current_identity_exchange).ok()?;
    let fresh =
        fresh_uv_from_finish_exchange(&value.finish_exchange, &value.management_request.command)
            .ok()?;
    Some(ApprovalEvidence {
        selected,
        current,
        fresh,
    })
}
pub(crate) fn valid(value: &OperationAuthorizeOnceRequestV2) -> bool {
    let Some(proof) = evidence(value) else {
        return false;
    };
    validate_finish_uv_continuity(
        &value.selected_begin_exchange,
        &value.finish_exchange,
        &value.management_request.command,
    )
    .is_ok()
        && stable(&proof, value)
        && ordered(&proof, value)
        && roles(&proof, value)
}

fn stable(proof: &ApprovalEvidence<'_>, value: &OperationAuthorizeOnceRequestV2) -> bool {
    let old = &proof.selected.assertion;
    let new = &proof.current.assertion;
    let fresh = proof.fresh;
    old.issuer == new.issuer
        && old.audience == new.audience
        && old.service_id == new.service_id
        && old.pairwise_subject == new.pairwise_subject
        && old.device_id == new.device_id
        && old.device_proof_key_ref == new.device_proof_key_ref
        && old.session_ref == new.session_ref
        && old.device_posture == new.device_posture
        && old.revocation_epochs == new.revocation_epochs
        && fresh.user_verified
        && fresh.identity_nonce == old.nonce
        && fresh.source_device_id == old.device_id
        && fresh.service_id == old.service_id
        && fresh.pairwise_subject == old.pairwise_subject
        && fresh.session_ref == old.session_ref
        && fresh.operation_digest_sha256
            == endpoint_operation_digest(&value.prepared).unwrap_or_default()
        && epochs(old, fresh)
}

fn ordered(proof: &ApprovalEvidence<'_>, value: &OperationAuthorizeOnceRequestV2) -> bool {
    let exchanges = [
        &value.selected_identity_exchange,
        &value.selected_begin_exchange,
        &value.finish_exchange,
        &value.current_identity_exchange,
    ];
    let generations = exchanges.map(|item| item.response.config_generation);
    let issued = exchanges.map(|item| item.response.issued_at_epoch_s);
    let current = proof.current;
    let begin_time = value.selected_begin_exchange.response.issued_at_epoch_s;
    generations[0] > 0
        && generations.windows(2).all(|pair| pair[0] <= pair[1])
        && issued.windows(2).all(|pair| pair[0] <= pair[1])
        && identity_current_at(proof.selected, begin_time)
        && proof.fresh.issued_at_epoch_s <= current.assertion.issued_at_epoch_s
        && current.assertion.issued_at_epoch_s == current.current_status.issued_at_epoch_s
        && current.assertion.issued_at_epoch_s <= issued[3]
}

fn roles(proof: &ApprovalEvidence<'_>, value: &OperationAuthorizeOnceRequestV2) -> bool {
    let Some(selected_sender) = sender(&value.selected_identity_exchange) else {
        return false;
    };
    let Some(current_sender) = sender(&value.current_identity_exchange) else {
        return false;
    };
    let authority = &value.current_identity_exchange.response.key_id;
    let assertion = &proof.current.assertion;
    selected_sender == current_sender
        && value.selected_identity_exchange.response.key_id == *authority
        && value.selected_begin_exchange.response.key_id == *authority
        && value.finish_exchange.response.key_id == *authority
        && distinct(&[
            authority,
            &assertion.key_id,
            &proof.current.current_status.key_id,
            &proof.fresh.key_id,
            selected_sender.0,
            &assertion.device_proof_key_ref,
        ])
}

fn sender(value: &SignedAuthorityExchangeV1) -> Option<(&str, &str)> {
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &value.request.command
    else {
        return None;
    };
    let [AuthorityEvidence::Signed(sender)] = value.request.evidence.as_slice() else {
        return None;
    };
    Some((&sender.key_id, &command.session_sender_key_fingerprint))
}

fn identity_current_at(value: &IdentityEvidenceMetadata, now: u64) -> bool {
    let assertion = &value.assertion;
    let status = &value.current_status;
    assertion.issued_at_epoch_s == status.issued_at_epoch_s
        && assertion.issued_at_epoch_s <= now
        && now < assertion.expires_at_epoch_s
        && now < status.expires_at_epoch_s
}

fn epochs(
    assertion: &ihat_identity_assertion_contracts::DeviceIdentityAssertionV1,
    fresh: &FreshUvV1,
) -> bool {
    let value = &assertion.revocation_epochs;
    (
        fresh.subject_epoch,
        fresh.service_epoch,
        fresh.device_epoch,
        fresh.session_epoch,
    ) == (value.subject, value.service, value.device, value.session)
}

fn distinct(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}
