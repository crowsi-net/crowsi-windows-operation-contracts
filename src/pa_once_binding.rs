use crate::{
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA,
    OPERATION_SERVICE_ID, OperationAuthorizeOnceRequestV2,
};
use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementIntentV2, decode_management_request_strict,
    endpoint_operation_digest, endpoint_operation_id,
};

pub(crate) fn valid(value: &OperationAuthorizeOnceRequestV2) -> bool {
    value.schema == OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA
        && crate::pa_once_approval::valid(value)
        && identity(value)
        && prepared(value)
        && management(value)
        && crate::pa_once_target::target(value)
        && crate::pa_once_target::sign(value)
}

fn identity(value: &OperationAuthorizeOnceRequestV2) -> bool {
    let Some(proof) = crate::pa_once_approval::evidence(value) else {
        return false;
    };
    let assertion = &proof.current.assertion;
    assertion.service_id == OPERATION_SERVICE_ID
        && assertion.audience == OPERATION_AUTHORIZATION_AUDIENCE
        && assertion.device_posture.state == "compliant"
}

fn prepared(value: &OperationAuthorizeOnceRequestV2) -> bool {
    let Some(proof) = crate::pa_once_approval::evidence(value) else {
        return false;
    };
    let prepared = &value.prepared;
    let Some(lifetime) = prepared
        .expires_at_epoch_s
        .checked_sub(prepared.issued_at_epoch_s)
    else {
        return false;
    };
    matches!(&prepared.intent, ManagementIntentV2::DeviceTransfer {
        service_id, target_device_ref, ..
    } if service_id == OPERATION_SERVICE_ID
        && target_device_ref == &proof.current.assertion.device_id)
        && prepared.pairwise_subject == proof.current.assertion.pairwise_subject
        && prepared.revocation.is_none()
        && (1..=300).contains(&lifetime)
        && endpoint_operation_id(prepared).is_ok_and(|id| id == prepared.operation_id)
}

fn management(value: &OperationAuthorizeOnceRequestV2) -> bool {
    let Some(proof) = crate::pa_once_approval::evidence(value) else {
        return false;
    };
    let Ok(wire) = serde_json::to_vec(&value.management_request) else {
        return false;
    };
    if decode_management_request_strict(&wire).is_err() {
        return false;
    }
    matches!(&value.management_request.command, ManagementCommandV2::TargetApprove {
        operation_id, attempt_id, assertion, ..
    } if operation_id == &value.prepared.operation_id
        && attempt_id == &proof.fresh.attempt_id
        && assertion.credential_id == proof.fresh.credential_id)
}

pub(crate) fn operation_digest(value: &OperationAuthorizeOnceRequestV2) -> String {
    endpoint_operation_digest(&value.prepared).unwrap_or_default()
}
