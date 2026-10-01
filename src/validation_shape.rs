use crate::{
    OPERATION_AUTHORIZATION_SCHEMA, OPERATION_REQUEST_SCHEMA, OperationOnlyAction,
    OperationOnlyRequest,
};

pub(crate) fn valid(value: &OperationOnlyRequest) -> bool {
    let authorization = &value.pa_authorization;
    let binding = &authorization.binding;
    value.schema == OPERATION_REQUEST_SCHEMA
        && id(&value.request_id, 128)
        && id(&value.credential_id, 128)
        && revision(&value.expected_revision)
        && action(&value.action)
        && authorization.schema == OPERATION_AUTHORIZATION_SCHEMA
        && id(&authorization.issuer, 128)
        && id(&authorization.key_id, 128)
        && hex(&authorization.signature_hex, 128, 128)
        && id(&binding.service_id, 128)
        && id(&binding.pairwise_subject, 128)
        && id(&binding.device_id, 128)
        && id(&binding.device_proof_key_ref, 240)
        && id(&binding.session_ref, 128)
        && id(&binding.device_posture, 32)
        && binding.device_posture_revision > 0
        && binding.subject_revocation_epoch > 0
        && binding.service_revocation_epoch > 0
        && binding.device_revocation_epoch > 0
        && binding.session_revocation_epoch > 0
        && id(&binding.workload_id, 128)
        && id(&binding.audience, 128)
        && id(&binding.action, 192)
        && digest(&binding.request_digest_sha256)
        && id(&binding.nonce, 128)
}

pub(crate) fn valid_result(
    action: &OperationOnlyAction,
    result: &crate::OperationOnlyResult,
) -> bool {
    match (action, result) {
        (
            OperationOnlyAction::Sign { algorithm, .. },
            crate::OperationOnlyResult::Signature {
                algorithm: actual,
                value_hex,
            },
        ) => algorithm == actual && hex(value_hex, 64, 16_384),
        (
            OperationOnlyAction::ProviderOperation {
                provider,
                operation,
                ..
            },
            crate::OperationOnlyResult::ProviderResult {
                provider: actual_provider,
                operation: actual_operation,
                value_hex,
            },
        ) => {
            provider == actual_provider
                && operation == actual_operation
                && hex(value_hex, 2, 16_384)
        }
        _ => false,
    }
}

fn action(value: &OperationOnlyAction) -> bool {
    match value {
        OperationOnlyAction::Sign { digest_sha256, .. } => digest(digest_sha256),
        OperationOnlyAction::ProviderOperation {
            provider,
            operation,
            input_digest_sha256,
        } => id(provider, 64) && id(operation, 64) && digest(input_digest_sha256),
    }
}
fn revision(value: &str) -> bool {
    value.len() == 69 && value.starts_with("rev1:") && hex(&value[5..], 64, 64)
}
fn digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && hex(&value[7..], 64, 64)
}
fn id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn hex(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
