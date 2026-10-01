use crowsi_credential_authority_contracts::target_device_proof_digest;

use crate::{OperationAuthorizeOnceRequestV2, OperationOnlyCredentialClass, SigningAlgorithm};

pub(crate) fn target(value: &OperationAuthorizeOnceRequestV2) -> bool {
    let Some(evidence) = crate::pa_once_approval::evidence(value) else {
        return false;
    };
    let proof = &value.target_device_proof;
    let identity = evidence.current;
    let lifetime = proof
        .expires_at_epoch_s
        .checked_sub(proof.issued_at_epoch_s);
    proof.schema == "crowsi://identity/target-device-key-proof/v2"
        && proof.owner_ref == value.prepared.opaque_owner_ref
        && proof.service_id == identity.assertion.service_id
        && proof.pairwise_subject == identity.assertion.pairwise_subject
        && proof.operation_id == value.prepared.operation_id
        && proof.challenge_digest_sha256 == crate::pa_once_binding::operation_digest(value)
        && proof.source_device_ref == value.prepared.source_device_ref
        && proof.target_device_ref == identity.assertion.device_id
        && proof.device_proof_key_ref == identity.assertion.device_proof_key_ref
        && proof.status_nonce == identity.current_status.nonce
        && proof.nonce == value.prepared.nonce
        && proof.key_id == proof.device_proof_key_ref
        && lifetime.is_some_and(|seconds| (1..=60).contains(&seconds))
        && evidence.fresh.issued_at_epoch_s <= identity.assertion.issued_at_epoch_s
        && evidence.fresh.issued_at_epoch_s <= identity.current_status.issued_at_epoch_s
        && identity.assertion.issued_at_epoch_s <= proof.issued_at_epoch_s
        && identity.current_status.issued_at_epoch_s <= proof.issued_at_epoch_s
        && proof.expires_at_epoch_s <= evidence.fresh.expires_at_epoch_s
        && proof.expires_at_epoch_s <= identity.assertion.expires_at_epoch_s
        && proof.expires_at_epoch_s <= identity.current_status.expires_at_epoch_s
        && proof.expires_at_epoch_s <= value.prepared.expires_at_epoch_s
}

pub(crate) fn sign(value: &OperationAuthorizeOnceRequestV2) -> bool {
    let intent = &value.sign_intent;
    let digest = target_device_proof_digest(&value.target_device_proof)
        .map(|bytes| format!("sha256:{}", hex::encode(bytes)));
    id(&intent.request_id, 128)
        && id(&intent.credential_id, 128)
        && revision(&intent.expected_revision)
        && intent.expected_revision == value.target_device_proof.custody_revision
        && intent.credential_class == OperationOnlyCredentialClass::Ed25519SigningKey
        && intent.algorithm == SigningAlgorithm::Ed25519
        && digest.is_ok_and(|expected| expected == intent.digest_sha256)
}

fn revision(value: &str) -> bool {
    value.len() == 69 && value.starts_with("rev1:") && lower_hex(&value[5..])
}
fn id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
