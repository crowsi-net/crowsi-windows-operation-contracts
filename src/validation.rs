use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    OperationOnlyAction, OperationOnlyCredentialClass, OperationOnlyRequest,
    PaOperationAuthorization, ReasonCode, Result,
};

/// Strictly decodes one bounded operation-only request.
///
/// # Errors
/// Rejects malformed, trailing, oversized, unknown, or semantically invalid input.
pub fn decode_operation_request(body: &[u8]) -> Result<OperationOnlyRequest> {
    if body.is_empty() || body.len() > crate::frame::MAX {
        return Err(ReasonCode::ContractRejected.into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value =
        serde::Deserialize::deserialize(&mut decoder).map_err(|_| ReasonCode::ContractRejected)?;
    decoder.end().map_err(|_| ReasonCode::ContractRejected)?;
    crate::validation_shape::valid(&value)
        .then_some(value)
        .ok_or_else(|| ReasonCode::ContractRejected.into())
}

/// Computes the domain-separated digest of the operation intent.
///
/// # Errors
/// Returns an error if the closed intent cannot be encoded.
pub fn operation_request_digest(value: &OperationOnlyRequest) -> Result<String> {
    #[derive(Serialize)]
    struct Intent<'a> {
        schema: &'a str,
        request_id: &'a str,
        credential_id: &'a str,
        expected_revision: &'a str,
        credential_class: OperationOnlyCredentialClass,
        action: &'a OperationOnlyAction,
    }
    let body = serde_json::to_vec(&Intent {
        schema: &value.schema,
        request_id: &value.request_id,
        credential_id: &value.credential_id,
        expected_revision: &value.expected_revision,
        credential_class: value.credential_class,
        action: &value.action,
    })
    .map_err(|_| ReasonCode::ContractRejected)?;
    let mut digest = Sha256::new();
    digest.update(b"crowsi-windows-operation-request-v3\0");
    digest.update(body);
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

/// Encodes the exact policy-authorization signing payload.
///
/// # Errors
/// Returns an error if the closed authorization cannot be encoded.
pub fn authorization_signing_bytes(value: &PaOperationAuthorization) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Signed<'a> {
        schema: &'a str,
        issuer: &'a str,
        key_id: &'a str,
        binding: &'a crate::OperationBinding,
        issued_at_epoch_s: u64,
        expires_at_epoch_s: u64,
    }
    serde_json::to_vec(&Signed {
        schema: &value.schema,
        issuer: &value.issuer,
        key_id: &value.key_id,
        binding: &value.binding,
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
    })
    .map_err(|_| ReasonCode::ContractRejected.into())
}

pub(crate) use crate::validation_shape::valid_result;
