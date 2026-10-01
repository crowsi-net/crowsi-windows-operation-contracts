use crate::{
    MAX_OPERATION_AUTHORIZE_ONCE_BYTES, OperationAuthorizeOnceRequestV2, OperationContractError,
    ReasonCode,
};

/// Strictly decodes the one closed PA target-proof authorization request.
///
/// # Errors
/// Rejects malformed, trailing, oversized, unknown, non-target, or substituted input.
pub fn decode_operation_authorize_once_request(
    body: &[u8],
) -> Result<OperationAuthorizeOnceRequestV2, OperationContractError> {
    if body.is_empty() || body.len() > MAX_OPERATION_AUTHORIZE_ONCE_BYTES {
        return rejected();
    }
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = serde::Deserialize::deserialize(&mut decoder)
        .map_err(|_| OperationContractError(ReasonCode::ContractRejected))?;
    decoder
        .end()
        .map_err(|_| OperationContractError(ReasonCode::ContractRejected))?;
    crate::pa_once_binding::valid(&value)
        .then_some(value)
        .ok_or(OperationContractError(ReasonCode::ContractRejected))
}
fn rejected<T>() -> Result<T, OperationContractError> {
    Err(OperationContractError(ReasonCode::ContractRejected))
}
