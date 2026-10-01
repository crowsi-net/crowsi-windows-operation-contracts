//! Closed operation-only custody documents and their bounded helper client.

#![forbid(unsafe_code)]

mod client;
mod client_process;
mod contract;
mod error;
mod frame;
mod pa_once_approval;
mod pa_once_binding;
mod pa_once_decode;
mod pa_once_model;
mod pa_once_target;
mod validation;
mod validation_shape;

pub use client::{CustodyClient, HelperIdentity};
pub use contract::{
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_AUTHORIZATION_ISSUER,
    OPERATION_AUTHORIZATION_SCHEMA, OPERATION_REQUEST_SCHEMA, OPERATION_RESPONSE_SCHEMA,
    OPERATION_SERVICE_ID, OPERATION_WORKLOAD_ID, OperationBinding, OperationOnlyAction,
    OperationOnlyCredentialClass, OperationOnlyRequest, OperationOnlyResponse, OperationOnlyResult,
    PaOperationAuthorization, SigningAlgorithm,
};
pub use error::{OperationContractError, ReasonCode, Result};
pub use pa_once_decode::decode_operation_authorize_once_request;
pub use pa_once_model::{
    MAX_OPERATION_AUTHORIZE_ONCE_BYTES, OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA,
    OperationAuthorizeOnceRequestV2, OperationOnlySignIntentV1,
};
pub use validation::{
    authorization_signing_bytes, decode_operation_request, operation_request_digest,
};
