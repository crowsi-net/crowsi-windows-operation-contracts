use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementRequestV2, SignedAuthorityExchangeV1,
    TargetDeviceProofBindingV2,
};
use serde::{Deserialize, Serialize};

use crate::{OperationOnlyCredentialClass, SigningAlgorithm};

pub const OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA: &str =
    "crowsi://policy-authority/operation-authorize-once-request/v2";
pub const MAX_OPERATION_AUTHORIZE_ONCE_BYTES: usize = 65_536;

/// The only custody intent accepted by the endpoint PA authorization port.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOnlySignIntentV1 {
    pub request_id: String,
    pub credential_id: String,
    pub expected_revision: String,
    pub credential_class: OperationOnlyCredentialClass,
    pub algorithm: SigningAlgorithm,
    pub digest_sha256: String,
}

/// Complete endpoint evidence needed to authorize one target-proof signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorizeOnceRequestV2 {
    pub schema: String,
    pub selected_identity_exchange: SignedAuthorityExchangeV1,
    pub selected_begin_exchange: SignedAuthorityExchangeV1,
    pub finish_exchange: SignedAuthorityExchangeV1,
    pub current_identity_exchange: SignedAuthorityExchangeV1,
    pub prepared: EndpointPreparedOperationV2,
    pub management_request: ManagementRequestV2,
    pub target_device_proof: TargetDeviceProofBindingV2,
    pub sign_intent: OperationOnlySignIntentV1,
}
