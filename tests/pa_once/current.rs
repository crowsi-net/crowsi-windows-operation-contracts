use crowsi_credential_authority_contracts::target_device_proof_digest;
use crowsi_windows_operation_contracts::decode_operation_authorize_once_request;
use ihat_identity_assertion_contracts::{AuthorityEvidence, AuthorityResult, ResponseOutcome};

use crate::support;

#[test]
fn stale_selected_identity_cannot_be_reused_as_submission_current() {
    let mut value = support::request();
    value.current_identity_exchange = value.selected_identity_exchange.clone();
    let identity = identity(&mut value.current_identity_exchange);
    value.target_device_proof.status_nonce = identity.current_status.nonce.clone();
    rebind(&mut value);
    assert!(decode(&value).is_err());
}

#[test]
fn current_session_epoch_or_posture_substitution_is_rejected() {
    for case in 0..3 {
        let mut value = support::request();
        let identity = identity(&mut value.current_identity_exchange);
        match case {
            0 => {
                identity.assertion.session_ref = "session-other".into();
                identity.current_status.session_ref = "session-other".into();
            }
            1 => {
                identity.assertion.revocation_epochs.session += 1;
                identity.current_status.revocation_epochs.session += 1;
            }
            _ => {
                identity.assertion.device_posture.revision += 1;
                identity.current_status.device_posture.revision += 1;
            }
        }
        assert!(decode(&value).is_err());
    }
}

#[test]
fn session_sender_key_cannot_alias_device_proof_role() {
    let mut value = support::request();
    for exchange in [
        &mut value.selected_identity_exchange,
        &mut value.current_identity_exchange,
    ] {
        let [AuthorityEvidence::Signed(sender)] = exchange.request.evidence.as_mut_slice() else {
            unreachable!()
        };
        sender.key_id = "proof-key-b".into();
    }
    assert!(decode(&value).is_err());
}

#[test]
fn authority_config_generation_cannot_roll_back() {
    let mut value = support::request();
    value.current_identity_exchange.response.config_generation = 6;
    assert!(decode(&value).is_err());
}

fn identity(
    exchange: &mut crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> &mut ihat_identity_assertion_contracts::IdentityEvidenceMetadata {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut exchange.response.outcome
    else {
        unreachable!()
    };
    identity
}

fn rebind(value: &mut crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2) {
    let digest = target_device_proof_digest(&value.target_device_proof).expect("proof digest");
    value.sign_intent.digest_sha256 = format!("sha256:{}", hex::encode(digest));
}

fn decode(
    value: &crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2,
) -> crowsi_windows_operation_contracts::Result<
    crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2,
> {
    decode_operation_authorize_once_request(&serde_json::to_vec(value).expect("wire"))
}
