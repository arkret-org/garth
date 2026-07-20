use ed25519_dalek::SigningKey;

pub fn dpop_proof_callback(
    signing_key: SigningKey,
) -> impl Fn(arkret_http_client::DpopProofRequest) -> arkret_http_client::Result<String>
+ Send
+ Sync
+ 'static {
    move |request| build_http_dpop_proof(request, &signing_key)
}

pub fn proof_only_auth(signing_key: SigningKey) -> arkret_http_client::DpopAuth {
    arkret_http_client::DpopAuth::proof_only(dpop_proof_callback(signing_key))
}

pub fn access_token_auth(
    access_token: impl Into<String>,
    signing_key: SigningKey,
) -> arkret_http_client::DpopAuth {
    arkret_http_client::DpopAuth::with_access_token(
        access_token.into(),
        dpop_proof_callback(signing_key),
    )
}

pub fn account_handoff_auth(
    account_handoff_grant: impl Into<String>,
    signing_key: SigningKey,
) -> arkret_http_client::DpopAuth {
    arkret_http_client::DpopAuth::with_dpop_token(
        account_handoff_grant.into(),
        dpop_proof_callback(signing_key),
    )
}

pub fn build_http_dpop_proof(
    request: arkret_http_client::DpopProofRequest,
    signing_key: &SigningKey,
) -> arkret_http_client::Result<String> {
    let proof = arkret::dpop::build_dpop_proof(&request, signing_key)
        .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))?;
    Ok(proof.header_value)
}
