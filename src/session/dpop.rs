use ed25519_dalek::SigningKey;

pub fn dpop_proof_callback(
    signing_key: SigningKey,
) -> impl Fn(cokret_http_client::DpopProofRequest) -> cokret_core::Result<String> + Send + Sync + 'static
{
    move |request| build_http_dpop_proof(request, &signing_key)
}

pub fn proof_only_auth(signing_key: SigningKey) -> cokret_http_client::DpopAuth {
    cokret_http_client::DpopAuth::proof_only(dpop_proof_callback(signing_key))
}

pub fn access_token_auth(
    access_token: impl Into<String>,
    signing_key: SigningKey,
) -> cokret_http_client::DpopAuth {
    cokret_http_client::DpopAuth::with_access_token(
        access_token.into(),
        dpop_proof_callback(signing_key),
    )
}

pub fn build_http_dpop_proof(
    request: cokret_http_client::DpopProofRequest,
    signing_key: &SigningKey,
) -> cokret_core::Result<String> {
    let mut sdk_request = cokret::dpop::DpopProofRequest::new(request.method, request.htu);
    if let Some(access_token) = request.access_token {
        sdk_request = sdk_request.access_token(access_token);
    }
    let proof = cokret::dpop::build_dpop_proof(&sdk_request, signing_key)?;
    Ok(proof.header_value)
}
