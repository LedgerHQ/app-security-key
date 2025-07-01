import pytest
from base64 import b64encode
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import CollectedClientData, AttestationObject
from okta.client import Client as OktaClient
from okta.models import ActivateFactorRequest
from okta.models import WebAuthnUserFactor, WebAuthnUserFactorProfile
from okta.models.factor_status import FactorStatus
from urllib.parse import urlparse

from .utils import MakeCredentialArguments


async def okta_await(function, *args, **kwargs):
    result = await function(*args, **kwargs)
    if len(result) == 3:
        payload, response, err = result
    else:
        payload = None
        response, err = result
    status = response.get_status()
    assert status < 400, f"{status}: {err.message}"
    return payload


async def clean_factors(okta_client: OktaClient, user_id: int) -> None:
    factors = await okta_await(okta_client.list_factors, user_id)

    webauthn_factors = filter(lambda x: x.factor_type == "webauthn", factors)
    pendings = filter(lambda x: x.status == FactorStatus.PENDING_ACTIVATION, webauthn_factors)

    for factor in pendings:
        await okta_client.delete_factor(user_id, factor.id)


async def create_factor(client, okta_client, okta_url, user_id: int) -> WebAuthnUserFactor:
    """
    Adds an authentication factor on the Okta account.
    With WebAuthn, the steps are:
    - Enroll the factor on the Okta account - basically creating a placeholder for the factor
      with only metadata (type, name, ...)
      This step will provide a challenge used to activate the factor.
    - Use this challenge and other data to MAKE_CREDENTIAL on the authenticator
    - Activate the factor by returning the authenticator response to the Okta API

    If none of these steps raises, then the factor is fully created and ready.
    """

    # Enroll a WebAuthn factor for this user #
    webauthn_factor = WebAuthnUserFactor(
        {
            "profile": WebAuthnUserFactorProfile(
                {"authenticatorName": "Ledger Flex", "credentialId": "New user"}
            ),
            "provider": "FIDO",
        }
    )
    factor = await okta_await(okta_client.enroll_factor, user_id, webauthn_factor)

    # Activate the WebAuthn factor. This needs a MAKE_CREDENTIAL call to SK #
    ctap2_make_creds = factor.embedded["activation"]
    ctap2_make_creds["user"]["id"] = ctap2_make_creds["user"]["id"].encode()
    ccd = CollectedClientData.create(
        type=CollectedClientData.TYPE.CREATE,
        challenge=ctap2_make_creds["challenge"],
        origin=okta_url,
    )
    args = MakeCredentialArguments(
        client_data_hash=ccd.hash,
        rp={"id": ctap2_make_creds["rp"]["name"] + ".oktapreview.com"},
        user=ctap2_make_creds["user"],
        key_params=ctap2_make_creds["pubKeyCredParams"],
        exclude_list=ctap2_make_creds["excludeCredentials"],
        extensions=None,
        options={
            "rk": ctap2_make_creds["authenticatorSelection"]["requireResidentKey"],
            "uv": ctap2_make_creds["authenticatorSelection"]["userVerification"] == "encouraged",
        },
        pin_uv_param=None,
        pin_uv_protocol=None,
        entreprise_attestation=None,
    )
    attestation = client.ctap2.make_credential(args)

    attestation_object = AttestationObject.create(
        fmt=attestation.fmt,
        att_stmt=attestation.att_stmt,
        auth_data=attestation.auth_data,
    )

    await okta_await(
        okta_client.activate_factor,
        user_id,
        factor.id,
        ActivateFactorRequest(
            {
                "attestation": websafe_encode(attestation_object),
                "clientData": ccd.b64,
            }
        ),
    )
    return factor


async def verify_factor(client, okta_client, okta_url, user_id: int, factor_id: int) -> None:
    """
    'Verifies' an authentication factor. With a WebAuthn factor that means:

    - first getting a challenge (empty `verify_factor` request)
    - then signing the challenge (GET_ASSERTION request to the authenticator)
    - finally responding to the RP (non-empty `verify_factor` request)

    If none of these steps raises, then the authenticator is verified.
    """

    # first request empty, to fetch the challenge
    challenge = await okta_await(okta_client.verify_factor, user_id, factor_id, dict())

    ctap2_get_assertion = challenge.embedded["challenge"]

    ccd = CollectedClientData.create(
        type=CollectedClientData.TYPE.GET,
        challenge=ctap2_get_assertion["challenge"],
        origin=okta_url,
    )

    allow_list = list()
    for factor_dict in challenge.embedded["enrolledFactors"]:
        if factor_dict["factorType"] != "webauthn":
            continue

        credential_id = websafe_decode(factor_dict["profile"]["credentialId"])
        allow_list.append({"id": credential_id, "type": "public-key"})

    options = {"uv": ctap2_get_assertion["userVerification"] in ["preferred", "required"]}

    attestation = client.ctap2.get_assertion(
        rp_id=urlparse(okta_url).hostname,
        client_data_hash=ccd.hash,
        allow_list=allow_list,
        options=options,
    )

    # We should be using `VerifyFactorRequest` here, but the Okta client does not manage neither
    # `authenticatorData` nor `signatureData` fields, which are required by the API. So let's use a
    # raw dict directly I guess.

    # for *some reason* the two last fields needs to be 'properly' `b64encode`d and not
    # `websafe_encode`d, or the API returns a `400 bad request` error.
    payload = {
        "clientData": ccd.b64,
        "authenticatorData": b64encode(attestation.auth_data).decode("ascii"),
        "signatureData": b64encode(attestation.signature).decode("ascii"),
    }

    await okta_await(okta_client.verify_factor, user_id, factor_id, payload)


@pytest.mark.asyncio
@pytest.mark.okta
async def test_okta(client, okta_client: OktaClient, okta_email: str, okta_url: str) -> None:

    # getting current user (for its ID)
    user = await okta_await(okta_client.get_user, okta_email)

    # cleaning unactivated factors
    await clean_factors(okta_client, user.id)

    # creating the factor
    factor = await create_factor(client, okta_client, okta_url, user.id)
    try:
        # checking the factor allows an authentication
        await verify_factor(client, okta_client, okta_url, user.id, factor.id)
    finally:
        # delete the factor (even if the authentication fails)
        await okta_await(okta_client.delete_factor, user.id, factor.id)

    # cleaning unactivated factors
    await clean_factors(okta_client, user.id)
