import pytest
from fido2.cose import ES256
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData

from ..utils import generate_random_bytes, MakeCredentialArguments


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 register is not available on NFC - 0x6D00")
def test_interop_u2f_reg_then_ctap2_auth(client):
    rp_id = "webctap.example.org"

    # Create credential through U2F/CTAP1
    challenge = generate_random_bytes(32)
    app_param = sha256(rp_id.encode("utf8"))

    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)

    # Authenticate with U2F/CTAP1 authentication
    challenge = generate_random_bytes(32)
    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    registration_data.key_handle)
    authentication_data.verify(app_param, challenge, registration_data.public_key)

    # Authenticate with CTAP2 authentication
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": registration_data.key_handle, "type": "public-key"}]
    assertion = client.ctap2.get_assertion(rp_id, client_data_hash,
                                           allow_list)

    credential_data = AttestedCredentialData.from_ctap1(
        registration_data.key_handle, registration_data.public_key
    )

    assertion.verify(client_data_hash, credential_data.public_key)
    assert assertion.credential["id"] == registration_data.key_handle


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 authenticate is not available on NFC - 0x6D00")
def test_interop_ctap2_reg_then_u2f_auth(client):

    rp_id = "webctap.example.org"

    # Create credential through CTAP2
    args = MakeCredentialArguments(generate_random_bytes(32),
                                   rp={"id": rp_id},
                                   user={"id": generate_random_bytes(64)},
                                   key_params=[{"type": "public-key", "alg": ES256.ALGORITHM}])

    attestation = client.ctap2.make_credential(args)
    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Authenticate with CTAP2 authentication
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    assertion = client.ctap2.get_assertion(rp_id, client_data_hash,
                                           allow_list)
    assertion.verify(client_data_hash, credential_data.public_key)

    # Authenticate with U2F/CTAP1 authentication
    challenge = generate_random_bytes(32)
    app_param = sha256(rp_id.encode("utf8"))
    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    credential_data.credential_id)
    pubkey_string = (b"\x04" + credential_data.public_key[-2] + credential_data.public_key[-3])
    authentication_data.verify(app_param, challenge, pubkey_string)
