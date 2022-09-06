import pytest

from fido2.ctap import CtapError
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.webauthn import AttestedCredentialData

from utils import generate_random_bytes, generate_make_credentials_params


def test_extensions_hmac_secret(client):
    for protocol in [PinProtocolV1(), PinProtocolV2()]:
        info = client.ctap2.info
        assert "hmac-secret" in info.extensions

        hmac_ext = HmacSecretExtension(client.ctap2, protocol)

        # Create a credential
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        extensions = {"hmac-secret": True}

        attestation = client.ctap2.make_credential(client_data_hash,
                                                   rp,
                                                   user,
                                                   key_params,
                                                   extensions=extensions)
        assert attestation.auth_data.extensions["hmac-secret"]

        # Retrieve a first assertion with one salt
        credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

        salt1 = generate_random_bytes(32)
        hmac_ext_data = hmac_ext.process_get_input({
            "hmacGetSecret": {"salt1": salt1}})
        extensions = {"hmac-secret": hmac_ext_data}

        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                               allow_list,
                                               extensions=extensions)

        hmac_secret1 = hmac_ext.process_get_output(assertion)["hmacGetSecret"]

        # Retrieve another assertion with two salts
        salt2 = generate_random_bytes(32)
        hmac_ext_data = hmac_ext.process_get_input({
            "hmacGetSecret": {"salt1": salt1, "salt2": salt2}})
        extensions = {"hmac-secret": hmac_ext_data}

        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                               allow_list,
                                               extensions=extensions)

        hmac_secret12 = hmac_ext.process_get_output(assertion)["hmacGetSecret"]

        # Compare the outputs
        assert hmac_secret1["output1"] == hmac_secret12["output1"]
        assert hmac_secret1["output1"] != hmac_secret12["output2"]


def test_extensions_hmac_secret_error(client):
    hmac_ext = HmacSecretExtension(client.ctap2)

    # Create a credential
    client_data_hash, rp, user, key_params = generate_make_credentials_params()
    extensions = {"hmac-secret": True}

    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               extensions=extensions)
    assert attestation.auth_data.extensions["hmac-secret"]

    # Check with missing keyAgreement in "hmac-secret"
    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    salt1 = generate_random_bytes(32)
    hmac_ext_data = hmac_ext.process_get_input({
        "hmacGetSecret": {"salt1": salt1}})
    hmac_ext_data.pop(1)
    extensions = {"hmac-secret": hmac_ext_data}

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash,
                                   allow_list,
                                   extensions=extensions)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

# Todo add tests with
# - Validation of request:
#   - CBOR fields errors: missing / bad type / bad length...
