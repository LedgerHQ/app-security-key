import pytest

from fido2.cose import ES256, EdDSA, RS256, PS256
from fido2.ctap import CtapError
from fido2.webauthn import AuthenticatorData, AttestedCredentialData

from client import TESTS_SPECULOS_DIR, LedgerAttestationVerifier
from utils import generate_random_bytes, generate_make_credentials_params
from utils import generate_get_assertion_params


def test_make_credential(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)

    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               check_screens="full",
                                               compare_args=compare_args)

    assert attestation.fmt == "packed"
    assert len(attestation.auth_data) >= 77

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags
    assert client.ctap2.info.aaguid == attestation.auth_data.credential_data.aaguid


def test_make_credential_certificate(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)

    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               check_screens="full",
                                               compare_args=compare_args)

    verifier = LedgerAttestationVerifier(client.model)
    verifier.verify_attestation(attestation, client_data_hash)


def test_make_credential_uv(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)

    options = {"uv": True}
    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               options=options,
                                               check_screens="full",
                                               compare_args=compare_args)

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.USER_VERIFIED
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags

    options = {"uv": False}
    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               options=options)

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags


def test_make_credential_up(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    # Specs says:
    # "If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION."

    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)
    options = {"up": False}

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     options=options,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_OPTION

    options = {"up": True}

    client.ctap2.make_credential(client_data_hash,
                                 rp,
                                 user,
                                 key_params,
                                 options=options,
                                 user_accept=True,
                                 check_screens="full",
                                 compare_args=compare_args)


def test_make_credential_rk(client, test_name):
    # Check that option RK can be passed with False value when not supporting RK.
    # This is used on Firefox on Linux and Mac and required by the spec.
    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)
    options = {"rk": False}
    client.ctap2.make_credential(client_data_hash,
                                 rp,
                                 user,
                                 key_params,
                                 options=options,
                                 user_accept=True)


def test_make_credential_exclude_list(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    # First check with an absent credential in exclude list
    client_data_hash, rp, user1, key_params = generate_make_credentials_params(ref=0)
    exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user1,
                                               key_params,
                                               exclude_list=exclude_list,
                                               check_screens="full",
                                               compare_args=compare_args)

    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Then check with the credential we have just created in exclude list
    client_data_hash, _rp, user2, key_params = generate_make_credentials_params()
    exclude_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        # DEVIATION from FIDO2.0 spec: "User presence check is required for
        # CTAP2 authenticators before the RP gets told that the token is already
        # registered to behave similarly to CTAP1/U2F authenticators."
        # Impact is minor because user as still manually unlocked it's device.
        # therefore user presence is somehow guarantee.
        attestation = client.ctap2.make_credential(client_data_hash,
                                                   rp,
                                                   user2,
                                                   key_params,
                                                   exclude_list=exclude_list,
                                                   user_accept=None)
    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED


def test_make_credential_user_refused(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     user_accept=False,
                                     check_screens="full",
                                     compare_args=compare_args)

    assert e.value.code == CtapError.ERR.OPERATION_DENIED


def test_make_credential_algos(client):
    # TODO add ES256K algorithm support in python code
    tests = [
        # Tests with only one supported
        ([ES256], ES256),
        ([EdDSA], EdDSA),

        # Tests with only unsupported
        ([RS256], None),
        ([PS256], None),
        ([PS256, RS256], None),

        # Tests with multiple => first supported
        ([ES256, EdDSA], ES256),
        ([EdDSA, ES256], EdDSA),
        ([PS256, ES256], ES256),
        ([PS256, EdDSA], EdDSA),
        ([ES256, PS256], ES256),
        ([EdDSA, PS256], EdDSA),
    ]

    for proposed_algs, expected_alg in tests:
        key_params = []
        for alg in proposed_algs:
            key_params.append({"type": "public-key", "alg": alg.ALGORITHM})

        if not expected_alg:
            with pytest.raises(CtapError) as e:
                generate_get_assertion_params(client, key_params=key_params,
                                              user_accept=None)

            assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM
            continue

        rp, credential_data, _ = generate_get_assertion_params(client, key_params=key_params)
        assert credential_data.public_key.ALGORITHM == expected_alg.ALGORITHM

        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                               allow_list)

        assertion.verify(client_data_hash, credential_data.public_key)


def test_make_credential_rpid_filter(client):
    client_data_hash, rp, user, key_params = generate_make_credentials_params()

    # On u2f proxy, our app enforce rpid to start with "webctap."
    # Returned error code is ERROR_PROP_RPID_MEDIA_DENIED 0x8E
    rp["id"] = rp["id"].replace("webctap", "www")
    if client.ctap2_u2f_proxy:
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         user_accept=None)

        assert e.value.code == CtapError(0x8E).code
    else:
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params)


def test_make_credential_cancel(client, test_name):
    if client.ctap2_u2f_proxy:
        pytest.skip("Does not work with this transport")

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    client_data_hash, rp, user, key_params = generate_make_credentials_params()
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     user_accept=None,
                                     check_screens="full",
                                     check_cancel=True,
                                     compare_args=compare_args)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL


def test_make_credential_bad_exclude_list(client):
    client_data_hash, rp, user, key_params = generate_make_credentials_params()

    # With an element that is not of type MAP
    exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    exclude_list.append(["toto"])
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash, rp, user, key_params,
                                     exclude_list=exclude_list,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "type"
    exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    exclude_list.append({"id": generate_random_bytes(12)})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash, rp, user, key_params,
                                     exclude_list=exclude_list,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "type"
    exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    exclude_list.append({"id": generate_random_bytes(12), "type": b"012451"})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash, rp, user, key_params,
                                     exclude_list=exclude_list,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "id"
    exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    exclude_list.append({"type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash, rp, user, key_params,
                                     exclude_list=exclude_list,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "id"
    exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    exclude_list.append({"id": "bad", "type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash, rp, user, key_params,
                                     exclude_list=exclude_list,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


# Todo add tests with
# - Validation of request:
#   - CBOR fields errors: missing / bad type / bad length...
# - Check that ux_require_pin() is being called when requested
