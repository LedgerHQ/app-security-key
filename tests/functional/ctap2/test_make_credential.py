import pytest
from fido2.cose import ES256, EdDSA, RS256, PS256
from fido2.ctap import CtapError
from fido2.webauthn import AuthenticatorData, AttestedCredentialData
from ledgered.devices import Device

from ..client import TESTS_SPECULOS_DIR, LedgerAttestationVerifier
from ..utils import FIDO_RP_ID_HASH_1, generate_random_bytes, \
    generate_make_credentials_params, ctap2_get_assertion, Nav


def test_make_credential(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name))
    args = generate_make_credentials_params(client, ref=0)

    attestation = client.ctap2.make_credential(args,
                                               check_screens=True,
                                               compare_args=compare_args)

    assert attestation.fmt == "packed"
    assert len(attestation.auth_data) >= 77

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags
    assert client.ctap2.info.aaguid == attestation.auth_data.credential_data.aaguid


def test_make_credential_followed_u2f(client, test_name, device: Device, u2f_over_fake_nfc):
    if device.is_nano:
        pytest.skip(f"No NFC available on {device.name.upper()}")
    if not u2f_over_fake_nfc:
        pytest.skip("--u2f-over-fake-nfc argument is required")

    # first make credential
    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name + "_1_make"))
    user1 = generate_make_credentials_params(client, ref=0)

    attestation = client.ctap2.make_credential(user1,
                                               check_screens=True,
                                               compare_args=compare_args)

    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    assert attestation.fmt == "packed"
    assert len(attestation.auth_data) >= 77

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags
    assert client.ctap2.info.aaguid == attestation.auth_data.credential_data.aaguid

    # first assert
    client_data_hash = generate_random_bytes(32)

    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name + "_1_assert"))

    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    assertion = client.ctap2.get_assertion(user1.rp["id"], client_data_hash, allow_list,
                                           check_users=[user1], check_screens=True,
                                           simple_login=False,
                                           compare_args=compare_args)
    assertion.verify(client_data_hash, credential_data.public_key)

    # U2F/CTAP1 registration
    challenge = generate_random_bytes(32)
    app_param = FIDO_RP_ID_HASH_1

    compare_args = (TESTS_SPECULOS_DIR, test_name + "_u2f")
    registration_data = client.ctap1.register(challenge, app_param,
                                              check_screens=True,
                                              compare_args=compare_args)
    registration_data.verify(app_param, challenge)


def test_make_credential_certificate(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name))
    args = generate_make_credentials_params(client, ref=0)

    attestation = client.ctap2.make_credential(args,
                                               check_screens=True,
                                               compare_args=compare_args)

    verifier = LedgerAttestationVerifier(client.ledger_device)
    verifier.verify_attestation(attestation, args.client_data_hash)


def test_make_credential_uv(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name))
    args = generate_make_credentials_params(client, ref=0, uv=True)

    attestation = client.ctap2.make_credential(args,
                                               check_screens=True,
                                               compare_args=compare_args)

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.USER_VERIFIED
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags

    args.options = {"uv": False}
    attestation = client.ctap2.make_credential(args)

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.ATTESTED
    assert attestation.auth_data.flags == expected_flags


def test_make_credential_up(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name))
    # Specs says:
    # "If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION."

    args = generate_make_credentials_params(client, ref=0, options={"up": False})

    with pytest.raises(CtapError) as e:
        print("YOLO1")
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.INVALID_OPTION

    args.options = {"up": True}

    print("YOLO2")
    client.ctap2.make_credential(args,
                                 check_screens=True,
                                 compare_args=compare_args)


def test_make_credential_rk(client):
    # Check that option RK can be passed with False value when not supporting RK.
    # This is used on Firefox on Linux and Mac and required by the spec.
    args = generate_make_credentials_params(client, ref=0, rk=False)
    client.ctap2.make_credential(args)


def test_make_credential_exclude_list_ok(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name))
    # First check with an absent credential in exclude list
    args1 = generate_make_credentials_params(client, ref=0,
                                             exclude_list=[{"id": generate_random_bytes(64),
                                                            "type": "public-key"}])
    attestation = client.ctap2.make_credential(args1,
                                               check_screens=True,
                                               compare_args=compare_args)

    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Then check with the credential we have just created in exclude list
    args2 = generate_make_credentials_params(client,
                                             exclude_list=[{"id": credential_data.credential_id,
                                                            "type": "public-key"}])
    args2.rp = args1.rp

    with pytest.raises(CtapError) as e:
        # DEVIATION from FIDO2.0 spec: "User presence check is required for
        # CTAP2 authenticators before the RP gets told that the token is already
        # registered to behave similarly to CTAP1/U2F authenticators."
        # Impact is minor because user as still manually unlocked it's device.
        # therefore user presence is somehow guarantee.
        attestation = client.ctap2.make_credential(args2, navigation=Nav.NONE)
    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED


@pytest.mark.skip_endpoint("NFC", reason="User can't refuse a MAKE_CREDENTIAL on NFC")
def test_make_credential_user_refused(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    args = generate_make_credentials_params(client, ref=0)

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args,
                                     navigation=Nav.USER_REFUSE,
                                     check_screens=True,
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
                ctap2_get_assertion(client, key_params=key_params, navigation=Nav.NONE)

            assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM
            continue

        t = ctap2_get_assertion(client, key_params=key_params)
        assert t.credential_data.public_key.ALGORITHM == expected_alg.ALGORITHM

        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
        assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list)

        assertion.verify(client_data_hash, t.credential_data.public_key)


def test_make_credential_rpid_filter(client):
    args = generate_make_credentials_params(client)

    # On u2f proxy, our app enforce rpid to start with "webctap."
    # Returned error code is ERROR_PROP_RPID_MEDIA_DENIED 0x8E
    args.rp["id"] = args.rp["id"].replace("webctap", "www")
    if client.ctap2_u2f_proxy:
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(args, navigation=Nav.NONE)

        assert e.value.code == CtapError(0x8E).code
    else:
        client.ctap2.make_credential(args)


@pytest.mark.skip_endpoint("NFC", reason="User can't cancel a MAKE_CREDENTIAL on NFC")
def test_make_credential_cancel(client):
    if client.ctap2_u2f_proxy:
        pytest.skip("Does not work with this transport")

    args = generate_make_credentials_params(client)
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.CLIENT_CANCEL)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL


def test_make_credential_bad_exclude_list(client):
    args = generate_make_credentials_params(client)

    # With an element that is not of type MAP
    args.exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    args.exclude_list.append(["toto"])
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "type"
    args.exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    args.exclude_list.append({"id": generate_random_bytes(12)})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "type"
    args.exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    args.exclude_list.append({"id": generate_random_bytes(12), "type": b"012451"})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "id"
    args.exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    args.exclude_list.append({"type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "id"
    args.exclude_list = [{"id": generate_random_bytes(64), "type": "public-key"}]
    args.exclude_list.append({"id": "bad", "type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE)
    assert e.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


# Todo add tests with
# - Validation of request:
#   - CBOR fields errors: missing / bad type / bad length...
# - Check that ux_require_pin() is being called when requested
