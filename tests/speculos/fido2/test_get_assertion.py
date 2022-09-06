import pytest

from cryptography.exceptions import InvalidSignature
from fido2.ctap import CtapError
from fido2.utils import sha256
from fido2.webauthn import AuthenticatorData, AttestedCredentialData

from client import TESTS_SPECULOS_DIR
from utils import generate_random_bytes, generate_get_assertion_params
from utils import generate_make_credentials_params, fido_known_app


def test_get_assertion(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    # This test use the fact that after a reboot of the device
    # the ctap2WrappingKey should stay the same.
    # Hence a non rk credential created before the reboot will remains
    # valid after the reboot.
    # However, has reboot don't persist the NVM in this workflow, we need
    # an extra step here.
    # Indeed, the ctap2WrappingKey will be automatically regenerate at boot
    # but it will be the same as before the reboot only if the
    # resetGeneration counter holds the same value.
    # At reboot, this counter will holds 0, but at the start of this test
    # it depends of the number of calls to client.ctap2.reset() in previous
    # test since the last call to client.simulate_reboot().
    # Therefore we call client.simulate_reboot() here to make sure that
    # resetGeneration won't change!
    client.simulate_reboot()

    rp, credential_data, user = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                           allow_list,
                                           check_users=[user],
                                           check_screens="full",
                                           compare_args=compare_args)

    assertion.verify(client_data_hash, credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None

    client.simulate_reboot()

    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                           allow_list)

    assertion.verify(client_data_hash, credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_uv(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    rp, credential_data, user = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    options = {"uv": True}
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                           allow_list, options=options,
                                           check_users=[user],
                                           check_screens="full",
                                           compare_args=compare_args)

    assertion.verify(client_data_hash, credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(rp["id"].encode()) == assertion.auth_data.rp_id_hash

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.USER_VERIFIED
    assert assertion.auth_data.flags == expected_flags
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_no_up(client):
    rp, credential_data, _user = generate_get_assertion_params(client)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    options = {"up": False}
    # DEVIATION from spec: Always require user consent
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                           allow_list, options=options,
                                           user_accept=True)

    assertion.verify(client_data_hash, credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_user_refused(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    rp, credential_data, user = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash,
                                   allow_list, user_accept=False,
                                   check_users=[user],
                                   check_screens="full",
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED


def test_get_assertion_no_credentials(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    client_data_hash, rp, _user, _key_params = generate_make_credentials_params(ref=0)

    # Try without allow_list
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash,
                                   login_type="none",
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    # Try with unknown credential in allow_list
    client_data_hash, _rp, _user, _key_params = generate_make_credentials_params()
    allow_list = [{"id": generate_random_bytes(32), "type": "public-key"}]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                   login_type="none",
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_wrong_id(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    rp, credential_data, _user = generate_get_assertion_params(client, ref=0)
    client_data_hash = generate_random_bytes(32)

    # Test changing the version field, the tag, or the ciphered data
    for pos in [0, 10, 20]:
        # Change id first bit
        wrong_id = bytearray(credential_data.credential_id)
        wrong_id[pos] ^= 0x80
        wrong_id = bytes(wrong_id)

        allow_list = [{"id": wrong_id, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash,
                                   allow_list,
                                   login_type="none",
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_wrong_rp(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    rp, credential_data, _user = generate_get_assertion_params(client, ref=0)
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    # Change rp_id at the end to still pass rpid_filter
    wrong_rp_id = rp["id"] + ".fake"

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(wrong_rp_id, client_data_hash,
                                   allow_list,
                                   login_type="none",
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_allow_list(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)

    # On u2f proxy, our app enforce rpid to start with "webctap."
    # Comply with it for this test.
    # Therefore RP id won't be recognized from the embedded, but that part
    # is tested elsewhere
    rp = {
        "id": "webctap." + list(fido_known_app.keys())[0],
    }

    allow_list = []
    registered_users = []
    users_credential_data = []

    # Register a first user with a random RP
    _, credential_data, _ = generate_get_assertion_params(client)
    allow_list.append({"id": credential_data.credential_id, "type": "public-key"})

    # Register 3 users for a known RP
    for idx in range(3):
        client_data_hash, _, user, key_params = generate_make_credentials_params(ref=idx)
        attestation = client.ctap2.make_credential(client_data_hash,
                                                   rp,
                                                   user,
                                                   key_params)
        credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
        allow_list.append({"id": credential_data.credential_id, "type": "public-key"})
        registered_users.append(user)
        users_credential_data.append(credential_data)

    # Register another user with another RP
    _, credential_data, _ = generate_get_assertion_params(client)
    allow_list.append({"id": credential_data.credential_id, "type": "public-key"})

    # Generate get assertion request checking presented users
    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                           login_type="multi",
                                           user_accept=True,
                                           check_users=registered_users,
                                           check_screens="full",
                                           compare_args=compare_args)

    credential_data = users_credential_data[0]
    assertion.verify(client_data_hash, credential_data.public_key)

    with pytest.raises(InvalidSignature):
        credential_data = users_credential_data[1]
        assertion.verify(client_data_hash, credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_rpid_filter(client):
    rp, credential_data, _ = generate_get_assertion_params(client)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    rp["id"] = rp["id"].replace("webctap", "www")
    if client.ctap2_u2f_proxy:
        # On u2f proxy, our app enforce rpid to start with "webctap."
        # Returned error code is ERROR_PROP_RPID_MEDIA_DENIED 0x8E
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash,
                                       allow_list, user_accept=None)

        assert e.value.code == CtapError(0x8E).code
    else:
        # RP id has changed, and so there should be no credentials with
        # this id
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash,
                                       allow_list,
                                       login_type="none",
                                       user_accept=None)
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_cancel(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    if client.ctap2_u2f_proxy:
        pytest.skip("Does not work with this transport")

    rp, credential_data, user = generate_get_assertion_params(client, ref=0)
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash,
                                   allow_list, user_accept=None,
                                   check_users=[user],
                                   check_screens="full",
                                   check_cancel=True,
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL


def test_get_assertion_bad_allow_list(client):
    rp, credential_data, _ = generate_get_assertion_params(client)
    client_data_hash = generate_random_bytes(32)

    # With an element that is not of type MAP
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    allow_list.append(["toto"])
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "type"
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"id": credential_data.credential_id})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "type"
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"id": credential_data.credential_id, "type": b"012451"})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "id"
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "id"
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"id": "bad", "type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


# Todo add tests with
# - Validation of request:
#   - CBOR fields errors: missing / bad type / bad length...
# - Check that ux_require_pin() is being called when requested
