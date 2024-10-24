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

    t = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                           allow_list,
                                           check_users=[t.args.user],
                                           check_screens="full",
                                           compare_args=compare_args)

    assertion.verify(client_data_hash, t.credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(t.args.rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None

    client.simulate_reboot()

    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                           allow_list)

    assertion.verify(client_data_hash, t.credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(t.args.rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_uv(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    t = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    options = {"uv": True}
    assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                           allow_list, options=options,
                                           check_users=[t.args.user],
                                           check_screens="full",
                                           compare_args=compare_args)

    assertion.verify(client_data_hash, t.credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(t.args.rp["id"].encode()) == assertion.auth_data.rp_id_hash

    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.USER_VERIFIED
    assert assertion.auth_data.flags == expected_flags
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_no_up(client):
    t = generate_get_assertion_params(client)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    options = {"up": False}
    assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                           allow_list, options=options,
                                           user_accept=None)

    assertion.verify(client_data_hash, t.credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(t.args.rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == 0
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_user_refused(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    t = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                   allow_list, user_accept=False,
                                   check_users=[t.args.user],
                                   check_screens="full",
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED


def test_get_assertion_no_credentials(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    args = generate_make_credentials_params(client, ref=0)

    # Try without allow_list
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(args.rp["id"], args.client_data_hash,
                                   login_type="none",
                                   check_screens="full",
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    # Try with unknown credential in allow_list
    args = generate_make_credentials_params(client)
    allow_list = [{"id": generate_random_bytes(32), "type": "public-key"}]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(args.rp["id"], args.client_data_hash,
                                   allow_list,
                                   login_type="none",
                                   check_screens="full",
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_no_credentials_no_up(client, test_name):
    options = {"up": False}
    args = generate_make_credentials_params(client, ref=0)

    # Try without allow_list
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(args.rp["id"], args.client_data_hash,
                                   options=options,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    # Try with unknown credential in allow_list
    args = generate_make_credentials_params(client)
    allow_list = [{"id": generate_random_bytes(32), "type": "public-key"}]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(args.rp["id"], args.client_data_hash,
                                   allow_list, options=options, user_accept=None)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_wrong_id(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    t = generate_get_assertion_params(client, ref=0)
    client_data_hash = generate_random_bytes(32)

    # Test changing the version field, the tag, or the ciphered data
    for pos in [0, 10, 20]:
        # Change id first bit
        wrong_id = bytearray(t.credential_data.credential_id)
        wrong_id[pos] ^= 0x80
        wrong_id = bytes(wrong_id)

        allow_list = [{"id": wrong_id, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                   allow_list,
                                   login_type="none",
                                   check_screens="full",
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_wrong_rp(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    t = generate_get_assertion_params(client, ref=0)
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]

    # Change rp_id at the end to still pass rpid_filter
    wrong_rp_id = t.args.rp["id"] + ".fake"

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(wrong_rp_id, client_data_hash,
                                   allow_list,
                                   login_type="none",
                                   check_screens="full",
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_allow_list_ok(client, test_name):
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
    t = generate_get_assertion_params(client, rp=rp)
    allow_list.append({"id": t.credential_data.credential_id, "type": "public-key"})

    # Register 3 users for a known RP
    for idx in range(1, 4):
        local_args = generate_make_credentials_params(client, ref=idx)
        local_args.rp = t.args.rp
        attestation = client.ctap2.make_credential(local_args)
        credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
        allow_list.append({"id": credential_data.credential_id, "type": "public-key"})
        registered_users.append(local_args.user)
        users_credential_data.append(credential_data)

    # Register another user with another RP
    new_t = generate_get_assertion_params(client)
    allow_list.append({"id": new_t.credential_data.credential_id, "type": "public-key"})

    # Generate get assertion request checking presented users
    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                           login_type="multi",
                                           user_accept=True,
                                           check_users=registered_users,
                                           check_screens="full",
                                           compare_args=compare_args,
                                           select_user_idx=3)

    credential_data = users_credential_data[2]
    assertion.verify(client_data_hash, t.credential_data.public_key)

    with pytest.raises(InvalidSignature):
        credential_data = users_credential_data[1]
        assertion.verify(client_data_hash, t.credential_data.public_key)

    assert len(assertion.auth_data) == 37
    assert sha256(t.args.rp["id"].encode()) == assertion.auth_data.rp_id_hash
    assert assertion.auth_data.flags == AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_get_assertion_rpid_filter(client):
    t = generate_get_assertion_params(client)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]

    t.args.rp["id"] = t.args.rp["id"].replace("webctap", "www")
    if client.ctap2_u2f_proxy:
        # On u2f proxy, our app enforce rpid to start with "webctap."
        # Returned error code is ERROR_PROP_RPID_MEDIA_DENIED 0x8E
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                       allow_list, user_accept=None)

        assert e.value.code == CtapError(0x8E).code
    else:
        # RP id has changed, and so there should be no credentials with
        # this id
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                       allow_list,
                                       login_type="none")
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_assertion_cancel(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    if client.ctap2_u2f_proxy:
        pytest.skip("Does not work with this transport")

    t = generate_get_assertion_params(client, ref=0)
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                   allow_list, user_accept=None,
                                   check_users=[t.args.user],
                                   check_screens="full",
                                   check_cancel=True,
                                   compare_args=compare_args)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL


def test_get_assertion_bad_allow_list(client):
    t = generate_get_assertion_params(client)
    client_data_hash = generate_random_bytes(32)

    # With an element that is not of type MAP
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    allow_list.append(["toto"])
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "type"
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"id": t.credential_data.credential_id})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "type"
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"id": t.credential_data.credential_id, "type": b"012451"})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.INVALID_CBOR

    # With an element with missing "id"
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # With an element with bad type for "id"
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    allow_list.append({"id": "bad", "type": "public-key"})
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


def test_get_assertion_duplicate_allow_list_entries(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    t = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}] * 2
    assertion = client.ctap2.get_assertion(t.args.rp["id"],
                                           client_data_hash,
                                           allow_list,
                                           check_users=[t.args.user],
                                           check_screens="full",
                                           compare_args=compare_args)

    assertion.verify(client_data_hash, t.credential_data.public_key)


def test_get_assertion_retrocompat(client):
    # Make sure that app update will still works with previously generated
    # key handles and public key already shared with some Relying Party
    credential_data_raw_hex = "58b44d0b0a7cf33afd48f7153c871352"
    credential_data_raw_hex += "0059022363d64e399b805bbc4cfe2600"
    credential_data_raw_hex += "84d80df32145a6f7adda491249fc742e"
    credential_data_raw_hex += "9dec78f4f45060ec450e7af01e4167c7"
    credential_data_raw_hex += "539b1df5da0355230fa94b7f7ea34a8b"
    credential_data_raw_hex += "14e2b565960f183a9cb33aafa11a23fa"
    credential_data_raw_hex += "bafe399a758dbdcb4dfaa8a501020326"
    credential_data_raw_hex += "2001215820aae619de9564ae171df2f0"
    credential_data_raw_hex += "de25f513e1cb80d17433fb3cf84ca5c8"
    credential_data_raw_hex += "16bfd4bd9e22582089199cc93633d93a"
    credential_data_raw_hex += "c3275a46a33f9266eee0a14f66c154e7"
    credential_data_raw_hex += "802677f5eb1cbdcf"
    credential_data_raw = bytearray.fromhex(credential_data_raw_hex)

    user_id_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

    user = {
        'id': bytearray.fromhex(user_id_hex),
        'name': 'My user name'
    }

    rp_id = "webctap.myservice.com"

    credential_data = AttestedCredentialData(credential_data_raw)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}] * 2
    assertion = client.ctap2.get_assertion(rp_id, client_data_hash,
                                           allow_list,
                                           check_users=[user])

    assertion.verify(client_data_hash, credential_data.public_key)


# Todo add tests with
# - Validation of request:
#   - CBOR fields errors: missing / bad type / bad length...
# - Check that ux_require_pin() is being called when requested
