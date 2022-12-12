import pytest
import sys

from fido2.ctap import CtapError
from fido2.webauthn import AuthenticatorData

from client import TESTS_SPECULOS_DIR
from utils import generate_random_bytes, generate_get_assertion_params

MAX_TX_AUTH_SIMPLE_SIZE = 200


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_extensions_txAuthSimple(client, test_name):
    info = client.ctap2.info
    assert "txAuthSimple" in info.extensions

    # Create a credential
    rp, credential_data, user = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    message_list = ["Pretty short message", "Pretty short message" * 5, "Pretty short message" * 20]
    for idx, message in enumerate(message_list):
        compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + str(idx))
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
        extensions = {"txAuthSimple": message}
        assertion = client.ctap2.get_assertion_with_txSimpleAuth(rp["id"], client_data_hash,
                                                                 allow_list, extensions,
                                                                 check_users=[user],
                                                                 compare_args=compare_args)

        assertion.verify(client_data_hash, credential_data.public_key)

        expected_flags = AuthenticatorData.FLAG.USER_PRESENT
        expected_flags |= AuthenticatorData.FLAG.EXTENSION_DATA
        assert assertion.auth_data.flags == expected_flags

        if len(message) < MAX_TX_AUTH_SIMPLE_SIZE:
            assert assertion.auth_data.extensions["txAuthSimple"] == message
        else:
            assert assertion.auth_data.extensions["txAuthSimple"] == ''

    # We are doing dangerous things with txAuthSimple:
    # - adding an '\0' at the end in the CBOR buffer
    # So check that we still can process the rest of the buffer correctly..

    # check parsing of uv
    client_data_hash = generate_random_bytes(32)
    message = "Pretty short message"
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    extensions = {"txAuthSimple": message}
    options = {"uv": True}
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + str(len(message_list)))
    assertion = client.ctap2.get_assertion_with_txSimpleAuth(rp["id"], client_data_hash,
                                                             allow_list, extensions, options,
                                                             check_users=[user],
                                                             compare_args=compare_args)

    assertion.verify(client_data_hash, credential_data.public_key)
    expected_flags = AuthenticatorData.FLAG.USER_PRESENT
    expected_flags |= AuthenticatorData.FLAG.USER_VERIFIED
    expected_flags |= AuthenticatorData.FLAG.EXTENSION_DATA
    assert assertion.auth_data.flags == expected_flags
    assert assertion.auth_data.extensions["txAuthSimple"] == message


def test_extensions_txAuthSimple_user_refused(client, test_name):
    compare_args = (TESTS_SPECULOS_DIR, test_name)
    # Create a credential
    rp, credential_data, user = generate_get_assertion_params(client, ref=0)

    client_data_hash = generate_random_bytes(32)
    message = "Pretty short message"

    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    extensions = {"txAuthSimple": message}

    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion_with_txSimpleAuth(rp["id"], client_data_hash,
                                                     allow_list, extensions,
                                                     user_accept=False,
                                                     check_users=[user],
                                                     compare_args=compare_args)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED


def test_extensions_txAuthSimple_multiple(client, test_name):
    allow_list = []
    registered_users = []
    users_credential_data = []
    rp = None

    # Register 3 users for the same RP
    for idx in range(3):
        rp, credential_data, user = generate_get_assertion_params(client, rp=rp, ref=idx)
        allow_list.append({"id": credential_data.credential_id, "type": "public-key"})
        users_credential_data.append(credential_data)
        registered_users.append(user)

    client_data_hash = generate_random_bytes(32)
    message = "Pretty short message"
    extensions = {"txAuthSimple": message}

    # Try without user accept
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/refused")
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion_with_txSimpleAuth(rp["id"], client_data_hash,
                                                     allow_list, extensions,
                                                     login_type="multi",
                                                     user_accept=False,
                                                     check_users=registered_users,
                                                     compare_args=compare_args)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED

    # Try with user accept
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/accepted")
    assertion = client.ctap2.get_assertion_with_txSimpleAuth(rp["id"], client_data_hash,
                                                             allow_list, extensions,
                                                             login_type="multi",
                                                             check_users=registered_users,
                                                             compare_args=compare_args)

    assertion.verify(client_data_hash, users_credential_data[0].public_key)

    assert assertion.auth_data.extensions["txAuthSimple"] == message

# Todo add tests with
# - Validation of request:
#   - CBOR fields errors: missing / bad type / bad length...
