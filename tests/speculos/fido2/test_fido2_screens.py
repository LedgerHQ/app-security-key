import pytest
import sys

from fido2.webauthn import AttestedCredentialData

from client import TESTS_SPECULOS_DIR
from utils import generate_random_bytes
from utils import generate_make_credentials_params
from utils import HAVE_RK_SUPPORT_SETTING

from ragger.navigator import NavInsID


@pytest.mark.skipif(not HAVE_RK_SUPPORT_SETTING,
                    reason="settings not enable")
def test_fido_screens_settings(client, test_name):
    instructions = []
    # Screen 0 -> 1
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 1 -> 2
    instructions.append(NavInsID.RIGHT_CLICK)
    # enter settings
    instructions.append(NavInsID.BOTH_CLICK)

    # Enable and check "Enabling" warning message
    instructions.append(NavInsID.BOTH_CLICK)
    # Screen 0 -> 1
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 1 -> 2
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 2 -> 3
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 3 -> 4
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 4 -> 5
    instructions.append(NavInsID.RIGHT_CLICK)
    # Confirm
    instructions.append(NavInsID.BOTH_CLICK)

    # Disable and check "Disabling" warning message
    instructions.append(NavInsID.BOTH_CLICK)
    # Screen 0 -> 1
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 1 -> 2
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 2 -> 3
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 3 -> 4
    instructions.append(NavInsID.RIGHT_CLICK)
    # Screen 4 -> 3
    instructions.append(NavInsID.LEFT_CLICK)
    # Approve
    instructions.append(NavInsID.BOTH_CLICK)

    # leave settings
    # Screen 0 -> 1
    instructions.append(NavInsID.RIGHT_CLICK)
    # confirm
    instructions.append(NavInsID.BOTH_CLICK)

    client.navigator.navigate_and_compare(TESTS_SPECULOS_DIR, test_name, instructions,
                                          screen_change_before_first_instruction=False)


def register_then_assert(client, test_name, user, options):
    client_data_hash, rp, _, key_params = generate_make_credentials_params(ref=0)
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/make")
    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               options=options,
                                               check_screens="fast",
                                               compare_args=compare_args)
    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Generate get assertion request
    client_data_hash = generate_random_bytes(32)
    if options and options.get("rk", False):
        allow_list = None
    else:
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/get")
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                           user_accept=True,
                                           check_users=[user],
                                           check_screens="fast",
                                           compare_args=compare_args)

    assertion.verify(client_data_hash, credential_data.public_key)


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_fido2_screens_short_id(client, test_name):
    # User ID: https://www.w3.org/TR/webauthn/#user-handle
    # => an opaque byte sequence with a maximum size of 64 bytes

    user = {"id": b"00"}
    register_then_assert(client, test_name, user, None)


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_fido2_screens_user_name(client, test_name):
    # User name: https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    # => can be more than 64 bytes

    user = {"id": b"00", "name": "a" * 75}
    register_then_assert(client, test_name, user, None)


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_fido2_screens_user_display_name(client, test_name):
    user = {"id": b"00", "displayName": "b" * 75}
    register_then_assert(client, test_name, user, None)


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_fido2_screens_user_name_and_display_name(client, test_name):
    user = {"id": b"00", "name": "a" * 75, "displayName": "b" * 75}
    register_then_assert(client, test_name, user, None)


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_fido2_screens_user_icon(client, test_name):
    user = {"id": b"00", "icon": "c" * 75}
    register_then_assert(client, test_name, user, None)
