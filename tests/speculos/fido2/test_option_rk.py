import pytest
import sys

from fido2.ctap import CtapError
from fido2.webauthn import AttestedCredentialData

from client import TESTS_SPECULOS_DIR
from utils import generate_random_bytes, generate_make_credentials_params
from utils import generate_get_assertion_params
from utils import HAVE_RK_SUPPORT_SETTING

from ragger.navigator import NavInsID, NavIns


@pytest.mark.skipif(not HAVE_RK_SUPPORT_SETTING,
                    reason="settings not enable")
def test_option_rk_disabled(client):
    info = client.ctap2.info
    assert not info.options["rk"]

    client_data_hash, rp, user, key_params = generate_make_credentials_params()
    options = {"rk": True}

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     options=options,
                                     user_accept=None)
    assert e.value.code == CtapError.ERR.UNSUPPORTED_OPTION


def enable_rk_option(client):
    info = client.ctap2.info
    if info.options["rk"]:
        return

    if not HAVE_RK_SUPPORT_SETTING:
        raise ValueError("rk and setting not enabled")

    if client.model.startswith("nano"):
        instructions = [
            # Enter in the settings
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,

            # Enable and skip "Enabling" message
            NavInsID.BOTH_CLICK
        ]

        if client.model != "nanos":
            # Screen 0 -> 5
            instructions += [NavInsID.RIGHT_CLICK] * 5
        else:
            # Screen 0 -> 13
            instructions += [NavInsID.RIGHT_CLICK] * 13

        instructions += [
            NavInsID.BOTH_CLICK,

            # Leave settings
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK
        ]
    else:
        instructions = [
            # Enter in the settings
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_NEXT,

            # Enable and skip "Enabling" message
            NavIns(NavInsID.CHOICE_CHOOSE, (1,)),
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            NavInsID.USE_CASE_STATUS_DISMISS,

            # Leave settings
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ]

    client.navigator.navigate(instructions,
                              screen_change_before_first_instruction=False)

    client.ctap2._info = client.ctap2.get_info()


def test_option_rk_enabled(client):
    enable_rk_option(client)

    info = client.ctap2.info
    assert info.options["rk"]


def test_option_rk_make_cred_exclude_refused(client, test_name):
    enable_rk_option(client)

    compare_args = (TESTS_SPECULOS_DIR, test_name)
    # Spec says that:
    # If the excludeList parameter is present and contains a credential ID that
    # is present on this authenticator and bound to the specified rpId, wait
    # for user presence, then terminate this procedure and return error code
    # CTAP2_ERR_CREDENTIAL_EXCLUDED.

    # Create a first credential with rk=True
    rp, credential_data, _ = generate_get_assertion_params(client, rk=True)

    # Now create a new one with:
    # - Same RP
    # - Previous credential in excludeList
    # leads to a CREDENTIAL_EXCLUDED error.
    client_data_hash, _, user, key_params = generate_make_credentials_params()
    exclude_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     exclude_list=exclude_list,
                                     user_accept=None)

    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    # DEVIATION from FIDO2.0 spec: Should prompt user to exclude
    # Impact is minor because user has manually unlocked its device.
    # Therefore user presence is somehow guarantee.

    # Check that if the RP didn't match, the request is accepted
    client_data_hash, rp, user, key_params = generate_make_credentials_params(ref=0)
    exclude_list = [{"id": credential_data.credential_id, "type": "public-key"}]

    client.ctap2.make_credential(client_data_hash,
                                 rp,
                                 user,
                                 key_params,
                                 exclude_list=exclude_list,
                                 check_screens="fast",
                                 compare_args=compare_args)

    # Reset device to clean rk credentials for next tests
    client.ctap2.reset()


def test_option_rk_get_assertion(client, test_name):
    enable_rk_option(client)

    client_data_hash, rp, user1, key_params = generate_make_credentials_params(ref=1)
    _, _, user2, key_params = generate_make_credentials_params(ref=2)
    _, _, user3, key_params = generate_make_credentials_params(ref=3)
    user2["name"] = "user name"
    options = {"rk": True}

    users = []
    allow_list = []

    for idx, user in enumerate([user1, user2, user3]):
        if idx == 2 and "--fast" in sys.argv:
            # Skip additional step on fast mode
            continue
        compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + str(idx) + "/make")
        attestation = client.ctap2.make_credential(client_data_hash,
                                                   rp,
                                                   user,
                                                   key_params,
                                                   options=options,
                                                   check_screens="fast",
                                                   compare_args=compare_args)
        credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

        # Users are then shown in the order with the last created presented first
        users = [user] + users
        login_type = "simple" if len(users) == 1 else "multi"

        client_data_hash = generate_random_bytes(32)
        compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + str(idx) + "/get_rk")
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                               check_users=users, check_screens="fast",
                                               login_type=login_type, compare_args=compare_args)

        assertion.verify(client_data_hash, credential_data.public_key)
        assert assertion.user["id"] == users[0]["id"]  # most recent selected

        # Check with allowList
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}] + allow_list

        client_data_hash = generate_random_bytes(32)
        compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + str(idx) + "/get_allow_list")
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                               allow_list=allow_list,
                                               check_users=users, check_screens="fast",
                                               login_type=login_type, compare_args=compare_args)
        assertion.verify(client_data_hash, credential_data.public_key)
        assert assertion.user["id"] == users[0]["id"]  # first of allow_list selected

    # Check that nothing remains after a reset
    client.ctap2.reset()

    client_data_hash = generate_random_bytes(32)
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp["id"], client_data_hash, login_type="none")
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_option_rk_key_store_full(client):
    enable_rk_option(client)

    # Check that at some point KEY_STORE_FULL error is returned
    with pytest.raises(CtapError) as e:
        for _ in range(30):
            generate_get_assertion_params(client, rk=True)
    assert e.value.code == CtapError.ERR.KEY_STORE_FULL

    # Check that it is consistently returned
    with pytest.raises(CtapError) as e:
        generate_get_assertion_params(client, rk=True)
    assert e.value.code == CtapError.ERR.KEY_STORE_FULL

    # Check that credentials can be stored again after a reset
    client.ctap2.reset()
    generate_get_assertion_params(client, rk=True)

    # Reset device to clean rk credentials for next tests
    client.ctap2.reset()


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_option_rk_overwrite_get_assertion(client, test_name):
    enable_rk_option(client)

    # Make a first "user1" credential
    client_data_hash, rp, user1, key_params = generate_make_credentials_params(ref=1)
    user1["name"] = "user1"
    options = {"rk": True}
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + "1" + "/make")
    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user1,
                                               key_params,
                                               options=options,
                                               check_screens="fast",
                                               compare_args=compare_args)
    user1_credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Verify that a valid assertion can be requested
    client_data_hash = generate_random_bytes(32)
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + "1" + "/get_assertion")
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, None,
                                           user_accept=True,
                                           check_users=[user1],
                                           check_screens="fast",
                                           compare_args=compare_args)
    assertion.verify(client_data_hash, user1_credential_data.public_key)

    # Overwrite previous user name by creating a new credential with same
    # RP ID and account ID.
    user2 = {
        "id": user1["id"],
        "name": "user2"
    }
    client_data_hash = generate_random_bytes(32)
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + "2" + "/make")
    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user2,
                                               key_params,
                                               options=options,
                                               check_screens="fast",
                                               compare_args=compare_args)
    user2_credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Verify that a valid assertion can be requested and that the user
    # information displayed are for user2.
    client_data_hash = generate_random_bytes(32)
    compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + "2" + "/get_assertion")
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, None,
                                           user_accept=True,
                                           check_users=[user2],
                                           check_screens="fast",
                                           compare_args=compare_args)
    assertion.verify(client_data_hash, user2_credential_data.public_key)

    # Simulate reboot here to exit the get_assertion flow that is pending
    client.simulate_reboot()

# Todo add tests with
# - If NVM feature is implemented using this framework, some test should be added
#   which would test the behavior upon reboot (credentials saved, ...)
