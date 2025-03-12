import pytest
import sys

from fido2.ctap import CtapError
from fido2.webauthn import AttestedCredentialData
from typing import Dict, List
from ragger.backend import SpeculosBackend
from ragger.firmware import Firmware
from ragger.navigator import NanoNavigator, TouchNavigator

from ..client import TESTS_SPECULOS_DIR, TestClient
from ..transport import TransportType
from ..utils import generate_random_bytes, generate_make_credentials_params, \
    ctap2_get_assertion, MakeCredentialArguments, Nav


@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_disabled(client):
    info = client.ctap2.info
    assert not info.options["rk"]

    args = generate_make_credentials_params(client, rk=True)

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.UNSUPPORTED_OPTION


@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_enabled(client):
    client.enable_rk_option()

    info = client.ctap2.info
    assert info.options["rk"]


@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_make_cred_exclude_refused(client, test_name):
    client.enable_rk_option()

    compare_args = (TESTS_SPECULOS_DIR, client.transported_path(test_name))
    # Spec says that:
    # If the excludeList parameter is present and contains a credential ID that
    # is present on this authenticator and bound to the specified rpId, wait
    # for user presence, then terminate this procedure and return error code
    # CTAP2_ERR_CREDENTIAL_EXCLUDED.

    # Create a first credential with rk=True
    t = ctap2_get_assertion(client, rk=True)

    # Now create a new one with:
    # - Same RP
    # - Previous credential in excludeList
    # leads to a CREDENTIAL_EXCLUDED error.
    args = generate_make_credentials_params(client,
                                            exclude_list=[{"id": t.credential_data.credential_id,
                                                           "type": "public-key"}])
    args.rp = t.args.rp
    args.credential_data = t.credential_data

    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)

    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    # DEVIATION from FIDO2.0 spec: Should prompt user to exclude
    # Impact is minor because user has manually unlocked its device.
    # Therefore user presence is somehow guarantee.

    # Check that if the RP didn't match, the request is accepted
    args = generate_make_credentials_params(client, ref=0,
                                            exclude_list=[{"id": t.credential_data.credential_id,
                                                           "type": "public-key"}])

    client.ctap2.make_credential(args, check_screens=True, compare_args=compare_args)


@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_get_assertion(client, test_name, transport: TransportType):
    test_prefix = client.transported_path(test_name)
    client.enable_rk_option()

    user1 = generate_make_credentials_params(client, ref=1, rk=True)
    user2 = generate_make_credentials_params(client, ref=2, rk=True,
                                             client_data_hash=user1.client_data_hash,
                                             rp=user1.rp)
    user3 = generate_make_credentials_params(client, ref=3, rk=True,
                                             client_data_hash=user1.client_data_hash,
                                             rp=user1.rp)

    user2.user["name"] = "user name"

    users: list[MakeCredentialArguments] = []
    allow_list: List[Dict] = []

    for idx, user in enumerate([user1, user2, user3]):
        if idx == 2 and "--fast" in sys.argv:
            # Skip additional step on fast mode
            continue
        compare_args = (TESTS_SPECULOS_DIR, test_prefix + f"/{idx}/make")
        attestation = client.ctap2.make_credential(user,
                                                   check_screens=True,
                                                   compare_args=compare_args)

        # Users are then shown in the order with the last created presented first
        users = [user] + users
        simple_login = len(users) == 1

        client_data_hash = generate_random_bytes(32)
        compare_args = (TESTS_SPECULOS_DIR, test_prefix + f"/{idx}/get_rk")
        assertion = client.ctap2.get_assertion(user.rp["id"], client_data_hash,
                                               check_users=users, check_screens=True,
                                               simple_login=simple_login, compare_args=compare_args)
        credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

        assertion.verify(client_data_hash, credential_data.public_key)
        assert user.user["id"] == users[0].user["id"]  # most recent selected

        # Check with allowList
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}] + allow_list

        client_data_hash = generate_random_bytes(32)
        compare_args = (TESTS_SPECULOS_DIR, test_prefix + f"/{idx}/get_allow_list")
        assertion = client.ctap2.get_assertion(user.rp["id"], client_data_hash,
                                               allow_list=allow_list,
                                               check_users=[u.user for u in users],
                                               check_screens=True,
                                               simple_login=simple_login, compare_args=compare_args)
        assertion.verify(client_data_hash, credential_data.public_key)
        assert assertion.user["id"] == users[0].user["id"]  # first of allow_list selected

    # CTAP2 reset is not available on NFC
    if transport is not TransportType.NFC:
        # Check that nothing remains after a reset
        client.ctap2.reset()
        client_data_hash = generate_random_bytes(32)
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(user1.rp["id"], client_data_hash, will_fail=True)
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def start_client(
        backend: SpeculosBackend,
        firmware: Firmware,
        transport: TransportType,
        ctap2_u2f_proxy: bool,
        golden_run: bool):
    NavigatorType = TouchNavigator if backend.firmware == Firmware.STAX else NanoNavigator
    navigator = NavigatorType(backend, backend.firmware, golden_run)
    client = TestClient(firmware, backend, navigator, transport, ctap2_u2f_proxy)
    client.start()
    client.enable_rk_option()
    return client


@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_with_persistance_get_assertion(
        get_2_backends,
        firmware: Firmware,
        test_name,
        transport: TransportType,
        ctap2_u2f_proxy: bool,
        golden_run: bool):

    backend_setup, backend_with_load_nvram = get_2_backends

    # Preparation
    attestation = []
    users: list[MakeCredentialArguments] = []

    with backend_setup:
        client = start_client(backend_setup, firmware, transport,
                              ctap2_u2f_proxy, golden_run)

        user1 = generate_make_credentials_params(client, ref=1, rk=True)
        user2 = generate_make_credentials_params(client, ref=2, rk=True)
        user3 = generate_make_credentials_params(client, ref=3, rk=True)

        for idx, user in enumerate([user1, user2, user3]):
            if idx == 2 and "--fast" in sys.argv:
                # Skip additional step on fast mode
                continue

            test_prefix = client.transported_path(test_name)
            compare_args = (TESTS_SPECULOS_DIR, test_prefix + f"/{idx}/make")
            attestation.append(client.ctap2.make_credential(user,
                                                            check_screens=True,
                                                            compare_args=compare_args))

            # Users are then shown in the order with the last created presented first
            users = [user] + users

    with backend_with_load_nvram:

        client = start_client(backend_with_load_nvram, firmware, transport,
                              ctap2_u2f_proxy, golden_run)

        for idx, user in enumerate([user1, user2, user3]):
            if idx == 2 and "--fast" in sys.argv:
                # Skip additional step on fast mode
                continue
            client_data_hash = generate_random_bytes(32)

            test_prefix = client.transported_path(test_name)
            compare_args = (TESTS_SPECULOS_DIR, test_prefix + f"/{idx}/get_rk")

            simple_login = len(users) == 1
            assertion = client.ctap2.get_assertion(user.rp["id"], client_data_hash,
                                                   check_users=users, check_screens=True,
                                                   simple_login=simple_login,
                                                   compare_args=compare_args)
            credential_data = AttestedCredentialData(attestation[idx].auth_data.credential_data)
            assertion.verify(client_data_hash, credential_data.public_key)

            # Check with allowList
            allow_list: List[Dict] = []
            allow_list = [{"id": credential_data.credential_id, "type": "public-key"}] + allow_list

            client_data_hash = generate_random_bytes(32)
            compare_args = (TESTS_SPECULOS_DIR, test_prefix + f"/{idx}/get_allow_list")
            assertion = client.ctap2.get_assertion(user.rp["id"], client_data_hash,
                                                   allow_list=allow_list,
                                                   check_users=[u.user for u in users],
                                                   check_screens=True,
                                                   simple_login=simple_login,
                                                   compare_args=compare_args)
            assertion.verify(client_data_hash, credential_data.public_key)

        # CTAP2 reset is not available on NFC
        if transport is not TransportType.NFC:
            # Check that nothing remains after a reset
            client.ctap2.reset()
            client_data_hash = generate_random_bytes(32)
            with pytest.raises(CtapError) as e:
                client.ctap2.get_assertion(user1.rp["id"], client_data_hash, will_fail=True)
            assert e.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.skipif("--fast" in sys.argv, reason="running in fast mode")
@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_key_store_full(client, transport: TransportType):
    client.enable_rk_option()

    # Check that at some point KEY_STORE_FULL error is returned
    with pytest.raises(CtapError) as e:
        for _ in range(30):
            ctap2_get_assertion(client, rk=True)
    assert e.value.code == CtapError.ERR.KEY_STORE_FULL

    # Check that it is consistently returned
    with pytest.raises(CtapError) as e:
        ctap2_get_assertion(client, rk=True, will_fail=True)
    assert e.value.code == CtapError.ERR.KEY_STORE_FULL

    # CTAP2 reset is not available on NFC
    if transport is not TransportType.NFC:
        # Check that credentials can be stored again after a reset
        client.ctap2.reset()
        ctap2_get_assertion(client, rk=True)


@pytest.mark.skipif("--fast" in sys.argv, reason="running in fast mode")
@pytest.mark.skip_if_not_rk_config_ui
def test_option_rk_overwrite_get_assertion(client, test_name):
    test_prefix = client.transported_path(test_name)
    client.enable_rk_option()

    # Make a first "user1" credential
    args = generate_make_credentials_params(client, ref=1, rk=True)
    args.user["name"] = "user1"
    compare_args = (TESTS_SPECULOS_DIR, test_prefix + "/1/make")
    attestation = client.ctap2.make_credential(args,
                                               check_screens=True,
                                               compare_args=compare_args)
    user1_credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Verify that a valid assertion can be requested
    client_data_hash = generate_random_bytes(32)
    compare_args = (TESTS_SPECULOS_DIR, test_prefix + "/1/get_assertion")
    assertion = client.ctap2.get_assertion(args.rp["id"], client_data_hash, None,
                                           check_users=[args.user],
                                           check_screens=True,
                                           compare_args=compare_args)
    assertion.verify(client_data_hash, user1_credential_data.public_key)

    # Overwrite previous user name by creating a new credential with same
    # RP ID and account ID.
    args.user["name"] = "user2"
    args.client_data_hash = generate_random_bytes(32)
    compare_args = (TESTS_SPECULOS_DIR, test_prefix + "/2/make")
    attestation = client.ctap2.make_credential(args,
                                               check_screens=True,
                                               compare_args=compare_args)
    user2_credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    # Verify that a valid assertion can be requested and that the user
    # information displayed are for user2.
    client_data_hash = generate_random_bytes(32)
    compare_args = (TESTS_SPECULOS_DIR, test_prefix + "/2/get_assertion")
    assertion = client.ctap2.get_assertion(args.rp["id"], client_data_hash, None,
                                           check_users=[args.user],
                                           check_screens=True,
                                           compare_args=compare_args)
    assertion.verify(client_data_hash, user2_credential_data.public_key)

    # Simulate reboot here to exit the get_assertion flow that is pending
    client.simulate_reboot()

# Todo add tests with
# - If NVM feature is implemented using this framework, some test should be added
#   which would test the behavior upon reboot (credentials saved, ...)
