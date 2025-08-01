import cryptography
import pytest
import struct
from fido2.ctap1 import Ctap1, ApduError, SignatureData
from fido2.hid import CTAPHID

from ..client import TESTS_SPECULOS_DIR
from ..ctap1_client import APDU, U2F_P1
from ..utils import FIDO_RP_ID_HASH_1, generate_random_bytes, Nav


def register(client, _app_param=None):
    challenge = generate_random_bytes(32)
    if _app_param:
        app_param = _app_param
    else:
        app_param = generate_random_bytes(32)
    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)

    return app_param, registration_data


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_check_only_ok(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  registration_data.key_handle,
                                  check_only=True,
                                  navigation=Nav.NONE)

    # 0x07 ("check-only"): if the control byte is set to 0x07 by the FIDO Client,
    # the U2F token is supposed to simply check whether the provided key handle
    # was originally created by this token, and whether it was created for the
    # provided application parameter. If so, the U2F token MUST respond with an
    # authentication response message:error:test-of-user-presence-required
    # (note that despite the name this signals a success condition).
    assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_check_only_wrong_key_handle(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)
    key_handle = bytearray(registration_data.key_handle)

    # Change key_handle first bit
    key_handle[0] ^= 0x40

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  key_handle,
                                  check_only=True,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_check_only_wrong_app_param(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)
    key_handle = bytearray(registration_data.key_handle)

    # Change app_param first bit
    app_param = bytearray(app_param)
    app_param[0] ^= 0x40

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  key_handle,
                                  check_only=True,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_ok(client, test_name):
    app_param, registration_data = register(client, FIDO_RP_ID_HASH_1)
    challenge = generate_random_bytes(32)

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    registration_data.key_handle,
                                                    check_screens=True,
                                                    compare_args=compare_args)

    authentication_data.verify(app_param, challenge, registration_data.public_key)


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_user_refused(client, test_name):
    app_param, registration_data = register(client, FIDO_RP_ID_HASH_1)
    challenge = generate_random_bytes(32)

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  registration_data.key_handle,
                                  navigation=Nav.USER_REFUSE,
                                  check_screens=True,
                                  compare_args=compare_args)

    assert e.value.code == APDU.SW_USER_REFUSED


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_with_reboot_ok(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)

    client.simulate_reboot()

    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    registration_data.key_handle)

    authentication_data.verify(app_param, challenge, registration_data.public_key)


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_multiple_ok(client):
    registrations = []
    for _ in range(5):
        app_param, registration_data = register(client)
        registrations.append((app_param, registration_data))

    for app_param, registration_data in registrations:
        challenge = generate_random_bytes(32)

        authentication_data = client.ctap1.authenticate(challenge,
                                                        app_param,
                                                        registration_data.key_handle)

        authentication_data.verify(app_param, challenge, registration_data.public_key)


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_counter_increment(client):
    app_param, registration_data = register(client)

    prev = 0
    for _ in range(5):
        challenge = generate_random_bytes(32)

        authentication_data = client.ctap1.authenticate(challenge,
                                                        app_param,
                                                        registration_data.key_handle)

        authentication_data.verify(app_param, challenge, registration_data.public_key)

        assert authentication_data.counter > prev

        prev = authentication_data.counter

        # Would be nice to test with device reboot too, but client.simulate_reboot()
        # doesn't keep NVM data.


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_no_registration(client):
    challenge = generate_random_bytes(32)

    # Use random app_param and public key
    key_handle = generate_random_bytes(64)
    app_param = generate_random_bytes(32)

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  key_handle,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_wrong_challenge(client):
    app_param, registration_data = register(client)
    challenge = bytearray(generate_random_bytes(32))

    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    registration_data.key_handle)

    # Change challenge first bit
    challenge[0] ^= 0x40

    with pytest.raises(cryptography.exceptions.InvalidSignature):
        authentication_data.verify(app_param, challenge, registration_data.public_key)


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_wrong_app_param(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)

    # Change app_param first bit
    app_param = bytearray(app_param)
    app_param[0] ^= 0x40

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  registration_data.key_handle,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_wrong_key_handle(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)
    key_handle = bytearray(registration_data.key_handle)

    # Change key_handle first bit
    key_handle[0] ^= 0x40

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  key_handle,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_length_too_short(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)

    # Shorten public key
    key_handle = registration_data.key_handle[:-1]

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  key_handle,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_length_too_long(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)

    # Extend public key
    key_handle = registration_data.key_handle + generate_random_bytes(1)

    with pytest.raises(ApduError) as e:
        client.ctap1.authenticate(challenge,
                                  app_param,
                                  key_handle,
                                  navigation=Nav.NONE)

    assert e.value.code == APDU.SW_WRONG_DATA


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_wrong_p1p2(client):
    app_param, registration_data = register(client)
    challenge = generate_random_bytes(32)
    key_handle = registration_data.key_handle

    # Craft nominal packet data
    data = (challenge + app_param + struct.pack(">B", len(key_handle)) + key_handle)

    # Valid P1 are:
    valid_p1 = [
        U2F_P1.CHECK_IS_REGISTERED,
        U2F_P1.REQUEST_USER_PRESENCE,
        U2F_P1.OPTIONAL_USER_PRESENCE
    ]
    for p1 in range(0xff + 1):
        if p1 in valid_p1:
            continue
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=Ctap1.INS.AUTHENTICATE,
                                   p1=p1,
                                   p2=0x00,
                                   data=data)
        assert e.value.code == APDU.SW_INCORRECT_P1P2

    # Only supported P2 is 0x00
    for p2 in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=Ctap1.INS.AUTHENTICATE,
                                   p1=0x00,
                                   p2=p2,
                                   data=data)
        assert e.value.code == APDU.SW_INCORRECT_P1P2


@pytest.mark.skip_endpoint(["NFC", "HID"], reason="This test is meant for U2F transport only")
def test_authenticate_raw(client):
    valid_p1 = [
        U2F_P1.CHECK_IS_REGISTERED,
        U2F_P1.REQUEST_USER_PRESENCE,
        U2F_P1.OPTIONAL_USER_PRESENCE
    ]
    for p1 in valid_p1:
        app_param, registration_data = register(client)
        challenge = generate_random_bytes(32)
        key_handle = registration_data.key_handle
        key_handle_len = struct.pack(">B", len(key_handle))

        data = challenge + app_param + key_handle_len + key_handle

        if p1 == U2F_P1.CHECK_IS_REGISTERED:
            client.ctap1.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE,
                                          p1=p1, data=data)
            response = client.ctap1.device.recv(CTAPHID.MSG)
            with pytest.raises(ApduError) as e:
                client.ctap1.parse_response(response)
            assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED

        else:
            # On U2F endpoint, the device should return APDU.SW_CONDITIONS_NOT_SATISFIED
            # until user validate.
            for i in range(10):
                client.ctap1.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE,
                                              p1=p1, data=data)

                response = client.ctap1.device.recv(CTAPHID.MSG)

                with pytest.raises(ApduError) as e:
                    response = client.ctap1.parse_response(response)

                assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED

            # Confirm request
            client.ctap1.confirm()

            client.ctap1.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE,
                                          p1=p1, data=data)

            response = client.ctap1.device.recv(CTAPHID.MSG)
            client.ctap1.wait_for_return_on_dashboard()
            response = client.ctap1.parse_response(response)

            authentication_data = SignatureData(response)

            authentication_data.verify(app_param, challenge, registration_data.public_key)


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_authenticate_retrocompat(client):
    # Make sure that app update will still works with previously generated
    # key handles and public key already shared with some Relying Party
    app_param_hex = "f430952043cccefab769aa034f8f38d6"
    app_param_hex += "9c21d3d685ed7044a3602c4f8901ec73"
    app_param = bytearray.fromhex(app_param_hex)

    key_handle_hex = "012f3f3858150bbef433cb4106cd3366"
    key_handle_hex += "6355b8f6a9642da8a7b85a29c5c0c5a2d5"
    key_handle = bytearray.fromhex(key_handle_hex)

    public_key_hex = "046aeca2df937f91bd30471e73f5c36d"
    public_key_hex += "60a3cdff36cd469d1ac6c95c9d84e01c"
    public_key_hex += "5db23952cc01a55c84b139277db0e810"
    public_key_hex += "b92da64950770c6a67a47a8782ec827f8e"
    public_key = bytearray.fromhex(public_key_hex)

    challenge = generate_random_bytes(32)

    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    key_handle)

    authentication_data.verify(app_param, challenge, public_key)
