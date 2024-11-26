import pytest

from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from ..utils import generate_random_bytes, generate_make_credentials_params, \
    ctap2_get_assertion


PIN_A = "aaaa"
PIN_B = "bbbb"


def test_client_pin_check_version(client):
    assert client.ctap2.info.pin_uv_protocols == [1]
    assert client.client_pin.protocol.VERSION == PinProtocolV1.VERSION


def test_client_pin_test_bad_protocol(client):
    # Force protocol to V2 which is not supported
    bad_pin_protocol = ClientPin(client.ctap2, PinProtocolV2)
    with pytest.raises(CtapError) as e:
        bad_pin_protocol.set_pin(PIN_A)
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER


def test_client_pin_check_not_set(client):
    info = client.ctap2.info
    # Value depends on if a pin as been set.
    # Upon boot, pin is never set as we don't have NVM
    assert not info.options["clientPin"]

    with pytest.raises(CtapError) as e:
        client.client_pin.get_pin_retries()
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    with pytest.raises(CtapError) as e:
        client.client_pin.change_pin(PIN_A, PIN_B)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    with pytest.raises(CtapError) as e:
        client.client_pin.get_pin_token(PIN_A)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Check make credential request behavior with zero length pinAuth
    args = generate_make_credentials_params(client, pin_uv_param=b"")

    # DEVIATION from FIDO2.0 spec: If platform sends zero length pinAuth,
    # authenticator needs to wait for user touch and then returns [...]"
    # Impact is minor because user as still manually unlocked it's device.
    # therefore user presence is somehow guarantee.
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, user_accept=None, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_NOT_SET

    # Check get assertion request behavior with zero length pinAuth
    t = ctap2_get_assertion(client)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]

    # DEVIATION from FIDO2.0 spec: If platform sends zero length pinAuth,
    # authenticator needs to wait for user touch and then returns [...]"
    # Impact is minor because user as still manually unlocked it's device.
    # therefore user presence is somehow guarantee.
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                   allow_list,
                                   pin_uv_param=b"",
                                   pin_uv_protocol=client.client_pin.protocol.VERSION,
                                   user_accept=None,
                                   will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_NOT_SET


def test_client_pin_check_set(client):
    info = client.ctap2.info
    # Value depends on if a pin as been set.
    # Upon boot, pin is never set as we don't have NVM
    assert not info.options["clientPin"]

    client.client_pin.set_pin(PIN_A)

    info = client.ctap2.get_info()
    assert info.options["clientPin"]

    assert client.client_pin.get_pin_retries() == (8, None)

    client.client_pin.get_pin_token(PIN_A)

    with pytest.raises(CtapError) as e:
        client.client_pin.set_pin(PIN_A)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    client.client_pin.change_pin(PIN_A, PIN_B)

    client.client_pin.get_pin_token(PIN_B)

    # Check make credential request behavior with zero length pinAuth
    args = generate_make_credentials_params(client, pin_uv_param=b"")

    # DEVIATION from FIDO2.0 spec: If platform sends zero length pinAuth,
    # authenticator needs to wait for user touch and then returns [...]"
    # Impact is minor because user as still manually unlocked it's device.
    # therefore user presence is somehow guarantee.
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, user_accept=None, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_INVALID

    # Check get assertion request behavior with zero length pinAuth
    t = ctap2_get_assertion(client, pin=PIN_B)

    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]

    # DEVIATION from FIDO2.0 spec: "If platform sends zero length pinAuth,
    # authenticator needs to wait for user touch and then returns [...]"
    # Impact is minor because user as still manually unlocked it's device.
    # therefore user presence is somehow guarantee.
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"],
                                   client_data_hash,
                                   allow_list,
                                   pin_uv_param=b"",
                                   pin_uv_protocol=client.client_pin.protocol.VERSION,
                                   user_accept=None,
                                   will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_INVALID


def test_use_pin(client):
    client.client_pin.set_pin(PIN_A)

    # Check can't get token with bad pin
    with pytest.raises(CtapError) as e:
        token = client.client_pin.get_pin_token(PIN_B)
    assert e.value.code == CtapError.ERR.PIN_INVALID
    assert client.client_pin.get_pin_retries() == (7, None)

    # Get pin token
    token = client.client_pin.get_pin_token(PIN_A)
    assert client.client_pin.get_pin_retries() == (8, None)

    args = generate_make_credentials_params(client)
    pin_auth = client.client_pin.protocol.authenticate(token, args.client_data_hash)

    # Create a bad pin auth using a bad token
    bad_token = bytearray(token)
    bad_token[0] ^= 0x40
    bad_token = bytes(bad_token)
    bad_pin_auth = client.client_pin.protocol.authenticate(bad_token, args.client_data_hash)

    # Check should use pin
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, user_accept=None, will_fail=True)
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED

    # Check should use correct token
    with pytest.raises(CtapError) as e:
        args.pin_uv_param = bad_pin_auth
        args.pin_uv_protocol = client.client_pin.protocol.VERSION
        client.ctap2.make_credential(args, user_accept=None)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Check should use correct protocol
    with pytest.raises(CtapError) as e:
        args.pin_uv_param = pin_auth
        args.pin_uv_protocol = PinProtocolV2.VERSION
        client.ctap2.make_credential(args, user_accept=None)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Using a bad token doesn't affect pin_retries
    assert client.client_pin.get_pin_retries() == (8, None)

    args.pin_uv_param = pin_auth
    args.pin_uv_protocol = client.client_pin.protocol.VERSION
    attestation = client.ctap2.make_credential(args)
    assert attestation.auth_data.flags & AuthenticatorData.FLAG.USER_PRESENT
    assert attestation.auth_data.flags & AuthenticatorData.FLAG.USER_VERIFIED

    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    pin_auth = client.client_pin.protocol.authenticate(token, client_data_hash)
    bad_pin_auth = client.client_pin.protocol.authenticate(bad_token, client_data_hash)

    # Check without using pin
    assertion = client.ctap2.get_assertion(args.rp["id"], client_data_hash, allow_list)
    assert assertion.auth_data.flags & AuthenticatorData.FLAG.USER_PRESENT
    assert not assertion.auth_data.flags & AuthenticatorData.FLAG.USER_VERIFIED

    # Check should use correct token
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(args.rp["id"], client_data_hash, allow_list,
                                   pin_uv_param=bad_pin_auth,
                                   pin_uv_protocol=client.client_pin.protocol.VERSION,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Check should use correct protocol
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(args.rp["id"], client_data_hash, allow_list,
                                   pin_uv_param=pin_auth,
                                   pin_uv_protocol=PinProtocolV2.VERSION,
                                   user_accept=None)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Check with pin
    assertion = client.ctap2.get_assertion(args.rp["id"], client_data_hash, allow_list,
                                           pin_uv_param=pin_auth,
                                           pin_uv_protocol=client.client_pin.protocol.VERSION)
    assert assertion.auth_data.flags & AuthenticatorData.FLAG.USER_PRESENT
    assert assertion.auth_data.flags & AuthenticatorData.FLAG.USER_VERIFIED

    assertion.verify(client_data_hash, credential_data.public_key)


def test_client_pin_unique_token(client):
    client.client_pin.set_pin(PIN_A)

    # Generate a first token
    token_a = client.client_pin.get_pin_token(PIN_A)

    # Check that token is working
    args = generate_make_credentials_params(client, pin_uv_param=b"")
    args.pin_uv_param = client.client_pin.protocol.authenticate(token_a, args.client_data_hash)

    client.ctap2.make_credential(args)

    # Generate a second token
    token_b = client.client_pin.get_pin_token(PIN_A)
    assert token_a != token_b

    # Check that first token can't be used anymore
    # Spec says:
    # "Authenticator also can expire pinToken based on certain conditions like
    # changing a PIN, timeout happening on authenticator, machine waking up
    # from a suspend state etc. If pinToken has expired, authenticator will return
    # CTAP2_ERR_PIN_TOKEN_EXPIRED and platform can act on the error accordingly."
    # we are considering that this specific error must be answered only when
    # the token expired due to timeout, which don't occurs on our devices.
    args = generate_make_credentials_params(client, pin_uv_param=b"")
    args.pin_uv_param = client.client_pin.protocol.authenticate(token_a, args.client_data_hash)
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, user_accept=None)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Check that second token can be used to validate the same request
    args.pin_uv_param = client.client_pin.protocol.authenticate(token_b, args.client_data_hash)
    client.ctap2.make_credential(args)


def test_client_pin_block(client):
    client.client_pin.set_pin(PIN_A)
    assert client.client_pin.get_pin_retries()[0] == 8

    for i in range(1, 10):
        err = CtapError.ERR.PIN_INVALID
        if i >= 3:
            err = CtapError.ERR.PIN_AUTH_BLOCKED

        with pytest.raises(CtapError) as e:
            ctap2_get_assertion(client, pin=PIN_B)
        assert e.value.code == err

        retries = 8 - i
        if i > 3:
            retries = 8 - 3

        assert client.client_pin.get_pin_retries()[0] == retries

    # Would be nice to test with device reboot too, but client.simulate_reboot()
    # doesn't keep NVM data.
    # Therefore we can't test the behavior:
    # - that retries counter doesn't restart upon reboot.
    # - that when retries counter reach 0, the return code is
    #   CTAP2_ERR_PIN_BLOCKED.


def test_client_pin_set_errors(client):
    with pytest.raises(CtapError) as e:
        client.client_pin.set_pin("A" * 64)
    assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

    with pytest.raises(CtapError) as e:
        # Do not use set_pin() to avoid _pad_pin() length check
        pin = "A" * 3
        pin_padded = pin.encode().ljust(64, b"\0")
        pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)
        key_agreement, shared_secret = client.client_pin._get_shared_secret()
        pin_enc = client.client_pin.protocol.encrypt(shared_secret, pin_padded)
        pin_uv_param = client.client_pin.protocol.authenticate(shared_secret, pin_enc)
        client.client_pin.ctap.client_pin(
            client.client_pin.protocol.VERSION,
            ClientPin.CMD.SET_PIN,
            key_agreement=key_agreement,
            new_pin_enc=pin_enc,
            pin_uv_param=pin_uv_param,
        )
    assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION


@pytest.mark.skip_endpoint("NFC", reason="CTAP2 reset is not available on NFC - 0x27")
def test_client_pin_reset(client):
    info = client.ctap2.info
    # Value depends on if a pin as been set.
    # Upon boot, pin is never set as we don't have NVM
    assert not info.options["clientPin"]

    # Set pin and validate it has been set
    client.client_pin.set_pin(PIN_A)

    info = client.ctap2.get_info()
    assert info.options["clientPin"]

    assert client.client_pin.get_pin_retries() == (8, None)

    client.client_pin.get_pin_token(PIN_A)

    # Reset device and check pin is not set anymore
    client.ctap2.reset()

    info = client.ctap2.get_info()
    assert not info.options["clientPin"]

    with pytest.raises(CtapError) as e:
        client.client_pin.get_pin_retries()
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


@pytest.mark.skip_endpoint("NFC", reason="CTAP2 reset is not available on NFC - 0x27")
def test_client_pin_blocked_reset(client):
    # Set pin and validate it has been set
    client.client_pin.set_pin(PIN_A)
    client.client_pin.get_pin_token(PIN_A)

    # block the pin
    for i in range(1, 4):
        err = CtapError.ERR.PIN_INVALID
        if i >= 3:
            err = CtapError.ERR.PIN_AUTH_BLOCKED

        with pytest.raises(CtapError) as e:
            ctap2_get_assertion(client, pin=PIN_B)
        assert e.value.code == err

    # Reset device and check pin is not set anymore
    # and not blocked anymore
    client.ctap2.reset()

    info = client.ctap2.get_info()
    assert not info.options["clientPin"]

    with pytest.raises(CtapError) as e:
        client.client_pin.get_pin_retries()
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Set pin and validate it has been set
    client.client_pin.set_pin(PIN_A)
    client.client_pin.get_pin_token(PIN_A)


# Todo
# If NVM feature is implemented using this framework, some test should be added
# which would test the behavior upon reboot (pin saved, token regenerated,...)
