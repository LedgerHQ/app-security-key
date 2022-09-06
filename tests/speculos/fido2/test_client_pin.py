import pytest

from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from utils import generate_random_bytes, generate_make_credentials_params
from utils import generate_get_assertion_params, fido_known_app


PIN_A = "aaaa"
PIN_B = "bbbb"


def test_client_pin_check_version(client):
    assert client.ctap2.info.pin_uv_protocols == [PinProtocolV2.VERSION, PinProtocolV1.VERSION]
    assert client.client_pin_v1.protocol.VERSION == PinProtocolV1.VERSION
    assert client.client_pin_v2.protocol.VERSION == PinProtocolV2.VERSION


def test_client_pin_test_bad_protocol(client):
    with pytest.raises(CtapError) as e:
        client.ctap2.client_pin(3, ClientPin.CMD.GET_PIN_RETRIES)
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER

    # Reset device for next tests
    client.ctap2.reset()


def test_client_pin_check_not_set(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        info = client.ctap2.info
        # Value depends on if a pin as been set.
        # Upon boot, pin is never set as we don't have NVM
        assert not info.options["clientPin"]

        with pytest.raises(CtapError) as e:
            client_pin.get_pin_retries()
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            client_pin.change_pin(PIN_A, PIN_B)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            client_pin.get_pin_token(PIN_A, user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Check uv token can be retrieved
        client_pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL)

        # Check make credential request behavior with zero length pinAuth
        # Spec require:
        # "If platform sends zero length pinAuth, authenticator needs to wait for
        # user touch and then returns either CTAP2_ERR_PIN_NOT_SET if pin is not
        # set or CTAP2_ERR_PIN_INVALID if pin has been set."
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        pin_auth = b""
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=True)
        assert e.value.code == CtapError.ERR.PIN_NOT_SET

        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=False)
        assert e.value.code == CtapError.ERR.OPERATION_DENIED

        # Check get assertion request behavior with zero length pinAuth
        # Spec require:
        # "If platform sends zero length pinAuth, authenticator needs to wait for
        # user touch and then returns either CTAP2_ERR_PIN_NOT_SET if pin is not
        # set or CTAP2_ERR_PIN_INVALID if pin has been set."
        rp, credential_data, _ = generate_get_assertion_params(client)

        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash,
                                       allow_list,
                                       pin_uv_param=pin_auth,
                                       pin_uv_protocol=client_pin.protocol.VERSION,
                                       user_accept=True)
        assert e.value.code == CtapError.ERR.PIN_NOT_SET

        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash,
                                       allow_list,
                                       pin_uv_param=pin_auth,
                                       pin_uv_protocol=client_pin.protocol.VERSION,
                                       user_accept=False)
        assert e.value.code == CtapError.ERR.OPERATION_DENIED

        # Reset device for next tests
        client.ctap2.reset()


def test_client_pin_check_set(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        info = client.ctap2.info
        # Value depends on if a pin as been set.
        # Upon boot, pin is never set as we don't have NVM
        assert not info.options["clientPin"]

        client_pin.set_pin(PIN_A)

        info = client.ctap2.get_info()
        assert info.options["clientPin"]

        assert client_pin.get_pin_retries() == (8, None)

        client_pin.get_pin_token(PIN_A)

        with pytest.raises(CtapError) as e:
            client_pin.set_pin(PIN_A)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        client_pin.change_pin(PIN_A, PIN_B)

        client_pin.get_pin_token(PIN_B)

        # Check uv token can be retrieved
        client_pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL)

        # Check make credential request behavior with zero length pinAuth
        # Spec require:
        # "If platform sends zero length pinAuth, authenticator needs to wait for
        # user touch and then returns either CTAP2_ERR_PIN_NOT_SET if pin is not
        # set or CTAP2_ERR_PIN_INVALID if pin has been set."
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        pin_auth = b""
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=True)
        assert e.value.code == CtapError.ERR.PIN_INVALID

        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=False)
        assert e.value.code == CtapError.ERR.OPERATION_DENIED

        # Check get assertion request behavior with zero length pinAuth
        # Spec require:
        # "If platform sends zero length pinAuth, authenticator needs to wait for
        # user touch and then returns either CTAP2_ERR_PIN_NOT_SET if pin is not
        # set or CTAP2_ERR_PIN_INVALID if pin has been set."
        rp, credential_data, _ = generate_get_assertion_params(client, pin=PIN_B)

        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash,
                                       allow_list,
                                       pin_uv_param=pin_auth,
                                       pin_uv_protocol=client_pin.protocol.VERSION,
                                       user_accept=True)
        assert e.value.code == CtapError.ERR.PIN_INVALID

        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash,
                                       allow_list,
                                       pin_uv_param=pin_auth,
                                       pin_uv_protocol=client_pin.protocol.VERSION,
                                       user_accept=False)
        assert e.value.code == CtapError.ERR.OPERATION_DENIED

        # Reset device for next tests
        client.ctap2.reset()


def test_get_uv_token(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        for pin_set in [False, True]:
            if pin_set:
                client_pin.set_pin(PIN_A)

        # Check user can refuse to grant permissions
        with pytest.raises(CtapError) as e:
            client_pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL,
                                    user_accept=False, check_screens=True)
        assert e.value.code == CtapError.ERR.OPERATION_DENIED

        # Check uv token can be retrieved with and without pin set
        client_pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL,
                                check_screens=True)

        # Check invalid permissions are handled
        for perms in [-1, 0, 0x40, 0x43, 0x83, 0x4512]:
            with pytest.raises(CtapError) as e:
                client_pin.get_uv_token(perms, user_accept=None)
            assert e.value.code == CtapError.ERR.INVALID_PARAMETER

        # Check unauthorized permissions are handled
        for perms in [ClientPin.PERMISSION.CREDENTIAL_MGMT,
                      ClientPin.PERMISSION.BIO_ENROLL,
                      ClientPin.PERMISSION.LARGE_BLOB_WRITE,
                      ClientPin.PERMISSION.AUTHENTICATOR_CFG]:
            with pytest.raises(CtapError) as e:
                client_pin.get_uv_token(perms, user_accept=None)
            assert e.value.code == CtapError.ERR.UNAUTHORIZED_PERMISSION

        # Check RP_ID is correctly displayed
        if not client.ctap2_u2f_proxy:
            for rp_id in [list(fido_known_app.keys())[0],
                          list(fido_known_app.keys())[0] + ".scam"]:
                rp = {"id": rp_id}
                token = client_pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL,
                                                rp_id, check_screens=True)

        # Check RP_ID is correctly handled
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        token = client_pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL,
                                        rp["id"])
        pin_auth = client_pin.protocol.authenticate(token, client_data_hash)

        bad_rp = {"id": rp["id"] + ".scam"}
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         bad_rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Check token can still be used with correct RP)
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     pin_uv_param=pin_auth,
                                     pin_uv_protocol=client_pin.protocol.VERSION)

        # Check token can't be reused (Permission lost)
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Check permission are checked
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        token = client_pin.get_uv_token(ClientPin.PERMISSION.GET_ASSERTION,
                                        rp["id"])
        pin_auth = client_pin.protocol.authenticate(token, client_data_hash)
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Reset device for next tests
        client.ctap2.reset()


def test_use_pin(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        client_pin.set_pin(PIN_A)

        # Check can't get token with bad pin
        with pytest.raises(CtapError) as e:
            token = client_pin.get_pin_token(PIN_B, user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_INVALID
        assert client_pin.get_pin_retries() == (7, None)

        # Get pin token
        token = client_pin.get_pin_token(PIN_A)
        assert client_pin.get_pin_retries() == (8, None)

        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        pin_auth = client_pin.protocol.authenticate(token, client_data_hash)

        # Create a bad pin auth using a bad token
        bad_token = bytearray(token)
        bad_token[0] ^= 0x40
        bad_token = bytes(bad_token)
        bad_pin_auth = client_pin.protocol.authenticate(bad_token, client_data_hash)

        # Check should use correct token
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=bad_pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Check should use correct protocol
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=3,
                                         user_accept=None)
        assert e.value.code == CtapError.ERR.INVALID_PARAMETER

        # Using a bad token doesn't affect pin_retries
        assert client_pin.get_pin_retries() == (8, None)

        attestation = client.ctap2.make_credential(client_data_hash,
                                                   rp,
                                                   user,
                                                   key_params,
                                                   pin_uv_param=pin_auth,
                                                   pin_uv_protocol=client_pin.protocol.VERSION)
        assert attestation.auth_data.flags & AuthenticatorData.FLAG.USER_PRESENT
        assert attestation.auth_data.flags & AuthenticatorData.FLAG.USER_VERIFIED

        credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]

        # Check without using pin
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list)
        assert assertion.auth_data.flags & AuthenticatorData.FLAG.USER_PRESENT
        assert not assertion.auth_data.flags & AuthenticatorData.FLAG.USER_VERIFIED

        # Retrieve a new token as previous one lost permission after use and last get_assertion call
        token = client_pin.get_pin_token(PIN_A)
        pin_auth = client_pin.protocol.authenticate(token, client_data_hash)
        bad_pin_auth = client_pin.protocol.authenticate(bad_token, client_data_hash)

        # Check should use correct token
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                       pin_uv_param=bad_pin_auth,
                                       pin_uv_protocol=client_pin.protocol.VERSION,
                                       user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Check should use correct protocol
        with pytest.raises(CtapError) as e:
            client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                       pin_uv_param=pin_auth,
                                       pin_uv_protocol=3,
                                       user_accept=None)
        assert e.value.code == CtapError.ERR.INVALID_PARAMETER

        # Check with pin
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list,
                                               pin_uv_param=pin_auth,
                                               pin_uv_protocol=client_pin.protocol.VERSION)
        assert assertion.auth_data.flags & AuthenticatorData.FLAG.USER_PRESENT
        assert assertion.auth_data.flags & AuthenticatorData.FLAG.USER_VERIFIED

        assertion.verify(client_data_hash, credential_data.public_key)

        # Reset device for next tests
        client.ctap2.reset()


def test_client_pin_unique_token(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        client_pin.set_pin(PIN_A)

        # Generate a first token
        token_a = client_pin.get_pin_token(PIN_A)

        # Check that token is working
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        pin_auth = client_pin.protocol.authenticate(token_a, client_data_hash)

        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     pin_uv_param=pin_auth,
                                     pin_uv_protocol=client_pin.protocol.VERSION)

        # Generate a second token
        token_b = client_pin.get_pin_token(PIN_A)
        assert token_a != token_b

        # Check that first token can't be used anymore
        # Spec says:
        # "Authenticator also can expire pinToken based on certain conditions like
        # changing a PIN, timeout happening on authenticator, machine waking up
        # from a suspend state etc. If pinToken has expired, authenticator will return
        # CTAP2_ERR_PIN_TOKEN_EXPIRED and platform can act on the error accordingly."
        # we are considering that this specific error must be answered only when
        # the token expired due to timeout, which don't occurs on our devices.
        client_data_hash, rp, user, key_params = generate_make_credentials_params()
        pin_auth = client_pin.protocol.authenticate(token_a, client_data_hash)
        with pytest.raises(CtapError) as e:
            client.ctap2.make_credential(client_data_hash,
                                         rp,
                                         user,
                                         key_params,
                                         pin_uv_param=pin_auth,
                                         pin_uv_protocol=client_pin.protocol.VERSION,
                                         user_accept=None)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Check that second token can be used to validate the same request
        pin_auth = client_pin.protocol.authenticate(token_b, client_data_hash)
        client.ctap2.make_credential(client_data_hash,
                                     rp,
                                     user,
                                     key_params,
                                     pin_uv_param=pin_auth,
                                     pin_uv_protocol=client_pin.protocol.VERSION)

        # Reset device for next tests
        client.ctap2.reset()


def test_client_pin_block(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        client_pin.set_pin(PIN_A)
        assert client_pin.get_pin_retries()[0] == 8

        for i in range(1, 10):
            err = CtapError.ERR.PIN_INVALID
            if i >= 3:
                err = CtapError.ERR.PIN_AUTH_BLOCKED

            with pytest.raises(CtapError) as e:
                client_pin.get_pin_token(pin=PIN_B, user_accept=None)
            assert e.value.code == err

            retries = 8 - i
            if i > 3:
                retries = 8 - 3

            assert client_pin.get_pin_retries()[0] == retries

        # Would be nice to test with device reboot too, but client.simulate_reboot()
        # doesn't keep NVM data.
        # Therefore we can't test the behavior:
        # - that retries counter doesn't restart upon reboot.
        # - that when retries counter reach 0, the return code is
        #   CTAP2_ERR_PIN_BLOCKED.

        # Reset device for next tests
        client.ctap2.reset()


def test_client_pin_set_errors(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        with pytest.raises(CtapError) as e:
            client_pin.set_pin("A" * 64)
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

        with pytest.raises(CtapError) as e:
            # Do not use set_pin() to avoid _pad_pin() length check
            pin = "A" * 3
            pin_padded = pin.encode().ljust(64, b"\0")
            pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)
            key_agreement, shared_secret = client_pin._get_shared_secret()
            pin_enc = client_pin.protocol.encrypt(shared_secret, pin_padded)
            pin_uv_param = client_pin.protocol.authenticate(shared_secret, pin_enc)
            client_pin.ctap.client_pin(
                client_pin.protocol.VERSION,
                ClientPin.CMD.SET_PIN,
                key_agreement=key_agreement,
                new_pin_enc=pin_enc,
                pin_uv_param=pin_uv_param,
            )
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

        # Reset device for next tests
        client.ctap2.reset()


def test_client_pin_reset(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        info = client.ctap2.info
        # Value depends on if a pin as been set.
        # Upon boot, pin is never set as we don't have NVM
        assert not info.options["clientPin"]

        # Set pin and validate it has been set
        client_pin.set_pin(PIN_A)

        info = client.ctap2.get_info()
        assert info.options["clientPin"]

        assert client_pin.get_pin_retries() == (8, None)

        client_pin.get_pin_token(PIN_A)

        # Reset device and check pin is not set anymore
        client.ctap2.reset()

        info = client.ctap2.get_info()
        assert not info.options["clientPin"]

        with pytest.raises(CtapError) as e:
            client_pin.get_pin_retries()
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Reset device for next tests
        client.ctap2.reset()


def test_client_pin_blocked_reset(client):
    for client_pin in [client.client_pin_v1, client.client_pin_v2]:
        # Set pin and validate it has been set
        client_pin.set_pin(PIN_A)
        client_pin.get_pin_token(PIN_A)

        # block the pin
        for i in range(1, 4):
            err = CtapError.ERR.PIN_INVALID
            if i >= 3:
                err = CtapError.ERR.PIN_AUTH_BLOCKED

            with pytest.raises(CtapError) as e:
                generate_get_assertion_params(client, pin=PIN_B)
            assert e.value.code == err

        # Reset device and check pin is not set anymore
        # and not blocked anymore
        client.ctap2.reset()

        info = client.ctap2.get_info()
        assert not info.options["clientPin"]

        with pytest.raises(CtapError) as e:
            client_pin.get_pin_retries()
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # Set pin and validate it has been set
        client_pin.set_pin(PIN_A)
        client_pin.get_pin_token(PIN_A)

        # Reset device for next tests
        client.ctap2.reset()

# Todo:
# - If NVM feature is implemented using this framework, some test should be added
#   which would test the behavior upon reboot (pin saved, token regenerated,...)
# - Test pinAuth timers
