import struct
import time

from typing import Mapping

from ragger.navigator import NavInsID, NavIns

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2.base import Ctap2, args, AttestationResponse, AssertionResponse
from fido2.ctap2.pin import ClientPin
from fido2.hid import CTAPHID
from fido2.utils import sha256

from ctap1_client import APDU
from utils import get_rp_id_hash, fido_known_appid, prepare_apdu
from screen_size_utils import get_message_nb_screen


class LedgerCtap2(Ctap2):
    """ Overriding fido2.ctap2.base.Ctap2

    This is mostly to allow to interact with the screen and the buttons
    during command exchange.
    To do so, send_cbor_nowait as been introduced.
    Then, make_credential(), get_assertion() and reset() Ctap2 functions are
    overridden to add interactions with the screen and the buttons.

    This class also add the capability to choose between sending FIDO2 commands:
    - directly in CTAPHID.CBOR command
    - encapsulated in U2F APDU with INS=0x10 in CTAPHID.MSG command
    """
    def __init__(self, device, model, navigator, ctap2_u2f_proxy, debug=False):
        self.model = model
        self.navigator = navigator
        self.ctap2_u2f_proxy = ctap2_u2f_proxy
        self.debug = debug
        super().__init__(device)

    def confirm(self):
        instructions = [NavIns(NavInsID.BOTH_CLICK)]
        self.navigator.navigate(instructions)

    def send_cbor_nowait(self, cmd, data=None, *, event=None, on_keepalive=None):
        request = struct.pack(">B", cmd)
        if data is not None:
            request += cbor.encode(data)

        if self.ctap2_u2f_proxy:
            # Encapsulate the cbor message in an APDU with INS=0x10
            request = prepare_apdu(ins=0x10, data=request)
            ctaphid_cmd = CTAPHID.MSG
        else:
            ctaphid_cmd = CTAPHID.CBOR

        self.device.send(ctaphid_cmd, request)
        return ctaphid_cmd

    def send_cbor(self, cmd, data=None, *, event=None, on_keepalive=None):
        ctaphid_cmd = self.send_cbor_nowait(cmd, data=data, event=event,
                                            on_keepalive=on_keepalive)
        response = self.device.recv(ctaphid_cmd)
        return self.parse_response(response)

    def parse_response(self, response):
        status = response[0]
        if status != 0x00:
            raise CtapError(status)

        response = response[1:]

        if self.ctap2_u2f_proxy:
            # Retrieve APDU encapsulation status code
            status = struct.unpack(">H", response[-2:])[0]
            response = response[:-2]
            try:
                status = APDU(status)
            except ValueError:
                pass

            # Check the status code which should always be APDU.SW_NO_ERROR
            if status != APDU.SW_NO_ERROR:
                raise ApduError(status, response)

        if not response:
            return {}

        decoded = cbor.decode(response)
        if self._strict_cbor:
            # Check that cbor message encoding is canonical
            expected = cbor.encode(decoded)
            if expected != response:
                raise ValueError(
                    "Non-canonical CBOR from Authenticator.\n"
                    f"Got: {response.hex()}\nExpected: {expected.hex()}"
                )
        if isinstance(decoded, Mapping):
            return decoded
        raise TypeError("Decoded value of wrong type")

    def get_user_screen_instructions(self, user):
        if "displayName" in user:
            nb = get_message_nb_screen(self.model, user["displayName"][:64])
        elif "name" in user:
            nb = get_message_nb_screen(self.model, user["name"][:64])
        elif "id" in user:
            nb = get_message_nb_screen(self.model, user["id"].hex().upper()[:64])

        return [NavIns(NavInsID.RIGHT_CLICK)] * nb

    def get_domain_screen_instructions(self, rp_id):
        rp_id_hash = get_rp_id_hash(rp_id)
        if rp_id_hash in fido_known_appid:
            nb = get_message_nb_screen(self.model, fido_known_appid[rp_id_hash])
        else:
            nb = get_message_nb_screen(self.model, rp_id)
        return [NavIns(NavInsID.RIGHT_CLICK)] * nb

    def make_credential(self, client_data_hash, rp, user, key_params,
                        exclude_list=None, extensions=None, options=None,
                        pin_uv_param=None, pin_uv_protocol=None,
                        enterprise_attestation=None, *, event=None,
                        on_keepalive=None, user_accept=True,
                        check_screens=None, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
        time.sleep(0.1)
        self.navigator._backend.get_current_screen_content()

        cmd = Ctap2.CMD.MAKE_CREDENTIAL
        data = args(client_data_hash,
                    rp,
                    user,
                    key_params,
                    exclude_list,
                    extensions,
                    options,
                    pin_uv_param,
                    pin_uv_protocol,
                    enterprise_attestation)
        ctap_hid_cmd = self.send_cbor_nowait(cmd, data, event=event,
                                             on_keepalive=on_keepalive)

        if pin_uv_param == b"":
            # This parameter leads to authenticator selection flow
            return self.selection(user_accept=user_accept, cmd_sent=ctap_hid_cmd)

        instructions = []

        if options and options.get("rk", False):
            expected_0 = "Register local\nFIDO 2"
        else:
            expected_0 = "Register\nFIDO 2"

        if user_accept and check_screens is None:
            # Still give time for screen thread to parse screens
            # Also this make sure the device doesn't receive the button press event
            # before launching the UI Flow.
            time.sleep(0.1)

            # Validate blindly
            instructions.append(NavIns(NavInsID.BOTH_CLICK))

        elif user_accept is not None:
            # check_screens == None only supported when user accept
            assert check_screens in ["full", "fast"]

            if options and options.get("rk", False):
                # Check resident key extra step 0bis content
                # Screen 0 -> 0bis
                warning = "This credential will be lost on application reset"
                nb = get_message_nb_screen(self.model, warning)
                instructions += [NavIns(NavInsID.RIGHT_CLICK)] * nb

            # Screen 0 -> 1
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Screen 1 -> 2
            instructions += self.get_domain_screen_instructions(rp["id"])

            # Screen 2 -> 3
            instructions += self.get_user_screen_instructions(user)

            if check_screens == "full":
                # Screen 3 -> 0
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                # Screen 0 -> 3
                instructions.append(NavIns(NavInsID.LEFT_CLICK))

            if user_accept:
                # Screen 3 -> 0
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Validate
            instructions.append(NavIns(NavInsID.BOTH_CLICK))

        elif check_cancel:
            # Screen 0 -> 1
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Home screen don't show before reception
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        else:
            self.navigator.navigate(instructions)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        # TODO check home screen displayed

        response = self.parse_response(response)

        return AttestationResponse.from_dict(response)

    def get_assertion(self, rp_id, client_data_hash, allow_list=None,
                      extensions=None, options=None, pin_uv_param=None,
                      pin_uv_protocol=None, *, event=None, on_keepalive=None,
                      login_type="simple", user_accept=True, check_users=None,
                      check_screens=None, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
        time.sleep(0.1)
        self.navigator._backend.get_current_screen_content()

        assert login_type in ["simple", "multi", "none"]

        cmd = Ctap2.CMD.GET_ASSERTION
        data = args(rp_id,
                    client_data_hash,
                    allow_list,
                    extensions,
                    options,
                    pin_uv_param,
                    pin_uv_protocol)

        ctap_hid_cmd = self.send_cbor_nowait(cmd, data, event=event,
                                             on_keepalive=on_keepalive)

        if pin_uv_param == b"":
            # This parameter leads to authenticator selection flow
            return self.selection(user_accept=user_accept, cmd_sent=ctap_hid_cmd)

        instructions = []
        if user_accept and check_screens is None:
            if login_type == "multi":
                # Go to confirm step
                instructions += [NavIns(NavInsID.LEFT_CLICK)] * 2

            # Validate blindly
            instructions.append(NavIns(NavInsID.BOTH_CLICK))

        elif user_accept is not None:
            # check_screens == None only supported when user accept
            assert check_screens in ["full", "fast"]

            if login_type == "none":
                # Screen 0 -> 1
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                # Screen 1 -> 2
                instructions += self.get_domain_screen_instructions(rp_id)

                # Validate
                instructions.append(NavIns(NavInsID.BOTH_CLICK))

            elif login_type == "multi":
                if len(check_users) == 1:
                    raise ValueError("Found 1 user while expecting multiple")

                # Screen 0 -> 1
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                # Screen 1 -> 2
                instructions += self.get_domain_screen_instructions(rp_id)

                for user in check_users:
                    # Screen 2 -> 3
                    instructions += self.get_user_screen_instructions(user)

                    if check_screens == "full":
                        # Screen 3 -> 4
                        instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                        # Screen 4 -> 5
                        instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                        # Screen 5 -> 0
                        instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                        # Screen 0 -> 5
                        instructions.append(NavIns(NavInsID.LEFT_CLICK))

                        # Go back to "Next User" (5 -> 4 -> 3) screen
                        instructions.append(NavIns(NavInsID.LEFT_CLICK))
                        instructions.append(NavIns(NavInsID.LEFT_CLICK))

                    # Validate
                    instructions.append(NavIns(NavInsID.BOTH_CLICK))

                    # Upon confirmation, the flow is update with the next user
                    # and restarts at screen 2 presenting user data

                # Screen 2 -> 3
                instructions += self.get_user_screen_instructions(check_users[0])

                # Go to "Confirm Login"
                # Screen 3 -> 4
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                if not user_accept:
                    # Go to step 5
                    instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                # Validate
                instructions.append(NavIns(NavInsID.BOTH_CLICK))

            else:
                if len(check_users) != 1:
                    raise ValueError("Found multiple users while expecting 1")

                # Screen 0 -> 1
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                # Screen 1 -> 2
                instructions += self.get_domain_screen_instructions(rp_id)

                # Screen 2 -> 3
                instructions += self.get_user_screen_instructions(check_users[0])

                if check_screens == "full":
                    # Screen 3 -> 0
                    instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                    # Screen 0 -> 3
                    instructions.append(NavIns(NavInsID.LEFT_CLICK))

                if user_accept:
                    # Screen 3 -> 0
                    instructions.append(NavIns(NavInsID.RIGHT_CLICK))

                # Validate
                instructions.append(NavIns(NavInsID.BOTH_CLICK))

        elif check_cancel:
            # Screen 0 -> 1
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Home screen don't show before reception
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        else:
            self.navigator.navigate(instructions)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        # TODO check home screen displayed

        response = self.parse_response(response)

        return AssertionResponse.from_dict(response)

    def get_assertion_with_txSimpleAuth(self, rp_id, client_data_hash, allow_list=None,
                                        extensions=None, options=None, pin_uv_param=None,
                                        pin_uv_protocol=None, *, event=None, on_keepalive=None,
                                        login_type="simple", user_accept=True, check_users=None,
                                        compare_args=None):
        # Refresh navigator screen content reference
        time.sleep(0.1)
        self.navigator._backend.get_current_screen_content()

        assert login_type in ["simple", "multi"]
        """
        Copy of get_assertion() to keep it simpler as the ux is different with txSimpleAuth
        and we don't want to merge he two function as this will create a mess for a somehow
        deprecated extension.
        """

        cmd = Ctap2.CMD.GET_ASSERTION
        data = args(rp_id,
                    client_data_hash,
                    allow_list,
                    extensions,
                    options,
                    pin_uv_param,
                    pin_uv_protocol)

        ctap_hid_cmd = self.send_cbor_nowait(cmd, data, event=event,
                                             on_keepalive=on_keepalive)

        instructions = []
        if user_accept is not None:

            # Screen 0 -> text_flow_0
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Screen text_flow_0 -> 1
            nb = get_message_nb_screen(self.model, extensions["txAuthSimple"])
            instructions += [NavIns(NavInsID.RIGHT_CLICK)] * nb

            # Screen 1 -> 2
            instructions += self.get_domain_screen_instructions(rp_id)

            # Screen 2 -> 3
            instructions += self.get_user_screen_instructions(check_users[0])

            if login_type == "multi":
                # Go to "Confirm" screen
                # Screen 3 -> 4
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            if not user_accept:
                # Go to "Reject" screen
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Validate
            instructions.append(NavIns(NavInsID.BOTH_CLICK))

        assert compare_args
        root, test_name = compare_args
        # Home screen don't show, so split navigation instruction
        # so that we don't have the last snapshot twice.
        self.navigator.navigate_and_compare(root, test_name, instructions[:-1])
        self.navigator.navigate([instructions[-1]])

        response = self.device.recv(ctap_hid_cmd)

        # TODO check home screen displayed

        response = self.parse_response(response)

        return AssertionResponse.from_dict(response)

    def reset(self, *, event=None, on_keepalive=None, validate_step=0,
              check_screens=None, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
        time.sleep(0.1)
        self.navigator._backend.get_current_screen_content()

        ctap_hid_cmd = self.send_cbor_nowait(Ctap2.CMD.RESET, event=event,
                                             on_keepalive=on_keepalive)

        instructions = []
        if validate_step != 3 and check_screens is None:
            # Validate blindly
            instructions.append(NavIns(NavInsID.BOTH_CLICK))

        elif check_cancel:
            # Screen 0 -> 1
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

        else:
            # check_screens == None only supported when user accept
            assert check_screens in ["full", "fast"]

            # Screen 0 -> 1
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Screen 1 -> 2
            warning = "All credentials will be invalidated"
            nb = get_message_nb_screen(self.model, warning)
            instructions += [NavIns(NavInsID.RIGHT_CLICK)] * nb

            # Screen 2 -> 3
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Screen 3 -> 0
            instructions.append(NavIns(NavInsID.RIGHT_CLICK))

            # Screen 0 -> 3
            instructions.append(NavIns(NavInsID.LEFT_CLICK))

            if validate_step == 0:
                # Screen 3 -> 0
                instructions.append(NavIns(NavInsID.RIGHT_CLICK))
            elif validate_step == 2:
                # Screen 3 -> 2
                instructions.append(NavIns(NavInsID.LEFT_CLICK))

            # Confirm
            instructions.append(NavIns(NavInsID.BOTH_CLICK))

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Home screen don't show before reception
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        else:
            self.navigator.navigate(instructions)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        # TODO check home screen displayed

        self.parse_response(response)

    def selection(self, *, event=None, on_keepalive=None, user_accept=True,
                  cmd_sent=None, check_cancel=False):
        if cmd_sent:
            ctap_hid_cmd = cmd_sent
        else:
            ctap_hid_cmd = self.send_cbor_nowait(Ctap2.CMD.SELECTION, event=event,
                                                 on_keepalive=on_keepalive)

        # Check step 0 content
        self.speculos_client.wait_for_screen_text("Device selection\nConfirm")

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")
        else:
            # Go to step 1 and check content
            self.press_and_release("right")
            self.speculos_client.wait_for_screen_text("Device selection\nAbort")

            if user_accept:
                # Loop from step 1 to step 0 and check content
                self.press_and_release("right")
                self.speculos_client.wait_for_screen_text("Device selection\nConfirm")

            # Confirm
            self.press_and_release('both')

        response = self.device.recv(ctap_hid_cmd)

        # Check idle screen
        self.speculos_client.wait_for_screen_text("Ready to\nauthenticate")

        self.parse_response(response)

    def client_pin(self, pin_uv_protocol, sub_cmd, key_agreement=None, pin_uv_param=None,
                   new_pin_enc=None, pin_hash_enc=None, permissions=None,
                   permissions_rpid=None, *, event=None, on_keepalive=None,
                   user_accept=True, check_screens=None):
        cmd = Ctap2.CMD.CLIENT_PIN
        data = args(pin_uv_protocol,
                    sub_cmd,
                    key_agreement,
                    pin_uv_param,
                    new_pin_enc,
                    pin_hash_enc,
                    None,
                    None,
                    permissions,
                    permissions_rpid)

        ctap_hid_cmd = self.send_cbor_nowait(cmd, data, event=event,
                                             on_keepalive=on_keepalive)

        if sub_cmd not in [ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
                           ClientPin.CMD.GET_TOKEN_USING_PIN,
                           ClientPin.CMD.GET_TOKEN_USING_UV]:
            response = self.device.recv(ctap_hid_cmd)
            return self.parse_response(response)

        if user_accept and check_screens is None:
            # Still give time for screen thread to parse screens
            # Also this make sure the device doesn't receive the button press event
            # before launching the UI Flow.
            time.sleep(0.1)

            # Validate blindly
            self.press_and_release("both")

        elif user_accept is not None:

            if sub_cmd == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY:
                expected_screen_perms = "register, login"
            else:
                perms = []
                if permissions & ClientPin.PERMISSION.MAKE_CREDENTIAL:
                    perms.append("register")
                if permissions & ClientPin.PERMISSION.GET_ASSERTION:
                    perms.append("login")
                if permissions & ClientPin.PERMISSION.CREDENTIAL_MGMT:
                    perms.append("manage creds")
                if permissions & ClientPin.PERMISSION.LARGE_BLOB_WRITE:
                    perms.append("write blobs")
                if perms:
                    expected_screen_perms = ", ".join(perms)
                else:
                    expected_screen_perms = ""

            # Check step 0 content
            self.speculos_client.wait_for_screen_text("Grant permissions\nFIDO 2")

            # Go to step 1 and check content
            self.press_and_release("right")
            screen_permissions = self.speculos_client.parse_bnnn_paging_screen("Permissions")
            assert screen_permissions == expected_screen_perms

            # Go to step 2 and check content
            self.press_and_release("right")
            domain_text = self.speculos_client.parse_bnnn_paging_screen("Domain")

            if not permissions_rpid:
                assert domain_text == "All"
            else:
                rp_id_hash = get_rp_id_hash(permissions_rpid)
                if rp_id_hash in fido_known_appid:
                    expected = fido_known_appid[rp_id_hash]
                    if domain_text != expected:
                        raise ValueError("Expecting {} instead of {}".format(
                                         repr(expected), repr(domain_text)))
                else:
                    expected = permissions_rpid
                    if domain_text != expected:
                        raise ValueError("Expecting {} instead of {}".format(
                                         repr(expected), repr(domain_text)))

            # Go to step 3 and check content
            self.press_and_release("right")
            self.speculos_client.wait_for_screen_text("Refuse\npermissions")

            # Loop from step 3 to step 0 and check content
            self.press_and_release("right")
            self.speculos_client.wait_for_screen_text("Grant permissions\nFIDO 2")

            # Loop from step 0 to step 3 and check content
            self.press_and_release("left")
            self.speculos_client.wait_for_screen_text("Refuse\npermissions")

            if user_accept:
                # Go back to step 0
                self.press_and_release("right")
                self.speculos_client.wait_for_screen_text("Grant permissions\nFIDO 2")

            # Confirm
            self.press_and_release('both')

        response = self.device.recv(ctap_hid_cmd)
        return self.parse_response(response)


class LedgerClientPin(ClientPin):
    """ Overriding fido2.ctap2.pin.ClientPin

    This is to allow to add check_screen and user_accept parameters to
    get_pin_token() and get_uv_token() function so that they are forwarded to
    LedgerCtap2().client_pin().
    """
    def get_pin_token(self, pin, permissions=None, permissions_rpid=None,
                      user_accept=True, check_screens=None):
        """ See fido2.ctap2.pin.ClientPin.get_pin_token() for implem explanation """
        key_agreement, shared_secret = self._get_shared_secret()

        pin_hash = sha256(pin.encode())[:16]
        pin_hash_enc = self.protocol.encrypt(shared_secret, pin_hash)

        if self._supports_permissions and permissions:
            cmd = ClientPin.CMD.GET_TOKEN_USING_PIN
        else:
            cmd = ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY
            # Ignore permissions if not supported
            permissions = None
            permissions_rpid = None

        resp = self.ctap.client_pin(
            self.protocol.VERSION,
            cmd,
            key_agreement=key_agreement,
            pin_hash_enc=pin_hash_enc,
            permissions=permissions,
            permissions_rpid=permissions_rpid,
            user_accept=user_accept,
            check_screens=check_screens
        )
        pin_token_enc = resp[ClientPin.RESULT.PIN_UV_TOKEN]
        return self.protocol.validate_token(
            self.protocol.decrypt(shared_secret, pin_token_enc)
        )

    def get_uv_token(self, permissions=None, permissions_rpid=None, event=None,
                     on_keepalive=None, user_accept=True, check_screens=None):
        """ See fido2.ctap2.pin.ClientPin.get_uv_token() for implem explanation """
        if not self.ctap.info.options.get("pinUvAuthToken"):
            raise ValueError("Authenticator does not support get_uv_token")

        key_agreement, shared_secret = self._get_shared_secret()

        resp = self.ctap.client_pin(
            self.protocol.VERSION,
            ClientPin.CMD.GET_TOKEN_USING_UV,
            key_agreement=key_agreement,
            permissions=permissions,
            permissions_rpid=permissions_rpid,
            event=event,
            on_keepalive=on_keepalive,
            user_accept=user_accept,
            check_screens=check_screens
        )

        pin_token_enc = resp[ClientPin.RESULT.PIN_UV_TOKEN]
        return self.protocol.validate_token(
            self.protocol.decrypt(shared_secret, pin_token_enc)
        )
