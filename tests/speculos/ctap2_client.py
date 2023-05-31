import struct

from typing import Mapping

from ragger.navigator import NavInsID

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2.base import Ctap2, args, AttestationResponse, AssertionResponse
from fido2.hid import CTAPHID

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
        instructions = [NavInsID.BOTH_CLICK]
        self.navigator.navigate(instructions,
                                screen_change_after_last_instruction=False)

    def wait_for_return_on_dashboard(self):
        self.navigator._backend.wait_for_home_screen()

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

        return [NavInsID.RIGHT_CLICK] * nb

    def get_domain_screen_instructions(self, rp_id):
        rp_id_hash = get_rp_id_hash(rp_id)
        if rp_id_hash in fido_known_appid:
            nb = get_message_nb_screen(self.model, fido_known_appid[rp_id_hash])
        else:
            nb = get_message_nb_screen(self.model, rp_id)
        return [NavInsID.RIGHT_CLICK] * nb

    def make_credential(self, client_data_hash, rp, user, key_params,
                        exclude_list=None, extensions=None, options=None,
                        pin_uv_param=None, pin_uv_protocol=None,
                        enterprise_attestation=None, *, event=None,
                        on_keepalive=None, user_accept=True,
                        check_screens=None, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
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

        rk = False
        if options and options.get("rk", False):
            rk = True

        instructions = []
        if user_accept is not None:
            if rk:
                # Check resident key extra step 0bis content
                # Screen 0 -> 0bis
                instructions.append(NavInsID.RIGHT_CLICK)

            # Screen 0 -> 1
            instructions.append(NavInsID.RIGHT_CLICK)

            # Screen 1 -> 2
            instructions += self.get_domain_screen_instructions(rp["id"])

            # Screen 2 -> 3
            instructions += self.get_user_screen_instructions(user)

            if rk:
                if user_accept:
                    # Screen 3 -> 4
                    instructions.append(NavInsID.RIGHT_CLICK)

            elif not user_accept:
                # Screen 3 -> 4
                instructions.append(NavInsID.RIGHT_CLICK)

            # Validate
            instructions.append(NavInsID.BOTH_CLICK)

        elif check_cancel:
            # Screen 0 -> 1
            instructions.append(NavInsID.RIGHT_CLICK)

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Over U2F endpoint (but not over HID) the device needs the
            # response to be retrieved before continuing the UX flow.
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        elif instructions:
            self.navigator.navigate(instructions,
                                    screen_change_after_last_instruction=False)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        if user_accept is not None:
            self.wait_for_return_on_dashboard()

        response = self.parse_response(response)

        return AttestationResponse.from_dict(response)

    def get_assertion(self, rp_id, client_data_hash, allow_list=None,
                      extensions=None, options=None, pin_uv_param=None,
                      pin_uv_protocol=None, *, event=None, on_keepalive=None,
                      login_type="simple", user_accept=True, check_users=None,
                      check_screens=None, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        assert login_type in ["simple", "multi", "none"]

        TAG_RESP_CREDENTIAL = 0x01

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
        if user_accept and check_screens is None and login_type not in ["none", "multi"]:
            # Validate blindly
            instructions.append(NavInsID.BOTH_CLICK)

        elif user_accept is not None:
            if login_type == "none":
                # Screen 0 -> 1
                instructions.append(NavInsID.RIGHT_CLICK)

                # Screen 1 -> 2
                instructions += self.get_domain_screen_instructions(rp_id)

                # Validate
                instructions.append(NavInsID.BOTH_CLICK)

            elif login_type == "multi":
                if len(check_users) == 1:
                    raise ValueError("Found 1 user while expecting multiple")

                # Screen 0 -> 1
                instructions.append(NavInsID.RIGHT_CLICK)

                # Screen 1 -> 2
                instructions += self.get_domain_screen_instructions(rp_id)

                for user in check_users:
                    # Screen 2 -> 3
                    instructions += self.get_user_screen_instructions(user)

                    # Validate
                    instructions.append(NavInsID.BOTH_CLICK)

                    # Upon confirmation, the flow is update with the next user
                    # and restarts at screen 2 presenting user data

                # Screen 2 -> 3
                instructions += self.get_user_screen_instructions(check_users[0])

                # Go to "Confirm Login"
                # Screen 3 -> 4
                instructions.append(NavInsID.RIGHT_CLICK)

                if not user_accept:
                    # Go to step 5
                    instructions.append(NavInsID.RIGHT_CLICK)

                # Validate
                instructions.append(NavInsID.BOTH_CLICK)

            else:
                if len(check_users) != 1:
                    raise ValueError("Found multiple users while expecting 1")

                # Screen 0 -> 1
                instructions.append(NavInsID.RIGHT_CLICK)

                # Screen 1 -> 2
                instructions += self.get_domain_screen_instructions(rp_id)

                # Screen 2 -> 3
                instructions += self.get_user_screen_instructions(check_users[0])

                if not user_accept:
                    # Screen 3 -> 4
                    instructions.append(NavInsID.RIGHT_CLICK)

                # Validate
                instructions.append(NavInsID.BOTH_CLICK)

        elif check_cancel:
            # Screen 0 -> 1
            instructions.append(NavInsID.RIGHT_CLICK)

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Over U2F endpoint (but not over HID) the device needs the
            # response to be retrieved before continuing the UX flow.
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        elif instructions:
            self.navigator.navigate(instructions,
                                    screen_change_after_last_instruction=False)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        if user_accept is not None:
            self.wait_for_return_on_dashboard()

        response = self.parse_response(response)

        if allow_list and len(allow_list) == 1 and TAG_RESP_CREDENTIAL not in response:
            # Credential may be omitted if the allowList has exactly one Credential.
            # But AssertionResponse() class doesn't support it.
            # So we are patching it here by adding the credential in the response.
            response[1] = allow_list[0]

        return AssertionResponse.from_dict(response)

    def get_assertion_with_txSimpleAuth(self, rp_id, client_data_hash, allow_list=None,
                                        extensions=None, options=None, pin_uv_param=None,
                                        pin_uv_protocol=None, *, event=None, on_keepalive=None,
                                        login_type="simple", user_accept=True, check_users=None,
                                        compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        assert login_type in ["simple", "multi"]
        """
        Copy of get_assertion() to keep it simpler as the ux is different with txSimpleAuth
        and we don't want to merge he two function as this will create a mess for a somehow
        deprecated extension.
        """
        TAG_RESP_CREDENTIAL = 0x01

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
            instructions.append(NavInsID.RIGHT_CLICK)

            # Screen text_flow_0 -> 1
            nb = get_message_nb_screen(self.model, extensions["txAuthSimple"])
            instructions += [NavInsID.RIGHT_CLICK] * nb

            # Screen 1 -> 2
            instructions += self.get_domain_screen_instructions(rp_id)

            # Screen 2 -> 3
            instructions += self.get_user_screen_instructions(check_users[0])

            if login_type == "multi":
                # Skip "Next user" screen
                # Screen 3 -> 4
                instructions.append(NavInsID.RIGHT_CLICK)

            if user_accept:
                # Go to "Accept" screen
                instructions.append(NavInsID.RIGHT_CLICK)

            # Validate
            instructions.append(NavInsID.BOTH_CLICK)

        assert compare_args
        root, test_name = compare_args
        # Over U2F endpoint (but not over HID) the device needs the
        # response to be retrieved before continuing the UX flow.
        self.navigator.navigate_and_compare(root, test_name, instructions,
                                            screen_change_after_last_instruction=False)

        response = self.device.recv(ctap_hid_cmd)

        if user_accept is not None:
            self.wait_for_return_on_dashboard()

        response = self.parse_response(response)

        if allow_list and len(allow_list) == 1 and TAG_RESP_CREDENTIAL not in response:
            # Credential may be omitted if the allowList has exactly one Credential.
            # But AssertionResponse() class doesn't support it.
            # So we are patching it here by adding the credential in the response.
            response[1] = allow_list[0]

        return AssertionResponse.from_dict(response)

    def reset(self, *, event=None, on_keepalive=None, validate_step=0,
              check_screens=None, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        ctap_hid_cmd = self.send_cbor_nowait(Ctap2.CMD.RESET, event=event,
                                             on_keepalive=on_keepalive)

        instructions = []
        if validate_step != 3 and check_screens is None:
            # Validate blindly
            instructions.append(NavInsID.BOTH_CLICK)

        elif check_cancel:
            # Screen 0 -> 1
            instructions.append(NavInsID.RIGHT_CLICK)

        else:
            # check_screens == None only supported when user accept
            assert check_screens in ["full", "fast"]

            instructions += [NavInsID.RIGHT_CLICK] * validate_step

            # Confirm
            instructions.append(NavInsID.BOTH_CLICK)

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Over U2F endpoint (but not over HID) the device needs the
            # response to be retrieved before continuing the UX flow.
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        elif instructions:
            self.navigator.navigate(instructions,
                                    screen_change_after_last_instruction=False)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        self.wait_for_return_on_dashboard()

        self.parse_response(response)
