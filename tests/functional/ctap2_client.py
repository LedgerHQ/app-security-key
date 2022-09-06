import struct

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns
from typing import List, Mapping, Union

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2.base import Ctap2, args, AttestationResponse, AssertionResponse
from fido2.ctap2.pin import ClientPin
from fido2.hid import CTAPHID
from fido2.hid import CtapHidDevice
from fido2.utils import sha256

from .ctap1_client import APDU
from .transport import TransportType
from .utils import LedgerCTAP, MakeCredentialArguments, Nav, prepare_apdu


class LedgerCtap2(Ctap2, LedgerCTAP):
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
    def __init__(self, device: CtapHidDevice, firmware: Firmware, navigator: Navigator,
                 ctap2_u2f_proxy, debug: bool = False):
        self.ctap2_u2f_proxy = ctap2_u2f_proxy
        Ctap2.__init__(self, device)
        LedgerCTAP.__init__(self, firmware, navigator, debug)

    @property
    def nfc(self) -> bool:
        return self.device.transport is TransportType.NFC

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
        ctaphid_cmd = self.send_cbor_nowait(cmd, data=data, event=event, on_keepalive=on_keepalive)
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

    def make_credential(self, args: MakeCredentialArguments,
                        event=None,
                        on_keepalive=None,
                        # if the user will accept the request or not (ignored in NFC)
                        # if None, the navigation is not checked
                        # if the command is expected to be canceled by the client (with an APDU)
                        # if True, navigation and snapshot check are deactivated
                        navigation: Nav = Nav.USER_ACCEPT,
                        # if snapshots are checked against golden ones or not
                        check_screens: bool = False,
                        compare_args=None,
                        # if the call is expected to raise an error
                        will_fail: bool = False) -> AttestationResponse:
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        cmd = Ctap2.CMD.MAKE_CREDENTIAL
        ctap_hid_cmd = self.send_cbor_nowait(cmd, args.cbor_args, event=event,
                                             on_keepalive=on_keepalive)
        if args.pin_uv_param == b"":
            # This parameter leads to authenticator selection flow
            return self.selection(user_accept=user_accept, cmd_sent=ctap_hid_cmd)

        text = None
        nav_ins = None
        val_ins: List[Union[NavIns, NavInsID]] = list()
        if self.nfc and will_fail:
            navigation = Nav.NONE
        if navigation is Nav.CLIENT_CANCEL:
            # when canceled from client side, no navigation checks
            check_screens = False

        # No navigation in NFC, only a screen change, so we enable navigation just to check the
        # snapshot, except in cases where an error is expected.
        if not self.nfc and navigation is not Nav.NONE:
            if self.firmware.is_nano:
                nav_ins = NavInsID.RIGHT_CLICK
                val_ins = [NavInsID.BOTH_CLICK]
                if navigation is Nav.USER_ACCEPT:
                    text = "Register$"
                else:
                    text = "Don't register"
            elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
                if navigation is Nav.USER_ACCEPT:
                    val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]
                else:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]

        if self.nfc:
            # In NFC, the result is displayed after the device sends its RAPDU (no user
            # interaction), so we need to receive *before* checking the navigation.
            response = self.device.recv(ctap_hid_cmd)

        self.navigate(navigation,
                      check_screens,
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)

        if navigation is Nav.CLIENT_CANCEL:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        if not self.nfc:
            # In USB, the device requires user interaction before responding with RAPDU,
            # so we need to receive *after* the navigation
            response = self.device.recv(ctap_hid_cmd)

        if navigation is not Nav.NONE:
            self.wait_for_return_on_dashboard()

        return AttestationResponse.from_dict(self.parse_response(response))

    def get_assertion(self, rp_id,
                      client_data_hash,
                      allow_list=None,
                      extensions=None,
                      options=None,
                      pin_uv_param=None,
                      pin_uv_protocol=None, *,
                      event=None,
                      on_keepalive=None,
                      navigation: Nav = Nav.USER_ACCEPT,
                      # if the call is expected to raise an error
                      will_fail: bool = False,
                      # if the login is simple (one choice) or not (multiple choices)
                      simple_login: bool = True,
                      check_users=None,
                      # if snapshots are checked against golden ones or not
                      check_screens: bool = False,
                      compare_args=None,
                      select_user_idx=1):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        cmd = Ctap2.CMD.GET_ASSERTION
        data = args(rp_id,
                    client_data_hash,
                    allow_list,
                    extensions,
                    options,
                    pin_uv_param,
                    pin_uv_protocol)

        ctap_hid_cmd = self.send_cbor_nowait(cmd, data, event=event, on_keepalive=on_keepalive)

        if pin_uv_param == b"":
            # This parameter leads to authenticator selection flow
            return self.selection(user_accept=user_accept, cmd_sent=ctap_hid_cmd)

        text = None
        nav_ins = None
        val_ins: List[Union[NavIns, NavInsID]] = list()
        if self.nfc and will_fail:
            navigation = Nav.NONE
        if navigation is Nav.CLIENT_CANCEL:
            check_screens = False
        # No navigation in NFC, only a screen change, so we enable navigation just to check the
        # snapshot, except in cases where an error is expected.
        if not self.nfc and navigation is not Nav.NONE:
            if self.firmware.is_nano:
                nav_ins = NavInsID.RIGHT_CLICK
                val_ins = [NavInsID.BOTH_CLICK]
                if will_fail:
                    text = "Close"
                elif not simple_login:
                    if check_users and len(check_users) == 1:
                        raise ValueError("Found 1 user while expecting multiple")
                    if navigation is Nav.USER_ACCEPT:
                        text = f"Log in user {select_user_idx}/"
                    else:
                        text = "Reject"
                else:
                    if check_users and len(check_users) != 1:
                        raise ValueError("Found multiple users while expecting 1")
                    if navigation is Nav.USER_ACCEPT:
                        text = "Log in"
                    else:
                        text = "Reject"
            elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
                if will_fail:
                    val_ins = [NavInsID.TAPPABLE_CENTER_TAP]
                if navigation is Nav.USER_REFUSE:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]
                else:
                    if not simple_login and select_user_idx != 1:
                        assert select_user_idx <= 5
                        val_ins = [NavIns(NavInsID.TOUCH, (200, 350)),
                                   NavIns(NavInsID.TOUCH, (200, 40 + 90 * select_user_idx)),
                                   NavInsID.USE_CASE_CHOICE_CONFIRM]
                    else:
                        val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]
        if self.nfc:
            # In NFC, the result is displayed after the device sends its RAPDU (no user
            # interaction), so we need to receive *before* checking the navigation.
            response = self.device.recv(ctap_hid_cmd)

        self.navigate(navigation,
                      check_screens,
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)
        if navigation is Nav.CLIENT_CANCEL:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")
        if navigation is not Nav.NONE:
            self.wait_for_return_on_dashboard()

        if not self.nfc:
            # In USB, the device requires user interaction before responding with RAPDU,
            # so we need to receive *after* the navigation
            response = self.device.recv(ctap_hid_cmd)

        response = self.parse_response(response)
        return AssertionResponse.from_dict(response)

    def get_next_assertion(self):
        cmd = Ctap2.CMD.GET_NEXT_ASSERTION
        ctap_hid_cmd = self.send_cbor_nowait(cmd)
        response = self.device.recv(ctap_hid_cmd)
        response = self.parse_response(response)
        return AssertionResponse.from_dict(response)

    def reset(self, *,
              event=None,
              on_keepalive=None,
              navigation: Nav = Nav.USER_ACCEPT,
              # if snapshots are checked against golden ones or not
              check_screens: bool = False,
              compare_args=None,
              will_fail: bool = False) -> None:
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        ctap_hid_cmd = self.send_cbor_nowait(Ctap2.CMD.RESET, event=event,
                                             on_keepalive=on_keepalive)

        text = None
        nav_ins = None
        val_ins: List[Union[NavIns, NavInsID]] = list()

        if navigation is Nav.CLIENT_CANCEL:
            check_screens = False
        if self.nfc and will_fail:
            navigation = Nav.NONE

        # No confirmation needed on NFC
        if not self.nfc:
            if self.firmware.is_nano:
                nav_ins = NavInsID.RIGHT_CLICK
                val_ins = [NavInsID.BOTH_CLICK]
                if navigation is Nav.USER_ACCEPT:
                    text = "Yes, delete"
                else:
                    text = "No, don't delete"
            elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
                if navigation is Nav.USER_ACCEPT:
                    val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]
                else:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]

        self.navigate(navigation,
                      check_screens,
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)

        if navigation is Nav.CLIENT_CANCEL:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        self.wait_for_return_on_dashboard()

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
