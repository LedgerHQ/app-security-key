import struct

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns
from typing import List, Mapping, Union

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2.base import Ctap2, args, AttestationResponse, AssertionResponse
from fido2.hid import CTAPHID
from fido2.hid import CtapHidDevice

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

    def get_assertion(self, rp_id, client_data_hash, allow_list=None,
                      extensions=None, options=None, pin_uv_param=None,
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
