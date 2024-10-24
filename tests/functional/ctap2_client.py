import struct

from typing import Mapping, Optional

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2.base import Ctap2, args, AttestationResponse, AssertionResponse
from fido2.hid import CTAPHID

from ctap1_client import APDU
from utils import LedgerCTAP, prepare_apdu, MakeCredentialArguments


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
    def __init__(self, device, firmware: Firmware, navigator: Navigator, ctap2_u2f_proxy, debug: bool = False):
        self.ctap2_u2f_proxy = ctap2_u2f_proxy
        Ctap2.__init__(self, device)
        LedgerCTAP.__init__(self, firmware, navigator, debug)

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

    def make_credential(self, args: MakeCredentialArguments,
                        event=None, on_keepalive=None, user_accept: Optional[bool] = True,
                        check_screens=False, check_cancel=False,
                        compare_args=None) -> AttestationResponse:
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        cmd = Ctap2.CMD.MAKE_CREDENTIAL
        ctap_hid_cmd = self.send_cbor_nowait(cmd, args.cbor_args, event=event,
                                             on_keepalive=on_keepalive)

        text = None
        nav_ins = None
        val_ins = None

        if self.firmware.is_nano:
            nav_ins = NavInsID.RIGHT_CLICK
            val_ins = [NavInsID.BOTH_CLICK]
            if user_accept is not None:
                if not user_accept:
                    text = "Don't register"
                else:
                    text = "Register$"
        elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
            if user_accept is not None:
                if not user_accept:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]
                else:
                    val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]

        self.navigate(user_accept,
                      check_screens,
                      check_cancel,
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)

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
                      check_screens=False, check_cancel=False, compare_args=None,
                      select_user_idx=1, no_check: bool = False):
        # Refresh navigator screen content reference
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

        ctap_hid_cmd = self.send_cbor_nowait(cmd, data, event=event, on_keepalive=on_keepalive)
        text = None
        nav_ins = None
        val_ins = None

        if self.firmware.is_nano:
            nav_ins = NavInsID.RIGHT_CLICK
            val_ins = [NavInsID.BOTH_CLICK]
            if user_accept is not None:
                if login_type == "none":
                    text = "Close"
                elif login_type == "multi":
                    if check_users and len(check_users) == 1:
                        raise ValueError("Found 1 user while expecting multiple")
                    if user_accept:
                        text = f"Log in user {select_user_idx}/"
                    else:
                        text = "Reject"
                else:
                    if check_users and len(check_users) != 1:
                        raise ValueError("Found multiple users while expecting 1")
                    if user_accept:
                        text = "Log in"
                    else:
                        text = "Reject"
        elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
            if user_accept is not None:
                if login_type == "none":
                    val_ins = [NavInsID.TAPPABLE_CENTER_TAP]
                if not user_accept:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]
                else:
                    if login_type == "multi" and select_user_idx != 1:
                        assert select_user_idx <= 5
                        val_ins = [NavIns(NavInsID.TOUCH, (200, 350)),
                                   NavIns(NavInsID.TOUCH, (200, 40 + 90 * select_user_idx)),
                                   NavInsID.USE_CASE_CHOICE_CONFIRM]
                    else:
                        val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]

        if not no_check:
            self.navigate(user_accept,
                          check_screens and not no_check,
                          check_cancel or no_check,
                          compare_args,
                          text,
                          nav_ins,
                          val_ins)

            if check_cancel:
                # Send a cancel command
                self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        if not no_check and user_accept is not None:
            self.wait_for_return_on_dashboard()

        response = self.parse_response(response)

        return AssertionResponse.from_dict(response)

    def reset(self, *, event=None, on_keepalive=None, user_accept=True,
              check_screens=False, check_cancel=False, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        ctap_hid_cmd = self.send_cbor_nowait(Ctap2.CMD.RESET, event=event,
                                             on_keepalive=on_keepalive)

        text = None
        nav_ins = None
        val_ins = None

        if self.firmware.is_nano:
            nav_ins = NavInsID.RIGHT_CLICK
            val_ins = [NavInsID.BOTH_CLICK]
            if user_accept is not None:
                if user_accept:
                    text = "Yes, delete"
                else:
                    text = "No, don't delete"
        elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
            if user_accept is not None:
                if not user_accept:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]
                else:
                    val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]

        self.navigate(user_accept,
                      check_screens,
                      check_cancel,
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)

        if check_cancel:
            # Send a cancel command
            self.device.send(CTAPHID.CANCEL, b"")

        response = self.device.recv(ctap_hid_cmd)

        self.wait_for_return_on_dashboard()

        self.parse_response(response)
