import struct

from enum import IntEnum

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from fido2.ctap1 import Ctap1, ApduError, RegistrationData, SignatureData
from fido2.hid import CTAPHID

from utils import prepare_apdu, LedgerCTAP


class APDU(IntEnum):
    """APDU status codes.

    Overriding fido2.ctap1.APDU to add many missing error codes."""

    # ISO7816 standard status codes
    SW_NO_ERROR = 0x9000,
    SW_WRONG_LENGTH = 0x6700,
    SW_CONDITIONS_NOT_SATISFIED = 0x6985,
    SW_WRONG_DATA = 0x6A80,
    SW_INCORRECT_P1P2 = 0x6A86,
    SW_INS_NOT_SUPPORTED = 0x6D00,
    SW_CLA_NOT_SUPPORTED = 0x6E00,

    # Vendor specific status codes
    SW_INTERNAL_EXCEPTION = 0X6F00,
    SW_USER_REFUSED = 0x6F01,
    SW_PROPRIETARY_INTERNAL = 0x6FFF,


class U2F_P1(IntEnum):
    CHECK_IS_REGISTERED = 0x07
    REQUEST_USER_PRESENCE = 0x03
    OPTIONAL_USER_PRESENCE = 0x08


class LedgerCtap1(Ctap1, LedgerCTAP):
    """ Overriding fido2.ctap1.Ctap1

    This is mostly to allow to interact with the screen and the buttons
    during APDU exchange.
    To do so, send_apdu_nowait as been introduced.
    Then, register() and authenticate() Ctap1 functions are overridden
    to add interactions with the screen and the buttons.
    """
    def __init__(self, device, firmware: Firmware, navigator: Navigator, debug: bool = False):
        Ctap1.__init__(self, device)
        LedgerCTAP.__init__(self, firmware, navigator, debug)

    def parse_response(self, response):
        status = struct.unpack(">H", response[-2:])[0]
        try:
            status = APDU(status)
        except ValueError:
            pass

        data = response[:-2]
        if status != APDU.SW_NO_ERROR:
            raise ApduError(status, data)
        return data

    def send_raw_apdu(self, apdu):
        response = self.device.exchange(CTAPHID.MSG, apdu)
        return self.parse_response(response)

    def send_apdu(self, cla=0, ins=0, p1=0, p2=0, data=b""):
        apdu = prepare_apdu(cla=cla, ins=ins, p1=p1, p2=p2, data=data)
        return self.send_raw_apdu(apdu)

    def send_apdu_nowait(self, cla=0, ins=0, p1=0, p2=0, data=b""):
        apdu = prepare_apdu(cla=cla, ins=ins, p1=p1, p2=p2, data=data)
        self.device.send(CTAPHID.MSG, apdu)

    def register(self, client_param, app_param, user_accept=True,
                 check_screens=None, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        data = client_param + app_param
        self.send_apdu_nowait(ins=Ctap1.INS.REGISTER, data=data)

        text = None
        nav_ins = None
        val_ins = None

        if self.firmware.is_nano:
            nav_ins = NavInsID.RIGHT_CLICK
            val_ins = [NavInsID.BOTH_CLICK]
            if user_accept is not None:
                if user_accept:
                    text = "Register"
                else:
                    text = "Abort"
        elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
            if user_accept is not None:
                if not user_accept:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]
                else:
                    val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]

        self.navigate(user_accept,
                      check_screens,
                      False,  # Never check cancel
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)

        response = self.device.recv(CTAPHID.MSG)
        try:
            response = self.parse_response(response)
        except ApduError as e:
            if e.code == APDU.SW_CONDITIONS_NOT_SATISFIED:
                # This status code is return over U2F endpoint to avoid
                # timeout until the user accept the request.
                # Now that we have validate or abort the request with button
                # press, we can resend the request and receive the "true"
                # request response.
                self.send_apdu_nowait(ins=Ctap1.INS.REGISTER, data=data)
                response = self.device.recv(CTAPHID.MSG)
                response = self.parse_response(response)
            else:
                if user_accept is not None:
                    self.wait_for_return_on_dashboard()
                raise e

        if user_accept is not None:
            self.wait_for_return_on_dashboard()

        return RegistrationData(response)

    def authenticate(self, client_param, app_param, key_handle,
                     check_only=False, user_accept=True,
                     check_screens=None, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        key_handle_len = struct.pack(">B", len(key_handle))
        data = client_param + app_param + key_handle_len + key_handle
        p1 = U2F_P1.CHECK_IS_REGISTERED if check_only else U2F_P1.REQUEST_USER_PRESENCE
        self.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE, p1=p1, data=data)

        text = None
        nav_ins = None
        val_ins = None

        if self.firmware.is_nano:
            nav_ins = NavInsID.RIGHT_CLICK
            val_ins = [NavInsID.BOTH_CLICK]
            if user_accept is not None:
                if user_accept:
                    text = "Login"
                else:
                    text = "Abort"
        elif self.firmware in [Firmware.STAX, Firmware.FLEX]:
            if user_accept is not None:
                if not user_accept:
                    val_ins = [NavInsID.USE_CASE_CHOICE_REJECT]
                else:
                    val_ins = [NavInsID.USE_CASE_CHOICE_CONFIRM]

        self.navigate(user_accept,
                      check_screens,
                      False,  # Never check cancel
                      compare_args,
                      text,
                      nav_ins,
                      val_ins)

        response = self.device.recv(CTAPHID.MSG)
        try:
            response = self.parse_response(response)
        except ApduError as e:
            if check_only is False and e.code == APDU.SW_CONDITIONS_NOT_SATISFIED:
                # This status code is return over U2F endpoint to avoid
                # timeout until the user accept the request.
                # Now that we have validate or abort the request with button
                # press, we can resend the request and receive the "true"
                # request response.
                self.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE,
                                      p1=p1, data=data)
                response = self.device.recv(CTAPHID.MSG)
                response = self.parse_response(response)
            else:
                if user_accept is not None:
                    self.wait_for_return_on_dashboard()
                raise e

        if user_accept is not None:
            self.wait_for_return_on_dashboard()

        return SignatureData(response)
