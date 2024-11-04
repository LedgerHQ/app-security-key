import random
import secrets
import string
import struct
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from fido2.cose import ES256
from fido2.ctap2.base import args, AttestationResponse
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavIns, NavInsID

# Application build configuration
HAVE_NO_RESET_GENERATION_INCREMENT = True
ENABLE_RK_CONFIG = True
ENABLE_RK_CONFIG_UI_SETTING = False


FIDO_RP_ID_HASH_1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                  "101112131415161718191a1b1c1d1e1f")


@dataclass
class MakeCredentialArguments:
    client_data_hash: str
    rp: str
    user: str
    key_params: List[Dict]
    exclude_list: Optional[List] = None
    extensions: Optional[Dict] = None
    options: Optional[Dict] = None
    pin_uv_param: Optional[Any] = None
    pin_uv_protocol: Optional[Any] = None
    entreprise_attestation: Optional[str] = None

    @property
    def cbor_args(self):
        return args(*asdict(self).values())


@dataclass
class MakeCredentialTransaction:
    args: MakeCredentialArguments
    attestation: AttestationResponse

    @property
    def credential_data(self) -> AttestedCredentialData:
        return AttestedCredentialData(self.attestation.auth_data.credential_data)


def prepare_apdu(cla=0, ins=0, p1=0, p2=0, data=b""):
    size = len(data)
    size_h = size >> 16 & 0xFF
    size_l = size & 0xFFFF
    apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, size_h, size_l) + data + b"\0\0"
    return apdu


def generate_random_bytes(length):
    return secrets.token_bytes(length)


def generate_random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def generate_make_credentials_params(client,
                                     rp=None,
                                     rk: Optional[bool] = None,
                                     uv=None,
                                     key_params=None,
                                     pin: Optional[bytes] = None,
                                     pin_uv_param: Optional[bytes] = None,
                                     ref: int = None,
                                     exclude_list: Optional[List] = None,
                                     extensions: Optional[List] = None,
                                     options: Optional[Dict] = None) -> MakeCredentialArguments:
    if ref is None:
        rp_base = generate_random_string(20)
        rp_id = "webctap.{}.com".format(rp_base)
        user_id = generate_random_bytes(64)
        user_name = None
    else:
        if ref == 0:
            rp_id = "webctap.myservice.com"
            user_id = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f")
            user_name = "My user name"
        else:
            rp_id = f"webctap.myservice_{ref}.com"
            user_id = bytes.fromhex("00000000000000000000000000000000"
                                    f"0000000000000000000000000000000{ref}")
            user_name = f"My user {ref} name"

    client_data_hash = generate_random_bytes(32)
    if rp is None:
        rp = {"id": rp_id}
    user = {"id": user_id}
    if user_name:
        user["name"] = user_name
    key_params = (key_params if key_params is not None
                  else [{"type": "public-key", "alg": ES256.ALGORITHM}])
    if rk is not None or uv is not None:
        options = options if options is not None else {}
        if rk is not None:
            options["rk"] = rk
        if uv is not None:
            options["uv"] = uv

    params = MakeCredentialArguments(client_data_hash, rp, user, key_params,
                                     exclude_list, extensions, options)

    if pin is not None or pin_uv_param is not None:
        if pin:
            token = client.client_pin.get_pin_token(pin)
            params.pin_uv_param = client.client_pin.protocol.authenticate(token, client_data_hash)
        else:
            params.pin_uv_param = pin_uv_param
        params.pin_uv_protocol = client.client_pin.protocol.VERSION
    else:
        params.pin_uv_param = None
        params.pin_uv_protocol = None

    return params


def generate_get_assertion_params(client,
                                  user_accept: Optional[bool] = True,
                                  **kwargs) -> MakeCredentialTransaction:
    make_credentials_arguments = generate_make_credentials_params(client, **kwargs)
    attestation = client.ctap2.make_credential(make_credentials_arguments, user_accept=user_accept)
    return MakeCredentialTransaction(make_credentials_arguments, attestation)


def get_rp_id_hash(rp_id):
    return sha256(rp_id.encode("utf8"))


# Extracted from src/fido_known_app.c
fido_known_app = {
    "www.binance.com": "Binance",
    "https://bitbucket.org": "Bitbucket",
    "https://www.bitfinex.com": "Bitfinex",
    "https://vault.bitwarden.com/app-id.json": "Bitwarden",
    "coinbase.com": "Coinbase",
    "https://www.dashlane.com": "Dashlane",
    "https://www.dropbox.com/u2f-app-id.json": "Dropbox",
    "www.dropbox.com": "Dropbox",
    "https://api-9dcf9b83.duosecurity.com": "Duo",
    "https://www.fastmail.com": "FastMail",
    "https://id.fedoraproject.org/u2f-origins.json": "Fedora",
    "https://account.gandi.net/api/u2f/trusted_facets.json": "Gandi",
    "https://github.com/u2f/trusted_facets": "GitHub",
    "https://gitlab.com": "GitLab",
    "https://www.gstatic.com/securitykey/origins.json": "Google",
    "https://keepersecurity.com": "Keeper",
    "https://lastpass.com": "LastPass",
    "https://slushpool.com/static/security/u2f.json": "Slush Pool",
    "https://dashboard.stripe.com": "Stripe",
    "https://u2f.bin.coffee": "u2f.bin.coffee",
    "webauthn.bin.coffee": "webauthn.bin.coffee",
    "webauthn.io": "WebAuthn.io",
    "webauthn.me": "WebAuthn.me",
    "demo.yubico.com": "demo.yubico.com",
}
fido_known_appid = {get_rp_id_hash(x): y for x, y in fido_known_app.items()}


class LedgerCTAP:

    def __init__(self, firmware: Firmware, navigator: Navigator, debug: bool = False):
        self.firmware = firmware
        self.navigator = navigator
        self.debug = debug

    def confirm(self):
        if self.firmware in [Firmware.STAX, Firmware.FLEX]:
            instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM]
        else:
            instructions = [NavInsID.BOTH_CLICK]
        self.navigator.navigate(instructions,
                                screen_change_after_last_instruction=False)

    def wait_for_return_on_dashboard(self):
        if self.firmware in [Firmware.STAX, Firmware.FLEX]:
            # On Stax tap on the center to dismiss the status message faster
            # Ignore if there is nothing that happen (probably already on home screen),
            # which is expected for flow without status (reset)
            self.navigator.navigate([NavInsID.USE_CASE_STATUS_DISMISS],
                                    screen_change_after_last_instruction=False)
        self.navigator._backend.wait_for_home_screen()

    def navigate(self,
                 user_accept: Optional[bool],
                 check_screens: bool,
                 check_cancel: bool,
                 compare_args,
                 text: Optional[str],
                 nav_ins,
                 val_ins):

        if check_screens:
            assert compare_args
            root, test_name = compare_args
        else:
            root, test_name = None, None

        if user_accept is not None:
            # Over U2F endpoint (but not over HID) the device needs the
            # response to be retrieved before continuing the UX flow.

            if text:
                self.navigator.navigate_until_text_and_compare(
                    nav_ins,
                    val_ins,
                    text,
                    root,
                    test_name,
                    screen_change_after_last_instruction=False)
            else:
                self.navigator.navigate_and_compare(
                    root,
                    test_name,
                    val_ins,
                    screen_change_after_last_instruction=False)

        elif check_cancel:
            self.navigator.navigate([NavIns(NavInsID.WAIT, (0.1,))],
                                    screen_change_after_last_instruction=False)
