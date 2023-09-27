import random
import secrets
import string
import struct

from fido2.cose import ES256
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData

# Application build configuration
HAVE_NO_RESET_GENERATION_INCREMENT = True
HAVE_RK_SUPPORT_SETTING = True


FIDO_RP_ID_HASH_1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                  "101112131415161718191a1b1c1d1e1f")


CRED_PARAMS = [
    ("webctap.myservice.com",
     bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                   "101112131415161718191a1b1c1d1e1f"),
     "My user name"),
    ("webctap.myservice_1.com",
     bytes.fromhex("00000000000000000000000000000000"
                   "00000000000000000000000000000001"),
     "My user 1 name"),
    ("webctap.myservice_2.com",
     bytes.fromhex("00000000000000000000000000000000"
                   "00000000000000000000000000000002"),
     "My user 2 name"),
    ("webctap.myservice_3.com",
     bytes.fromhex("00000000000000000000000000000000"
                   "00000000000000000000000000000003"),
     "My user 3 name")
]


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


def generate_make_credentials_params(ref=None):
    if ref is None:
        rp_base = generate_random_string(20)
        rp_id = "webctap.{}.com".format(rp_base)
        user_id = generate_random_bytes(64)
        user_name = None
    else:
        rp_id, user_id, user_name = CRED_PARAMS[ref]

    client_data_hash = generate_random_bytes(32)
    rp = {"id": rp_id}
    user = {"id": user_id}
    if user_name:
        user["name"] = user_name
    key_params = [{"type": "public-key", "alg": ES256.ALGORITHM}]
    return client_data_hash, rp, user, key_params


def generate_get_assertion_params(client, rp=None, rk=None, uv=None,
                                  key_params=None, user_accept=True,
                                  pin=None, ref=None):
    client_data_hash, _rp, user, _key_params = generate_make_credentials_params(ref=ref)
    options = None

    if not rp:
        rp = _rp

    if rk is not None or uv is not None:
        options = {}
        if rk is not None:
            options["rk"] = rk
        if uv is not None:
            options["uv"] = uv

    if not key_params:
        key_params = _key_params

    if pin:
        token = client.client_pin.get_pin_token(pin)
        pin_uv_param = client.client_pin.protocol.authenticate(token, client_data_hash)
        pin_uv_protocol = client.client_pin.protocol.VERSION
    else:
        pin_uv_param = None
        pin_uv_protocol = None

    attestation = client.ctap2.make_credential(client_data_hash,
                                               rp,
                                               user,
                                               key_params,
                                               options=options,
                                               user_accept=user_accept,
                                               pin_uv_param=pin_uv_param,
                                               pin_uv_protocol=pin_uv_protocol)
    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)

    return rp, credential_data, user


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


def navigate(navigator,
             user_accept,
             check_screens,
             check_cancel,
             compare_args,
             text,
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
        navigator.navigate_until_text_and_compare(
            nav_ins,
            val_ins,
            text,
            root,
            test_name,
            screen_change_after_last_instruction=False)

    elif check_cancel:
        navigator.navigate([nav_ins],
                           screen_change_after_last_instruction=False)
