#!/usr/bin/env python3

import nfc
from time import sleep
from datetime import datetime
from fido2 import cbor
from fido2.ctap2.base import Ctap2, Info, args, AttestationResponse, AssertionResponse
from fido2.ctap1 import Ctap1, RegistrationData, SignatureData
from fido2.webauthn import AttestedCredentialData
from fido2.cose import ES256

import struct
import secrets
import random
import string


FIDO_CLA = 0x00
FIDO_AID = bytearray.fromhex("A0000006472F0001")


def generate_random_bytes(length):
    return secrets.token_bytes(length)


def generate_random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def generate_make_credentials_params():
    rp_base = generate_random_string(20)
    rp_id = "webctap.{}.com".format(rp_base)
    user_id = generate_random_bytes(64)
    user_name = "vgfjbdeskjgbrsbvgsb"

    client_data_hash = generate_random_bytes(32)
    rp = {"id": rp_id}
    user = {"id": user_id}
    if user_name:
        user["name"] = user_name
    key_params = [{"type": "public-key", "alg": ES256.ALGORITHM}]
    return client_data_hash, rp, user, key_params


class DongleNFC():
    def __init__(self, debug=False):
        self.waitImpl = self
        self.opened = True
        self.debug = debug
        self.clf = nfc.ContactlessFrontend('usb')
        self.tag = self.clf.connect(rdwr={'on-connect': lambda tag: False})

    def exchange(self, apdu):
        if self.debug:
            print(f"[NFC] => {apdu.hex()}")
        response = self.tag.transceive(apdu, 5.0)
        if self.debug:
            print(f"[NFC] <= {response.hex()}")
            return response

    def parse_u2f_response(self, response):
        return response[-2:].hex(), response[:-2]

    def send_u2f_apdu(self, apdu):
        t1 = datetime.now()
        response = self.exchange(apdu)
        t2 = datetime.now()
        if self.debug:
            print((t2 - t1).microseconds // 1000, "ms", len(response), "bytes")
        return self.parse_u2f_response(response)

    def craft_apdu(self, cla, ins, p1=0, p2=0, data=None, le=0, short_encoding=True):
        apdu = struct.pack(">BBBB", cla, ins, p1, p2)
        if short_encoding:
            if data:
                lc = len(data)
                assert lc < 256
                apdu += struct.pack(">B", lc)
                apdu += data
            apdu += struct.pack(">B", le)
        else:
            apdu += struct.pack(">B", 0)
            if data:
                lc = len(data)
                apdu += struct.pack(">H", lc)
                apdu += data
            apdu += struct.pack(">H", le)
        return apdu

    def send_u2f_cmd(self, cla, ins, p1=0, p2=0, data=None, le=0, short_encoding=True):
        apdu = self.craft_apdu(cla, ins, p1, p2, data, le, short_encoding)

        sw, rx = self.send_u2f_apdu(apdu)
        response = rx
        if short_encoding:
            while sw.startswith("61"):
                apdu = self.craft_apdu(cla, 0xC0)
                sw, rx = self.send_u2f_apdu(apdu)
                response += rx

        return sw, response

    def parse_fido2_response(self, sw, response):
        assert sw == "9000"
        assert response[0] == 0

        response = response[1:]
        decoded = cbor.decode(response)
        return decoded

    def send_fido2_cbor(self, cmd, data=None, short_encoding=True):
        request = struct.pack(">B", cmd)
        if data is not None:
            request += cbor.encode(data)

        if short_encoding:
            while request:
                more = False
                if len(request) > 255:
                    more = True
                    cla = 0x90
                else:
                    cla = 0x80

                lc = min(255, len(request))
                data = request[:lc]

                request = request[lc:]
                sw, rx = self.send_u2f_cmd(cla=cla, ins=0x10, data=data, short_encoding=True)

                if more:
                    assert sw == "9000"
                    assert not rx
                else:
                    break
        else:
            sw, rx = self.send_u2f_cmd(cla=0x0, ins=0x10, data=request, short_encoding=False)

        return self.parse_fido2_response(sw, rx)

    def close(self):
        self.clf.close()


def test_u2f(short_encoding):
    challenge_param = generate_random_bytes(32)
    app_param = generate_random_bytes(32)

    dongle = DongleNFC(True)

    # APPLET_SELECT
    sw, resp = dongle.send_u2f_cmd(cla=FIDO_CLA, ins=0xA4, p1=0x04, data=FIDO_AID, short_encoding=short_encoding)
    assert sw == "9000"
    assert resp.decode() == "U2F_V2"

    # U2F_VERSION
    sw, resp = dongle.send_u2f_cmd(cla=FIDO_CLA, ins=Ctap1.INS.VERSION, short_encoding=short_encoding)
    assert sw == "9000"
    assert resp.decode() == "U2F_V2"

    # U2F_REGISTER
    data = challenge_param + app_param
    sw, resp = dongle.send_u2f_cmd(cla=FIDO_CLA, ins=Ctap1.INS.REGISTER, data=data, short_encoding=short_encoding)
    assert sw == "9000"
    registration_data = RegistrationData(resp)
    registration_data.verify(app_param, challenge_param)

    # U2F_AUTHENTICATE
    challenge_param = generate_random_bytes(32)
    data = challenge_param + app_param
    data += struct.pack(">B", len(registration_data.key_handle))
    data += registration_data.key_handle
    sw, resp = dongle.send_u2f_cmd(cla=FIDO_CLA, ins=Ctap1.INS.AUTHENTICATE, p1=3, data=data, short_encoding=short_encoding)
    assert sw == "9000"
    auth_data = SignatureData(resp)
    auth_data.verify(app_param, challenge_param, registration_data.public_key)

    dongle.close()


def test_fido2(short_encoding):

    dongle = DongleNFC(True)

    # APPLET_SELECT
    sw, resp = dongle.send_u2f_cmd(cla=FIDO_CLA, ins=0xA4, p1=0x04, data=FIDO_AID, short_encoding=short_encoding)
    assert sw == "9000"
    assert resp.decode() == "U2F_V2"

    # U2F_VERSION
    sw, resp = dongle.send_u2f_cmd(cla=FIDO_CLA, ins=Ctap1.INS.VERSION, short_encoding=short_encoding)
    assert sw == "9000"
    assert resp.decode() == "U2F_V2"

    # GET INFO
    decoded = dongle.send_fido2_cbor(Ctap2.CMD.GET_INFO, short_encoding=short_encoding)
    Info.from_dict(decoded)

    client_data_hash, rp, user, key_params = generate_make_credentials_params()

    # MAKE_CREDENTIAL
    data = args(client_data_hash,
                rp,
                user,
                key_params,
                None,
                None,
                None,
                None,
                None,
                None)
    decoded = dongle.send_fido2_cbor(Ctap2.CMD.MAKE_CREDENTIAL, data, short_encoding=short_encoding)
    attestation = AttestationResponse.from_dict(decoded)

    # GET_ASSERTION
    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
    client_data_hash = generate_random_bytes(32)
    allow_list = [
        {"id": credential_data.credential_id, "type": "public-key"},
        {"id": credential_data.credential_id, "type": "public-key"}  # to increase the cmd size so that is above 255bytes
    ]
    data = args(rp["id"],
                client_data_hash,
                allow_list,
                None,
                None,
                None,
                None)
    decoded = dongle.send_fido2_cbor(Ctap2.CMD.GET_ASSERTION, data, short_encoding=short_encoding)
    assertion = AssertionResponse.from_dict(decoded)

    assertion.verify(client_data_hash, credential_data.public_key)


#test_u2f(True)
#test_u2f(False)
#test_fido2(True)
test_fido2(False)
