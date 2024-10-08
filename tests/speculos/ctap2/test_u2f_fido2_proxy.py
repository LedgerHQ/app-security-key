import pytest
import struct

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2 import Ctap2

from ctap1_client import APDU


def test_u2f_fido2_proxy_get_info_raw(client):
    request = struct.pack(">B", Ctap2.CMD.GET_INFO)
    response = client.ctap1.send_apdu(cla=0x00,
                                      ins=0x10,
                                      p1=0x00,
                                      p2=0x00,
                                      data=request)
    status = response[0]
    assert status == 0x00

    enc = response[1:]
    decoded = cbor.decode(enc)

    # Check canonical encoding
    expected = cbor.encode(decoded)
    assert enc == expected

    # Check part on the content
    assert decoded[1] == ['U2F_V2', 'FIDO_2_0']


def test_u2f_fido2_proxy_wrong_p1p2(client):
    request = struct.pack(">B", Ctap2.CMD.GET_INFO)

    # Only supported P1 is 0x00
    for p1 in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=0x10,
                                   p1=p1,
                                   p2=0x00,
                                   data=request)
        assert e.value.code == APDU.SW_INCORRECT_P1P2

    # Only supported P2 is 0x00
    for p2 in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=0x10,
                                   p1=0x00,
                                   p2=p2,
                                   data=request)
        assert e.value.code == APDU.SW_INCORRECT_P1P2


def test_u2f_fido2_proxy_no_length(client):

    response = client.ctap1.send_apdu(cla=0x00,
                                      ins=0x10,
                                      p1=0x00,
                                      p2=0x00,
                                      data=b"")
    status = response[0]
    assert status == CtapError.ERR.INVALID_CBOR
