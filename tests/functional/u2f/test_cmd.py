import pytest
import struct
from fido2.ctap1 import Ctap1, ApduError

from ..ctap1_client import APDU
from ..utils import generate_random_bytes


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_cmd_wrong_cla(client):
    # Only supported CLA is 0x00
    for cla in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=cla,
                                   ins=Ctap1.INS.VERSION,
                                   p1=0x00,
                                   p2=0x00,
                                   data=b"")
        assert e.value.code == APDU.SW_CLA_NOT_SUPPORTED


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_cmd_wrong_ins(client):
    for ins in range(0xff + 1):
        # Only supported INS are [0x01, 0x02, 0x03, 0x10, 0xa4]
        # source: src/u2f_processing.c
        if ins in [0x01, 0x02, 0x03, 0x10, 0xa4]:
            continue

        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=ins,
                                   p1=0x00,
                                   p2=0x00,
                                   data=b"")

        assert e.value.code == APDU.SW_INS_NOT_SUPPORTED


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_cmd_length(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)

    cla = 0x00
    ins = Ctap1.INS.REGISTER
    p1 = 0x00
    p2 = 0x00
    data = challenge + app_param
    length = len(data)
    ne = bytearray(b"\xaa\xbb")  # Can be quite anything
    apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, 0, length) + data

    # Test ko with partial Le
    with pytest.raises(ApduError) as e:
        client.ctap1.send_raw_apdu(apdu + ne[:1])
    assert e.value.code == APDU.SW_WRONG_LENGTH

    # Test ko with partial data.
    # Case i == 5 (with only minimal APDU header: cla, ins, p1, p2) is a valid
    # APDU, but not a valid REGISTER cmd so error SW_WRONG_LENGTH should still
    # be raised.
    for i in range(1, len(apdu)):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_raw_apdu(apdu[:i])
        assert e.value.code == APDU.SW_WRONG_LENGTH

    # Test ko with bad length field
    for dl in [-5, -1, 1, +5]:
        # On purpose bad data length
        apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, 0, length + dl) + data
        with pytest.raises(ApduError) as e:
            client.ctap1.send_raw_apdu(apdu)
        assert e.value.code == APDU.SW_WRONG_LENGTH


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_cmd_no_data_extended_encoding(client):
    cla = 0x00
    ins = Ctap1.INS.VERSION
    p1 = 0x00
    p2 = 0x00
    nc = 0
    ne = 0xaabb  # Can be quite anything

    # Extended encoding, explicit Lc and Le
    apdu = struct.pack(">BBBBBHH", cla, ins, p1, p2, 0, nc, ne)
    result = client.ctap1.send_raw_apdu(apdu)

    # Extended encoding, explicit Lc and no Le
    apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, 0, nc)
    assert result == client.ctap1.send_raw_apdu(apdu)

    # Test errors

    # Extended encoding, bad explicit Lc and Le
    apdu = struct.pack(">BBBBBHH", cla, ins, p1, p2, 0, 1, ne)
    with pytest.raises(ApduError) as e:
        client.ctap1.send_raw_apdu(apdu)
    assert e.value.code == APDU.SW_WRONG_LENGTH


@pytest.mark.skip_endpoint(["U2F", "NFC"])
def test_cmd_no_data_extended_encoding_hid_only(client):
    cla = 0x00
    ins = Ctap1.INS.VERSION
    p1 = 0x00
    p2 = 0x00
    ne = 0xaabb  # Can be quite anything

    # Extended encoding, no Lc and explicit Le
    apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, 0, ne)
    result = client.ctap1.send_raw_apdu(apdu)

    # Extended encoding, no Lc and no Le
    apdu = struct.pack(">BBBB", cla, ins, p1, p2)
    assert result == client.ctap1.send_raw_apdu(apdu)


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_cmd_no_data_short_encoding_u2f_only(client):
    cla = 0x00
    ins = Ctap1.INS.VERSION
    p1 = 0x00
    p2 = 0x00

    # Short encoding (not supported), Lc and Le
    apdu = struct.pack(">BBBBBB", cla, ins, p1, p2, 0, 0xaa)
    with pytest.raises(ApduError) as e:
        client.ctap1.send_raw_apdu(apdu)
    assert e.value.code == APDU.SW_WRONG_LENGTH


@pytest.mark.skip_endpoint(["U2F", "NFC"])
def test_cmd_no_data_short_encoding_hid_only(client):
    cla = 0x00
    ins = Ctap1.INS.VERSION
    p1 = 0x00
    p2 = 0x00
    nc = 0

    # Short encoding Lc and Le
    apdu = struct.pack(">BBBBBB", cla, ins, p1, p2, 0, 0xaa)
    result = client.ctap1.send_raw_apdu(apdu)

    # Short encoding, Lc and no Le
    # This should not be supported as spec requires that messages over HID
    # should be encoded using extended length APDU encoding:
    # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html#u2fhid-protocol-implementation
    # However, it is not respected on v1.7.0 even after an issue was raised:
    # https://github.com/fido-alliance/conformance-test-tools-resources/issues/614
    apdu = struct.pack(">BBBBB", cla, ins, p1, p2, nc)
    assert result == client.ctap1.send_raw_apdu(apdu)
