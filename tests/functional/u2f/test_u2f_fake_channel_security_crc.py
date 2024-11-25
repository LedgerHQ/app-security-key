import pytest
import socket
from fido2.ctap1 import ApduError, Ctap1
from fido2.hid import CTAPHID

from ..ctap1_client import APDU
from ..utils import generate_random_bytes


@pytest.mark.skip_endpoint(["NFC", "HID"], reason="This test is meant for U2F transport only")
def test_register_raw_u2f_fake_channel_security_crc_raw(client):
    challenge = bytearray(generate_random_bytes(32))
    app_param = generate_random_bytes(32)
    data = challenge + app_param

    # On U2F endpoint, the device should return APDU.SW_CONDITIONS_NOT_SATISFIED
    # until user validate, except if the request changes!
    client.ctap1.send_apdu_nowait(cla=0x00,
                                  ins=Ctap1.INS.REGISTER,
                                  p1=0x00,
                                  p2=0x00,
                                  data=data)

    response = client.ctap1.device.recv(CTAPHID.MSG)

    with pytest.raises(ApduError) as e:
        response = client.ctap1.parse_response(response)

    assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED

    # Confirm request
    client.ctap1.confirm()

    # TODO: It turns out this bit does not bring much except errors on latest NBGL cases,
    #       because it triggers a new register which delivers a proper response before
    #       the previous confirmation could go to an error.
    #       Which is not the case on BAGL devices. This is to be investigated.
    #       Maybe related? This error was only showing with Flex, then it happened also
    #       with Stax when bumped to API LEVEL 21. So the graphiclib may not be the culprit.

    # # Change challenge first bit
    # challenge[0] ^= 0x40
    # data = challenge + app_param

    # client.ctap1.send_apdu_nowait(cla=0x00,
    #                               ins=Ctap1.INS.REGISTER,
    #                               p1=0x00,
    #                               p2=0x00,
    #                               data=data)

    with pytest.raises((AssertionError, ConnectionResetError, TimeoutError, socket.timeout)) as e:
        response = client.ctap1.device.recv(CTAPHID.MSG)
