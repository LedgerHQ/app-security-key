import pytest
import socket
from ragger.firmware import Firmware

from fido2.ctap1 import ApduError, Ctap1
from fido2.hid import CTAPHID

from ctap1_client import APDU
from utils import generate_random_bytes


# TODO: investigate why this does not work (or rather fail) as expected on Flex.
#       Everything seems totally similar with other devices, even in the SDK.  ?!
@pytest.mark.skip_devices(Firmware.FLEX)
@pytest.mark.skip_endpoint("HID")
def test_register_raw_u2f_fake_channel_security_crc(client):
    challenge = bytearray(generate_random_bytes(32))
    app_param = generate_random_bytes(32)
    data = challenge + app_param

    # On U2F endpoint, the device should return APDU.SW_CONDITIONS_NOT_SATISFIED
    # until user validate, except if the request change!
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

    # Change challenge first bit
    challenge[0] ^= 0x40
    data = challenge + app_param

    client.ctap1.send_apdu_nowait(cla=0x00,
                                  ins=Ctap1.INS.REGISTER,
                                  p1=0x00,
                                  p2=0x00,
                                  data=data)

    with pytest.raises((AssertionError, ConnectionResetError, TimeoutError, socket.timeout)) as e:
        response = client.ctap1.device.recv(CTAPHID.MSG)
