import pytest
import struct
import sys

from fido2.hid import TYPE_INIT, CTAPHID
from fido2.ctap import CtapError

from .utils import generate_random_bytes

BROADCAST_CID = 0xFFFFFFFF
PACKET_SIZE = 64
INIT_U2F_VERSION = 0x02
INIT_CAPABILITIES = 0x04

INIT_CMD_HEADER_SIZE = 4 + 1 + 2  # CID + CMD + LEN
CONT_FRAME_HEADER_SIZE = 4 + 1  # CID + SEQ
INIT_CMD_MAX_PAYLOAD_SIZE = PACKET_SIZE - INIT_CMD_HEADER_SIZE
CONT_FRAME_MAX_PAYLOAD_SIZE = PACKET_SIZE - CONT_FRAME_HEADER_SIZE


def send_cmd(client, cid, cmd, payload):
    data = struct.pack(">IBH", cid, cmd, len(payload))
    data += payload
    assert len(data) <= PACKET_SIZE
    data = data.ljust(PACKET_SIZE, b"\xee")
    client.device._connection.write_packet(data)


def send_cont_frame(client, cid, seq, payload):
    data = struct.pack(">IB", cid, seq)
    data += payload
    assert len(data) <= PACKET_SIZE
    data = data.ljust(PACKET_SIZE, b"\xee")
    client.device._connection.write_packet(data)


def recv_resp(client, cid, cmd):
    resp = client.device._connection.read_packet()
    assert len(resp) == PACKET_SIZE
    resp_cid, resp_cmd, resp_len = struct.unpack(">IBH", resp[:7])
    assert resp_cid == cid

    if resp_cmd == cmd:
        return resp_len, resp[7:7 + resp_len]
    elif resp_cmd == TYPE_INIT | CTAPHID.ERROR:
        raise CtapError(struct.unpack_from(">B", resp[7:])[0])
    else:
        raise CtapError(CtapError.ERR.INVALID_COMMAND)


def recv_init_resp(client, cid, cmd, nonce):
    resp_len, resp = recv_resp(client, cid, cmd)
    assert resp_len == 17
    assert resp[:8] == nonce
    new_cid = struct.unpack(">I", resp[8:12])[0]
    assert new_cid != 0 and new_cid != BROADCAST_CID
    assert int(resp[12]) == INIT_U2F_VERSION
    assert int(resp[16]) == INIT_CAPABILITIES
    return new_cid


def init_channel(client, cid=BROADCAST_CID):
    cmd = TYPE_INIT | CTAPHID.INIT
    nonce = generate_random_bytes(8)
    send_cmd(client, cid, cmd, nonce)

    return recv_init_resp(client, cid, cmd, nonce)


@pytest.mark.skipif("--fast" in sys.argv, reason="running in fast mode")
@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_no_unexpected_tx(client):
    with pytest.raises(TimeoutError):
        client.device._connection.read_packet()


@pytest.mark.skipif("--fast" in sys.argv, reason="running in fast mode")
@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_no_resp_to_unexpected_cont(client):
    cid = struct.unpack(">I", generate_random_bytes(4))[0]
    payload = generate_random_bytes(CONT_FRAME_MAX_PAYLOAD_SIZE)
    send_cont_frame(client, cid, 1, payload)
    with pytest.raises(TimeoutError):
        client.device._connection.read_packet()


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_init(client):
    new_cid = init_channel(client)
    assert new_cid != 0


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_init_multiples(client):
    cid1 = init_channel(client)
    cid2 = init_channel(client)
    cid3 = init_channel(client)
    assert len(set([cid1, cid2, cid3])) == 3


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_ping(client):
    payload = generate_random_bytes(50)
    resp = client.device.call(CTAPHID.PING, payload)
    assert resp == payload


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_long_ping(client):
    payload = generate_random_bytes(1024)
    resp = client.device.call(CTAPHID.PING, payload)
    assert resp == payload


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_reinit_during_ping(client):
    cid = init_channel(client)

    # Send start of ping
    cmd = TYPE_INIT | CTAPHID.PING
    data = struct.pack(">IBH", cid, cmd, 1024)
    data += generate_random_bytes(INIT_CMD_MAX_PAYLOAD_SIZE)
    client.device._connection.write_packet(data)

    # Send cont frame
    for i in range(5):
        payload = generate_random_bytes(CONT_FRAME_MAX_PAYLOAD_SIZE)
        send_cont_frame(client, cid, i, payload)

    # Reinit the channel
    cid1 = init_channel(client, cid=cid)
    assert cid == cid1


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_invalid_cmd(client):
    cmd = 0x21
    with pytest.raises(CtapError) as e:
        client.device.call(cmd, b"")
    assert e.value.code == CtapError.ERR.INVALID_COMMAND


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_invalid_init_cid(client):
    with pytest.raises(CtapError) as e:
        init_channel(client, cid=0)
    assert e.value.code == CtapError.ERR.INVALID_CHANNEL


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_ping_on_invalid_cid(client):
    for cid in [0, BROADCAST_CID]:
        cmd = TYPE_INIT | CTAPHID.PING
        data = generate_random_bytes(50)
        send_cmd(client, cid, cmd, data)
        with pytest.raises(CtapError) as e:
            recv_resp(client, cid, cmd)
        assert e.value.code == CtapError.ERR.INVALID_CHANNEL


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_invalid_seq(client):
    cid = init_channel(client)

    # Send start of ping
    cmd = TYPE_INIT | CTAPHID.PING
    data = struct.pack(">IBH", cid, cmd, 1024)
    data += generate_random_bytes(INIT_CMD_MAX_PAYLOAD_SIZE)
    client.device._connection.write_packet(data)

    # Send cont frame
    for i in range(3):
        payload = generate_random_bytes(CONT_FRAME_MAX_PAYLOAD_SIZE)
        send_cont_frame(client, cid, i, payload)

    # Send wrong cont frame
    payload = generate_random_bytes(CONT_FRAME_MAX_PAYLOAD_SIZE)
    send_cont_frame(client, cid, 4, payload)
    with pytest.raises(CtapError) as e:
        recv_resp(client, cid, cmd)
    assert e.value.code == CtapError.ERR.INVALID_SEQ


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_cbor_invalid_length(client):
    cid = init_channel(client)

    cmd = TYPE_INIT | CTAPHID.CBOR
    send_cmd(client, cid, cmd, b"")
    recv = recv_resp(client, cid, cmd)
    with pytest.raises(CtapError) as e:
        client.ctap2.parse_response(recv)
    assert e.value.code == CtapError.ERR.INVALID_COMMAND


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_cmd_to_long(client):
    cid = init_channel(client)

    cmd = TYPE_INIT | CTAPHID.PING
    data = struct.pack(">IBH", cid, cmd, 2000)
    data = data.ljust(PACKET_SIZE, b"\xee")
    client.device._connection.write_packet(data)

    with pytest.raises(CtapError) as e:
        recv_resp(client, cid, cmd)
    assert e.value.code == CtapError.ERR.INVALID_LENGTH


# TODO spec behavior to confirm
# @pytest.mark.skip_endpoint(["HID", "NFC"])
# def test_init_while_processing(client):
#     challenge = generate_random_bytes(32)
#     app_param = generate_random_bytes(32)
#     data = challenge + app_param
#
#     # Send a U2F register command
#     client.ctap1.send_apdu_nowait(cla=0x00,
#                                   ins=Ctap1.INS.REGISTER,
#                                   p1=0x00,
#                                   p2=0x00,
#                                   data=data)
#
#     # Send an init on another channel
#     init_channel(client)


@pytest.mark.skip_endpoint(["HID", "NFC"])
def test_check_busy(client):
    cid = client.device._channel_id
    cmd = TYPE_INIT | CTAPHID.PING

    # Send start of ping
    ping_data = generate_random_bytes(INIT_CMD_MAX_PAYLOAD_SIZE + 20)
    data = struct.pack(">IBH", cid, cmd, len(ping_data))
    data += ping_data[:INIT_CMD_MAX_PAYLOAD_SIZE]
    client.device._connection.write_packet(data)

    # Send start of ping on another CID
    new_cid = cid + 1
    data = struct.pack(">IBH", new_cid, cmd, 1024)
    data += generate_random_bytes(INIT_CMD_MAX_PAYLOAD_SIZE)
    client.device._connection.write_packet(data)
    with pytest.raises(CtapError) as e:
        recv_resp(client, new_cid, cmd)
    assert e.value.code == CtapError.ERR.CHANNEL_BUSY

    # Finish ping on first channel
    send_cont_frame(client, cid, 0, ping_data[INIT_CMD_MAX_PAYLOAD_SIZE:])
    resp = client.device.recv(cmd)
    assert resp == ping_data

# TODO missing CBOR keep-alive check
