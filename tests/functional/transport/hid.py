import socket
import struct
from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice, TYPE_INIT, CAPABILITY, CTAPHID
from fido2.hid.base import CtapHidConnection, HidDescriptor
from typing import Optional

from . import TransportType


class LedgerCtapHidConnection(CtapHidConnection):
    """ Overriding fido2.hid.base.CtapHidConnection

    This is mostly a redirection of write_packet() and read_packet()
    to speculos raw socket.
    """
    def __init__(self, transport: TransportType, debug: bool = False):
        if transport is TransportType.NFC:
            raise ValueError("This class is incompatible with NFC transport")
        self.sock = socket.create_connection(('127.0.0.1', 5001))
        self.u2f_hid_endpoint = (transport is TransportType.U2F)
        self.debug = debug
        # Set a timeout to allow tests to raise on socket rx failure
        self.sock.settimeout(5)

    def write_packet(self, packet):
        packet = bytes(packet)
        if self.debug:
            print(f"> pkt = {packet.hex()}")
        self.sock.send(struct.pack('>I', len(packet)) + packet)

    def read_packet(self):
        resp_size_bytes = b''
        while len(resp_size_bytes) < 4:
            new_bytes = self.sock.recv(4 - len(resp_size_bytes))
            assert new_bytes, "connection closed"
            resp_size_bytes += new_bytes
        resp_size = (int.from_bytes(resp_size_bytes, 'big') + 2) & 0xffffffff
        if self.u2f_hid_endpoint:
            assert resp_size == 64

        packet = b''
        while len(packet) < resp_size:
            new_bytes = self.sock.recv(resp_size - len(packet))
            assert new_bytes, "connection closed"
            packet += new_bytes
        if self.debug:
            print(f"< pkt = {packet.hex()}")

        return packet

    def close(self):
        self.sock.close()


class LedgerCtapHidDevice(CtapHidDevice):
    """ Overriding fido2.hid.CtapHidDevice

    This is mostly to split call() function in send() and recv() functions.
    This allow Ctap1 and Ctap2 clients to interact with the buttons between
    the sending of a command and the reception of the response.

    This overriding also handle the particularity of sending commands over
    the raw HID endpoint, which means without using the U2F HID encapsulation.
    """
    def __init__(self, transport: TransportType, debug: bool = False):
        self.transport = transport
        self.raw_hid_endpoint = (transport is TransportType.HID)
        connection = LedgerCtapHidConnection(transport, debug)
        descriptor = HidDescriptor("sim", 0, 0, 64, 64, "speculos", "0000")
        super().__init__(descriptor, connection)

    def send(self, cmd: CTAPHID, data: bytes = b"") -> None:
        if self.raw_hid_endpoint:
            # Send raw request without encapsulation
            self._connection.write_packet(data)
            return

        # Send request with U2F encapsulation
        remaining = data
        seq = 0
        header = struct.pack(">IBH", self._channel_id, TYPE_INIT | cmd, len(remaining))

        while remaining or seq == 0:
            size = min(len(remaining), self._packet_size - len(header))
            body, remaining = remaining[:size], remaining[size:]
            packet = header + body
            # Padding packet can be done with anything.
            # Reasonable implementations use 0x00 which might be more intuitive.
            # However using 0xee can help discover APDU Lc field parsing issues.
            # Note: this is what the Fido Conformance tool is using on some tests.
            packet = packet.ljust(self._packet_size, b"\xee")
            self._connection.write_packet(packet)
            header = struct.pack(">IB", self._channel_id, 0x7F & seq)
            seq += 1

    def recv(self, cmd: CTAPHID) -> bytes:
        seq = 0
        response = b""
        if self.raw_hid_endpoint:
            return self._connection.read_packet()

        while True:
            recv = self._connection.read_packet()

            r_channel = struct.unpack_from(">I", recv)[0]
            recv = recv[4:]
            if r_channel != self._channel_id:
                raise Exception("Wrong channel")

            if not response:  # Initialization packet
                r_cmd, r_len = struct.unpack_from(">BH", recv)
                recv = recv[3:]
                if r_cmd == TYPE_INIT | cmd:
                    pass  # first data packet
                elif r_cmd == TYPE_INIT | CTAPHID.KEEPALIVE:
                    continue
                elif r_cmd == TYPE_INIT | CTAPHID.ERROR:
                    raise CtapError(struct.unpack_from(">B", recv)[0])
                else:
                    raise CtapError(CtapError.ERR.INVALID_COMMAND)
            else:  # Continuation packet
                r_seq = struct.unpack_from(">B", recv)[0]
                recv = recv[1:]
                if r_seq != seq:
                    raise Exception("Wrong sequence number")
                seq += 1

            response += recv
            if len(response) >= r_len:
                break

        return response[:r_len]

    def exchange(self, cmd: CTAPHID, data: bytes = b"") -> bytes:
        if self.raw_hid_endpoint and cmd != CTAPHID.MSG:
            # Only CTAPHID.MSG without header are supported over raw HID endpoint
            if cmd == CTAPHID.INIT:
                # Fake CTAPHID.INIT call so that CtapHidDevice().__init__()
                # don't fail. Indeed at init, it makes a call to
                # self.call(CTAPHID.INIT, nonce) which is not really necessary
                # but we don't want to override CtapHidDevice().__init__().
                print("Faking CTAPHID.INIT over HID endpoint")
                response = data  # Nonce
                u2fhid_version = 0x02
                capabilities = CAPABILITY.CBOR
                response += struct.pack(">IBBBBB", self._channel_id,
                                        u2fhid_version, 0, 0, 0, capabilities)
                return response

            raise ValueError("Unexpected cmd over HID endpoint {}".format(hex(cmd)))

        self.send(cmd, data)
        return self.recv(cmd)

    def call(self, cmd: CTAPHID, data: bytes = b"", event=None,
             on_keepalive: Optional[bool] = None):
        if event:
            raise ValueError("event handling is not supported")

        if on_keepalive:
            raise ValueError("on_keepalive handling is not supported")

        return self.exchange(cmd, data)
