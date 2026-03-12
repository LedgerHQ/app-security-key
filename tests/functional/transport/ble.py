import socket
import struct
import time

from fido2.ctap import CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID

from threading import Event
from typing import Optional, Callable, Iterator

from . import TransportType

# FIDO BLE transport command bytes (CTAP2 §8.3.4)
BLE_CMD_PING       = 0x81
BLE_CMD_KEEPALIVE  = 0x82
BLE_CMD_MSG        = 0x83
BLE_CMD_CANCEL     = 0xBE
BLE_CMD_ERROR      = 0xBF

# FIDO BLE keepalive status codes
KEEPALIVE_TUP_NEEDED  = 0x01
KEEPALIVE_PROCESSING  = 0x02

# FIDO BLE error codes (CTAP2 §8.3.5)
BLE_ERR_INVALID_CMD   = 0x01
BLE_ERR_INVALID_PAR   = 0x02
BLE_ERR_INVALID_LEN   = 0x03
BLE_ERR_INVALID_SEQ   = 0x04
BLE_ERR_REQ_TIMEOUT   = 0x05
BLE_ERR_NA            = 0x06


class LedgerCtapBLEConnection:
    """Connection to the BLE FIDO endpoint of speculos.

    Implements the FIDO BLE framing protocol (CTAP2 §8.3.4):
      Initialization fragment: CMD(1) | HLEN(1) | LLEN(1) | DATA(up to maxLen-3)
      Continuation fragment:   SEQ(1) | DATA(up to maxLen-1)

    Communication goes through a speculos raw socket that carries
    BLE ATT-level write/notification payloads.
    """
    # Default BLE ATT MTU-based fragment size (ATT_MTU - 3 for ATT header)
    DEFAULT_MAX_FRAGMENT_LEN = 20

    def __init__(self, port: int = 5002, debug: bool = False):
        self.debug = debug
        self.max_fragment_len = self.DEFAULT_MAX_FRAGMENT_LEN
        self.sock = socket.create_connection(('127.0.0.1', port))
        self.sock.settimeout(10)

    def _send_raw(self, data: bytes) -> None:
        """Send a raw BLE fragment over the socket."""
        if self.debug:
            print(f"> ble frag ({len(data)}B) = {data.hex()}")
        self.sock.send(struct.pack('>I', len(data)) + data)

    def _recv_raw(self) -> bytes:
        """Receive a raw BLE fragment from the socket."""
        size_bytes = b''
        while len(size_bytes) < 4:
            new = self.sock.recv(4 - len(size_bytes))
            assert new, "BLE connection closed"
            size_bytes += new
        size = int.from_bytes(size_bytes, 'big')

        data = b''
        while len(data) < size:
            new = self.sock.recv(size - len(data))
            assert new, "BLE connection closed"
            data += new
        if self.debug:
            print(f"< ble frag ({len(data)}B) = {data.hex()}")
        return data

    def send_message(self, cmd: int, data: bytes) -> None:
        """Send a complete BLE FIDO message (with fragmentation)."""
        total_len = len(data)

        # Initialization fragment: CMD | HLEN | LLEN | DATA
        max_init_data = self.max_fragment_len - 3
        init_data = data[:max_init_data]
        remaining = data[max_init_data:]
        init_frag = struct.pack('>BBB', cmd, (total_len >> 8) & 0xFF,
                                total_len & 0xFF) + init_data
        self._send_raw(init_frag)

        # Continuation fragments: SEQ | DATA
        seq = 0
        max_cont_data = self.max_fragment_len - 1
        while remaining:
            cont_data = remaining[:max_cont_data]
            remaining = remaining[max_cont_data:]
            cont_frag = struct.pack('>B', seq) + cont_data
            self._send_raw(cont_frag)
            seq += 1
            if seq > 0x7F:
                raise ValueError("BLE sequence number overflow")

    def recv_message(self) -> tuple:
        """Receive a complete BLE FIDO message (with reassembly).

        Returns:
            (cmd, data) tuple where cmd is the FIDO BLE command byte
            and data is the reassembled payload.
        """
        # Read initialization fragment
        frag = self._recv_raw()
        if len(frag) < 3:
            raise ValueError(f"BLE init fragment too short: {len(frag)}")

        cmd = frag[0]
        total_len = (frag[1] << 8) | frag[2]
        data = frag[3:]

        # Read continuation fragments
        seq = 0
        while len(data) < total_len:
            frag = self._recv_raw()
            if len(frag) < 1:
                raise ValueError("BLE cont fragment too short")
            r_seq = frag[0]
            if r_seq != seq:
                raise ValueError(f"BLE wrong sequence: expected {seq}, got {r_seq}")
            data += frag[1:]
            seq += 1

        return cmd, data[:total_len]

    def close(self) -> None:
        self.sock.close()


class LedgerCtapBLEDevice(CtapDevice):
    """CTAP device implementation for BLE FIDO transport.

    Implements the FIDO over BLE protocol as specified in CTAP2 §8.3.
    Commands are framed with BLE_CMD_MSG (0x83) and responses arrive
    as BLE_CMD_MSG. Keepalive messages (0x82) are consumed while waiting
    for the final response.
    """
    transport = TransportType.BLE

    def __init__(self, port: int = 5002, debug: bool = False):
        time.sleep(1)
        self.debug = debug
        self._conn = LedgerCtapBLEConnection(port=port, debug=debug)

    @property
    def version(self) -> int:
        return 2

    @property
    def capabilities(self) -> CAPABILITY:
        return CAPABILITY.CBOR

    def send(self, cmd: CTAPHID, data: bytes = b"") -> None:
        """Send a CTAP command over BLE.

        CTAP2 commands (CTAPHID.CBOR) are sent as BLE_CMD_MSG.
        CTAP1 commands (CTAPHID.MSG) are also sent as BLE_CMD_MSG.
        """
        if cmd == CTAPHID.CBOR or cmd == CTAPHID.MSG:
            ble_cmd = BLE_CMD_MSG
        elif cmd == CTAPHID.CANCEL:
            ble_cmd = BLE_CMD_CANCEL
        elif cmd == CTAPHID.PING:
            ble_cmd = BLE_CMD_PING
        else:
            raise ValueError(f"Unsupported CTAPHID command over BLE: {cmd}")

        self._conn.send_message(ble_cmd, data)

    def recv(self, cmd: CTAPHID) -> bytes:
        """Receive a CTAP response over BLE.

        Consumes any KEEPALIVE messages received while waiting for
        the actual response (MSG, PING, or ERROR).
        """
        while True:
            r_cmd, data = self._conn.recv_message()

            if r_cmd == BLE_CMD_KEEPALIVE:
                if self.debug:
                    status = data[0] if data else 0
                    status_str = {
                        KEEPALIVE_TUP_NEEDED: "TUP_NEEDED",
                        KEEPALIVE_PROCESSING: "PROCESSING",
                    }.get(status, f"UNKNOWN({status})")
                    print(f"  BLE keepalive: {status_str}")
                continue

            if r_cmd == BLE_CMD_ERROR:
                err_code = data[0] if data else 0
                raise CtapError(err_code)

            if r_cmd == BLE_CMD_MSG:
                return data

            if r_cmd == BLE_CMD_PING:
                return data

            raise ValueError(f"Unexpected BLE response cmd: 0x{r_cmd:02X}")

    def exchange(self, cmd: CTAPHID, data: bytes = b"") -> bytes:
        self.send(cmd, data)
        return self.recv(cmd)

    def call(
        self,
        cmd: CTAPHID,
        data: bytes = b"",
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ) -> bytes:
        if event:
            raise ValueError("event handling is not supported")
        if on_keepalive:
            raise ValueError("on_keepalive handling is not supported")
        return self.exchange(cmd, data)

    def close(self) -> None:
        self._conn.close()

    @classmethod
    def list_devices(cls, name: str = "") -> Iterator:
        yield
