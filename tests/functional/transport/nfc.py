import time
from fido2.ctap import CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID

from threading import Event
from typing import Optional, Callable, Iterator

from ragger.backend import BackendInterface

from . import TransportType

NFC_CLA = 0x80

INS_NEXT_CHUNK = 0xC0

STATUS_MORE_DATA = 0x6100


class LedgerCtapNFCDevice(CtapDevice):
    transport = TransportType.NFC

    def __init__(self, backend: BackendInterface, debug: bool = False):
        time.sleep(1)
        self.debug = debug
        self._backend = backend

    @property
    def version(self) -> int:
        return 2

    @property
    def capabilities(self) -> CAPABILITY:
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    def exchange(self, cmd: CTAPHID, data: bytes) -> bytes:
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

    def send(self, cmd: CTAPHID, data: bytes = b"") -> None:
        if len(data) <= 0xff:
            return self._backend.send(NFC_CLA, cmd, data=data)
        # extended APDU, with length on 3 bytes ([00, len[0], len[1]])
        msg = bytes([NFC_CLA, cmd, 0, 0, 0, len(data) >> 8, len(data) & 0xff]) + data
        return self._backend.send_raw(msg)

    def recv(self, cmd: CTAPHID) -> bytes:
        response = b""
        while True:
            answer = self._backend.receive()
            response += answer.data
            status, remaining_length = answer.status & 0xff00, answer.status & 0x00ff
            if status == 0x9000:
                if len(response) == 1 and response[0]:
                    raise CtapError(response[0])
                return response
            if status == STATUS_MORE_DATA:
                if remaining_length == 0:
                    self.send(INS_NEXT_CHUNK)
                else:
                    raw_cmd = bytes([NFC_CLA, INS_NEXT_CHUNK, 0, 0, remaining_length])
                    self._backend.send_raw(raw_cmd)
        return response

    @classmethod
    def list_devices(cls, name: str = "") -> Iterator:
        yield
