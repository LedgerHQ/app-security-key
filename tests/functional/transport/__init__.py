from enum import auto, Enum


class TransportType(Enum):
    U2F = auto()
    HID = auto()
    NFC = auto()
