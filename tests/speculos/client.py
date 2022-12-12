import json
import os
import socket
import struct

from base64 import b64decode

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

from pathlib import Path

from fido2.attestation import AttestationVerifier
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice, TYPE_INIT, CAPABILITY, CTAPHID
from fido2.hid.base import CtapHidConnection, HidDescriptor

from ctap1_client import LedgerCtap1
from ctap2_client import LedgerCtap2

TESTS_SPECULOS_DIR = Path(__file__).absolute().parent
REPO_ROOT_DIR = TESTS_SPECULOS_DIR.parent.parent
APP_ELF_PATH = REPO_ROOT_DIR / "bin" / "app.elf"

METADATAS_PATH = REPO_ROOT_DIR / "conformance"
CA_PATH = REPO_ROOT_DIR / "attestations" / "data"
TEST_CA_PATH = CA_PATH / "test" / "ca-cert.pem"
PROD_CA_PATH = CA_PATH / "prod" / "ca-cert.pem"


class LedgerAttestationVerifier(AttestationVerifier):
    def __init__(self, device_model):
        super().__init__()

        use_prod_ca = os.environ.get("USE_PROD_CA", False)

        if use_prod_ca:
            self.metadata_path = METADATAS_PATH / "prod-{}.json".format(device_model)
            self.ca_path = PROD_CA_PATH
        else:
            self.metadata_path = METADATAS_PATH / "test-{}.json".format(device_model)
            self.ca_path = TEST_CA_PATH

    def ca_lookup(self, result, auth_data):
        # A real platform normally take CA information from certification metadatas
        # but we check that the data is the same in attestation ca-cert.pem file
        with open(self.metadata_path, "r") as f:
            data = json.load(f)
        metadata_cert = b64decode(data["attestationRootCertificates"][0])

        with open(self.ca_path, "rb") as f:
            root_cert = load_pem_x509_certificate(f.read())
        attestation_cert = root_cert.public_bytes(serialization.Encoding.DER)

        assert metadata_cert == attestation_cert
        return metadata_cert


class LedgerCtapHidConnection(CtapHidConnection):
    """ Overriding fido2.hid.base.CtapHidConnection

    This is mostly a redirection of write_packet() and read_packet()
    to speculos raw socket.
    """
    def __init__(self, transport, debug=False):
        self.sock = socket.create_connection(('127.0.0.1', 9999))
        self.u2f_hid_endpoint = (transport.upper() == "U2F")
        self.debug = debug

        if self.u2f_hid_endpoint:
            # Device answers should be fast
            self.sock.settimeout(1)
        else:
            self.sock.settimeout(10)

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
    def __init__(self, descriptor, connection, transport, debug=False):
        self.raw_hid_endpoint = (transport.upper() == "HID")
        self.debug = debug
        super().__init__(descriptor, connection)

    def send(self, cmd, data=b""):

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

    def recv(self, cmd):
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

    def exchange(self, cmd, data=b""):
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

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        if event:
            raise ValueError("event handling is not supported")

        if on_keepalive:
            raise ValueError("on_keepalive handling is not supported")

        return self.exchange(cmd, data)


class TestClient:
    def __init__(self, firmware, ragger_backend, navigator, transport,
                 ctap2_u2f_proxy, debug=False):
        self.firmware = firmware
        self.model = firmware.device
        self.ragger_backend = ragger_backend
        self.navigator = navigator
        self.debug = debug

        # USB transport configuration
        self.USB_transport = transport
        self.use_U2F_endpoint = (self.USB_transport.upper() == "U2F")
        self.use_raw_HID_endpoint = (self.USB_transport.upper() == "HID")
        if not self.use_U2F_endpoint and not self.use_raw_HID_endpoint:
            assert ValueError("Invalid endpoint")

        # CTAP2 (cbor) messages can be sent using CTAPHID.CBOR command or
        # they can be encapsulated in an U2F (APDU) message using INS=0x10
        self.ctap2_u2f_proxy = ctap2_u2f_proxy

        # On USB_HID transport endpoint, only CTAPHID.MSG are supported
        # and they must be sent without encapsulation, e.g. without the
        # header containing the channel_id, the command type and the command
        # length.
        if self.use_raw_HID_endpoint and not self.ctap2_u2f_proxy:
            print("Enforce using CTAP2 U2F proxy over raw HID endpoint")
            self.ctap2_u2f_proxy = True

    def start(self):
        try:
            hid_dev = LedgerCtapHidConnection(self.USB_transport,
                                              self.debug)
            descriptor = HidDescriptor("sim", 0, 0, 64, 64, "speculos", "0000")
            self.dev = LedgerCtapHidDevice(descriptor, hid_dev,
                                           self.USB_transport, self.debug)

            self.ctap1 = LedgerCtap1(self.dev, self.model, self.navigator,
                                     self.debug)
            try:
                self.ctap2 = LedgerCtap2(self.dev, self.model, self.navigator,
                                         self.ctap2_u2f_proxy, self.debug)
                self.client_pin = ClientPin(self.ctap2)
            except Exception:
                # Can occurs if the app is build without FIDO2 features.
                # Then only U2F tests can be used.
                print("FIDO2 not supported")
                self.ctap2 = None
                self.client_pin = None

        except Exception as e:
            raise e

    def simulate_reboot(self):
        # Warning, data saved in NVM won't be restored.
        # So this is not a perfect reboot simulation.
        self.ragger_backend._client.stop()
        self.ragger_backend._client.start()
        self.start()
