import json
import os

from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from fido2.attestation import AttestationVerifier
from fido2.ctap import CtapDevice
from fido2.ctap2.pin import ClientPin
from pathlib import Path
from ledgered.devices import Device, DeviceType

from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID, NavIns
from typing import Optional

from .ctap1_client import LedgerCtap1
from .ctap2_client import LedgerCtap2
from .transport import TransportType
from .transport.hid import LedgerCtapHidDevice
from .transport.nfc import LedgerCtapNFCDevice


TESTS_SPECULOS_DIR = Path(__file__).absolute().parent
REPO_ROOT_DIR = TESTS_SPECULOS_DIR.parent.parent
APP_ELF_PATH = REPO_ROOT_DIR / "bin" / "app.elf"

METADATAS_PATH = REPO_ROOT_DIR / "conformance"
CA_PATH = REPO_ROOT_DIR / "attestations" / "data"
TEST_CA_PATH = CA_PATH / "test" / "ca-cert.pem"
PROD_CA_PATH = CA_PATH / "prod" / "ca-cert.pem"


class LedgerAttestationVerifier(AttestationVerifier):
    def __init__(self, device: Device):
        super().__init__()

        use_prod_ca = os.environ.get("USE_PROD_CA", False)

        if use_prod_ca:
            self.metadata_path = f"{METADATAS_PATH}/prod-{device.name}.json"
            self.ca_path = PROD_CA_PATH
        else:
            self.metadata_path = f"{METADATAS_PATH}/test-{device.name}.json"
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


class TestClient:
    def __init__(self, device: Device,
                 ragger_backend: BackendInterface,
                 navigator: Navigator,
                 transport: TransportType,
                 ctap2_u2f_proxy: bool,
                 debug=False):
        self.ledger_device = device
        self.ragger_backend = ragger_backend
        self.navigator = navigator
        self.debug = debug
        self._transport = transport
        self._device: Optional[CtapDevice] = None

        # CTAP2 (cbor) messages can be sent using CTAPHID.CBOR command or
        # they can be encapsulated in an U2F (APDU) message using INS=0x10
        self.ctap2_u2f_proxy = ctap2_u2f_proxy

        # On USB_HID transport endpoint, only CTAPHID.MSG are supported and they
        # must be sent without encapsulation, e.g. without the header containing
        # the channel ID, the command type and the command length.
        if self._transport is TransportType.HID and not self.ctap2_u2f_proxy:
            print("Enforce using CTAP2 U2F proxy over raw HID endpoint")
            self.ctap2_u2f_proxy = True

    @property
    def device(self) -> CtapDevice:
        assert self._device is not None, "Client must be started before accessing its inner device"
        return self._device

    @property
    def transport(self) -> TransportType:
        return self._transport

    def transported_path(self, name: str) -> str:
        if self.ledger_device.is_nano:
            return name
        return "/".join([name, ("nfc" if self.transport is TransportType.NFC else "usb")])

    def start(self):
        try:
            if self.transport is TransportType.NFC:
                self._device = LedgerCtapNFCDevice(self.ragger_backend, self.debug)
            else:
                self._device = LedgerCtapHidDevice(self.transport, self.debug)

            self.ctap1 = LedgerCtap1(self._device, self.ledger_device, self.navigator, self.debug)
            self.ctap2 = LedgerCtap2(self._device, self.ledger_device, self.navigator,
                                     self.ctap2_u2f_proxy, self.debug)
            self.client_pin = ClientPin(self.ctap2)

        except Exception as e:
            raise e

    def simulate_reboot(self):
        # Warning, data saved in NVM won't be restored.
        # So this is not a perfect reboot simulation.
        self.ragger_backend._client.stop()
        self.ragger_backend._client.start()
        self.start()

    # TODO: clean when the RK will be activated by default
    def activate_rk_option(self):
        if self.ledger_device.is_nano:
            instructions = [
                # Enter in the settings
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                # Enable and skip "Enabling" message
                NavInsID.BOTH_CLICK
            ]

            if self.ledger_device.type == DeviceType.NANOS:
                # Screen 0 -> 5
                instructions += [NavInsID.RIGHT_CLICK] * 5
            else:
                # Screen 0 -> 13
                instructions += [NavInsID.RIGHT_CLICK] * 13

            instructions += [
                NavInsID.BOTH_CLICK,
                # Leave settings
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK
            ]
        else:
            instructions = [
                # Enter in the settings
                NavInsID.USE_CASE_HOME_SETTINGS,
                # Enable and skip "Enabling" message
                NavIns(NavInsID.CHOICE_CHOOSE, (1,)),
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
                # Leave settings
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ]

        self.navigator.navigate(instructions,
                                screen_change_before_first_instruction=False)

    def enable_rk_option(self):
        if self.ctap2.info.options["rk"]:
            return

        if self.ledger_device.is_nano:
            instructions = [
                # Enter in the settings
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                # Enable and skip "Enabling" message
                NavInsID.BOTH_CLICK
            ]
            if self.ledger_device.type != DeviceType.NANOS:
                # Screen 0 -> 5
                instructions += [NavInsID.RIGHT_CLICK] * 5
            else:
                # Screen 0 -> 13
                instructions += [NavInsID.RIGHT_CLICK] * 13
            instructions += [
                NavInsID.BOTH_CLICK,
                # Leave settings
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK
            ]
        else:
            instructions = [
                # Enter in the settings
                NavInsID.USE_CASE_HOME_SETTINGS,
                # Enable and skip "Enabling" message
                NavIns(NavInsID.CHOICE_CHOOSE, (1,)),
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
                # Leave settings
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ]

        self.navigator.navigate(instructions, screen_change_before_first_instruction=False)
        self.ctap2._info = self.ctap2.get_info()
