from fido2.ctap2.base import Ctap2, Info
from hashlib import sha256
from ledgered.devices import DeviceType


from ..utils import ENABLE_RK_CONFIG


def test_get_info(client):
    ctap2_info = client.ctap2.get_info()

    assert ctap2_info == client.ctap2.info
    raw_info = Info.from_dict(client.ctap2.send_cbor(Ctap2.CMD.GET_INFO))
    assert raw_info == client.ctap2.info


def test_get_info_version(client):
    info = client.ctap2.info

    assert "U2F_V2" in info.versions
    assert "FIDO_2_0" in info.versions
    assert len(info.versions) == 2


def test_get_info_extensions(client):
    info = client.ctap2.info

    assert "hmac-secret" in info.extensions
    assert len(info.extensions) == 1


def test_get_info_aaguid(client):
    info = client.ctap2.info

    expected_base_string = {
        DeviceType.NANOS: "Ledger FIDO 2 1.0",
        DeviceType.NANOX: "Ledger FIDO 2 1.0 NanoX",
        DeviceType.NANOSP: "Ledger FIDO 2 1.0 NanoS+",
        DeviceType.STAX: "Ledger FIDO 2 1.0 Stax",
        DeviceType.FLEX: "Ledger FIDO 2 1.0 Flex"
    }
    if client.ledger_device.type not in expected_base_string:
        raise ValueError("Unhandled model")

    base_string = expected_base_string[client.ledger_device.type]
    hs = sha256(base_string.encode('utf-8')).hexdigest()
    hs = hs[:32]  # Keep only the 16 first bytes
    assert hs == info.aaguid.hex()


def test_get_info_options(client):
    info = client.ctap2.info

    # Specified options with fix value
    if ENABLE_RK_CONFIG:
        assert not info.options["rk"]
    else:
        assert info.options["rk"]

    assert info.options["up"]
    assert info.options["uv"]
    assert "clientPin" in info.options

    # Value depends on if a pin as been set.
    # Upon boot, pin is never set as we don't have NVM
    assert not info.options["clientPin"]

    # Default value options
    assert not info.options["plat"]

    assert len(info.options) == 5


def test_get_info_max_msg_size(client):
    info = client.ctap2.info
    assert info.max_msg_size == 1024


def test_get_info_pin_protocol(client):
    info = client.ctap2.info
    assert info.pin_uv_protocols == [1]
