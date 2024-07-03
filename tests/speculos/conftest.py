import pytest
from pathlib import Path
from ragger.firmware import Firmware
from ragger.backend import SpeculosBackend
from ragger.utils import find_project_root_dir
from typing import Iterable

from client import TestClient

from ragger.conftest import configuration

#######################
# CONFIGURATION START #
#######################

# You can configure optional parameters by overriding the value of
# ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

configuration.OPTIONAL.BACKEND_SCOPE = "module"

#####################
# CONFIGURATION END #
#####################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


##########################
# CONFIGURATION OVERRIDE #
##########################

BACKENDS = ["speculos"]


def pytest_addoption(parser):
    parser.addoption("--transport", default="U2F")
    parser.addoption("--fast", action="store_true")
    parser.addoption("--ctap2_u2f_proxy", action="store_true")


@pytest.fixture(scope="session")
def transport(pytestconfig):
    return pytestconfig.getoption("transport")


@pytest.fixture(scope="session")
def ctap2_u2f_proxy(pytestconfig):
    return pytestconfig.getoption("ctap2_u2f_proxy")


def prepare_speculos_args(root_pytest_dir: Path, firmware: Firmware, display: bool, transport: str):
    speculos_args = ["--usb", transport]

    if display:
        speculos_args += ["--display", "qt"]

    device = firmware.name
    if device == "nanosp":
        device = "nanos2"

    # Find the compiled application for the requested device
    project_root_dir = find_project_root_dir(root_pytest_dir)

    app_path = Path(project_root_dir / "build" / device / "bin" / "app.elf").resolve()
    if not app_path.is_file():
        raise ValueError(f"File '{app_path}' missing. Did you compile for this target?")

    return (app_path, {"args": speculos_args})


# Depending on the "--backend" option value, a different backend is
# instantiated, and the tests will either run on Speculos or on a physical
# device depending on the backend
def create_backend(root_pytest_dir: Path, backend_name: str,
                   firmware: Firmware, display: bool, transport: str):
    if backend_name.lower() == "speculos":
        app_path, speculos_args = prepare_speculos_args(root_pytest_dir, firmware,
                                                        display, transport)
        return SpeculosBackend(app_path,
                               firmware=firmware,
                               **speculos_args)
    else:
        raise ValueError(f"Backend '{backend_name}' is unknown. Valid backends are: {BACKENDS}")


@pytest.fixture(scope="module")
def backend(root_pytest_dir: Path, backend_name: str, firmware: Firmware, display: bool, transport: str):
    with create_backend(root_pytest_dir, backend_name, firmware, display, transport) as b:
        yield b


@pytest.fixture
def client(firmware: Firmware, backend, navigator, transport: str, ctap2_u2f_proxy: bool) -> TestClient:
    client = TestClient(firmware, backend, navigator, transport, ctap2_u2f_proxy)
    client.start()
    return client


@pytest.fixture(autouse=True)
def skip_by_endpoint(request, client):
    if request.node.get_closest_marker('skip_endpoint'):
        endpoint = request.node.get_closest_marker('skip_endpoint').args[0].lower()
        if (client.use_U2F_endpoint and endpoint == "u2f") \
           or (client.use_raw_HID_endpoint and endpoint == "hid"):
            pytest.skip('skipped on this endpoint: {}'.format(endpoint))


@pytest.fixture(autouse=True)
def skip_by_devices(request, firmware):
    if request.node.get_closest_marker('skip_devices'):
        devices = request.node.get_closest_marker('skip_devices').args[0]
        if not isinstance(devices, Iterable):
            devices = [devices]
        if (firmware in devices):
            pytest.skip('skipped on this device: {}'.format(firmware.device))


def pytest_configure(config):
    custom_decorator = [
        "skip_endpoint(endpoint): skip test depending on endpoint (either HID or U2F)",
        "skip_devices(devices): skip test depending on current device"
    ]
    for cd in custom_decorator:
        config.addinivalue_line("markers", cd)
