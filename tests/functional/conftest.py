import pytest
from okta.client import Client as OktaClient
from pathlib import Path
from ragger.backend import SpeculosBackend, RaisePolicy
from ragger.conftest.base_conftest import prepare_speculos_args
from ragger.firmware import Firmware
from typing import Iterable, Optional, List

from .client import TestClient
from .transport import TransportType
from .transport.nfc import STATUS_MORE_DATA

pytest_plugins = ("ragger.conftest.base_conftest", )
BACKENDS = ["speculos"]


def pytest_addoption(parser):
    parser.addoption("--transport", default="U2F", choices=("U2F", "HID", "NFC"))
    parser.addoption("--fast", action="store_true")
    parser.addoption("--ctap2_u2f_proxy", action="store_true")
    parser.addoption("--okta", action="store_true", default=False,
                     help="Run the Okta test (else ignored)")
    parser.addoption("--okta-token", type=str, default=None)
    parser.addoption("--okta-url", type=str, default=None)
    parser.addoption("--okta-email", type=str, default=None)
    parser.addoption("--rk-config-ui", action="store_true", default=False,
                     help="Enable RK UI configuration")


@pytest.fixture(scope="session")
def okta_token(pytestconfig) -> Optional[str]:
    okta_token = pytestconfig.getoption("okta_token")
    if okta_token is None:
        raise ValueError("Missing `--okta-token` option")
    return okta_token


@pytest.fixture(scope="session")
def okta_url(pytestconfig) -> Optional[str]:
    okta_url = pytestconfig.getoption("okta_url")
    if okta_url is None:
        raise ValueError("Missing `--okta-url` option")
    return okta_url


@pytest.fixture(scope="session")
def okta_email(pytestconfig) -> Optional[str]:
    okta_email = pytestconfig.getoption("okta_email")
    if okta_email is None:
        raise ValueError("Missing `--okta-email` option")
    return okta_email


@pytest.fixture(scope="session")
def transport(pytestconfig) -> TransportType:
    return TransportType[pytestconfig.getoption("transport")]


@pytest.fixture(scope="session")
def ctap2_u2f_proxy(pytestconfig):
    return pytestconfig.getoption("ctap2_u2f_proxy")


@pytest.fixture(scope="session")
def rk_config_ui(pytestconfig):
    return pytestconfig.getoption("rk_config_ui")


def create_speculos_backend(root_pytest_dir: Path,
                            firmware: Firmware,
                            display: bool,
                            transport: TransportType,
                            cli_user_seed: str,
                            additional_speculos_arguments: List[str]):

    additional_speculos_arguments += ["--transport", transport.name]

    app_path, speculos_args = prepare_speculos_args(root_pytest_dir, firmware,
                                                    display, cli_user_seed,
                                                    additional_speculos_arguments)
    backend = SpeculosBackend(app_path,
                              firmware=firmware,
                              **speculos_args)
    if transport is TransportType.NFC:
        # In NFC, chunked RAPDUs are managed with 0x61XX status code
        backend.raise_policy = RaisePolicy.RAISE_CUSTOM
        backend.whitelisted_status = [0x9000] + \
            [s for s in range(STATUS_MORE_DATA, STATUS_MORE_DATA + 0x0100)]

    return backend


# Depending on the "--backend" option value, a different backend is
# instantiated, and the tests will either run on Speculos or on a physical
# device depending on the backend
def create_backend(root_pytest_dir: Path, backend_name: str,
                   firmware: Firmware, display: bool, transport: TransportType,
                   cli_user_seed: str,
                   additional_speculos_arguments: List[str]):
    if backend_name.lower() != "speculos":
        raise ValueError(f"Backend '{backend_name}' is unknown. Valid backends are: {BACKENDS}")

    return create_speculos_backend(root_pytest_dir, firmware, display, transport,
                                   cli_user_seed, additional_speculos_arguments)


@pytest.fixture(scope="session")
def okta_client(okta_url, okta_token) -> OktaClient:
    config = {"orgUrl": okta_url, 'token': okta_token}
    return OktaClient(config)


@pytest.fixture(scope="class")
def backend(root_pytest_dir: Path, backend_name: str, firmware: Firmware, display: bool,
            transport: TransportType,
            cli_user_seed: str,
            additional_speculos_arguments: List[str]):
    if firmware.is_nano and transport is TransportType.NFC:
        pytest.skip(f"No NFC available on {firmware.name.upper()}")
    with create_backend(root_pytest_dir, backend_name, firmware, display, transport,
                        cli_user_seed, additional_speculos_arguments) as b:
        yield b


@pytest.fixture
def client(firmware: Firmware, backend, navigator, transport: TransportType,
           ctap2_u2f_proxy: bool) -> TestClient:
    client = TestClient(firmware, backend, navigator, transport, ctap2_u2f_proxy)
    client.start()
    return client


@pytest.fixture(scope="class")
def get_2_backends(
        root_pytest_dir: Path,
        backend_name: str,
        firmware: Firmware,
        display: bool,
        transport: TransportType,
        log_apdu_file: Optional[Path],
        cli_user_seed: str,
        additional_speculos_arguments: List[str]):

    if backend_name.lower() != "speculos":
        raise ValueError(f"Backend '{backend_name}' is unknown. Valid backends are: {BACKENDS}")

    b = []
    additional_speculos_arguments_loc = \
        [additional_speculos_arguments + ["--save-nvram"], \
        additional_speculos_arguments + ["--load-nvram"]]

    for i in range(2):
        backend = create_speculos_backend(root_pytest_dir, firmware, display, transport,
                                          cli_user_seed, additional_speculos_arguments_loc[i])
        b.append(backend)

    yield b[0], b[1]


@pytest.fixture(autouse=True)
def skip_by_endpoint(request, transport):
    if request.node.get_closest_marker('skip_endpoint'):
        args = request.node.get_closest_marker('skip_endpoint').args[0]
        reason = request.node.get_closest_marker('skip_endpoint').kwargs.get("reason")
        if not isinstance(args, list):
            endpoints = [TransportType[args]]
        else:
            endpoints = [TransportType[arg] for arg in args]
        if transport in endpoints:
            msg = f"Skipped on endpoint {transport.name}"
            if reason:
                msg += f". Reason: {reason}"
            pytest.skip(msg)


@pytest.fixture(autouse=True)
def skip_by_devices(request, firmware):
    if request.node.get_closest_marker('skip_devices'):
        devices = request.node.get_closest_marker('skip_devices').args[0]
        if not isinstance(devices, Iterable):
            devices = [devices]
        if (firmware in devices):
            pytest.skip('skipped on this device: {}'.format(firmware.device))


@pytest.fixture(autouse=True)
def skip_by_rk_config_ui(request, rk_config_ui):
    if request.node.get_closest_marker('skip_if_not_rk_config_ui'):
        if not rk_config_ui:
            pytest.skip('RK UI setting is not activated')


def pytest_configure(config):
    custom_decorator = [
        "skip_endpoint(endpoint): skip test depending on endpoint (HID, U2F or NFC)",
        "skip_devices(devices): skip test depending on current device",
        "okta: run only the Okta tests",
        "skip_if_not_rk_config_ui: run test with RK UI enabled",
    ]
    for cd in custom_decorator:
        config.addinivalue_line("markers", cd)


def pytest_collection_modifyitems(config, items):
    if config.getoption("--okta"):
        # skipping all the tests, except the one tagged as `okta`
        skip_msg = pytest.mark.skip(reason="Only Okta test running")

        def behavior(item):
            if "okta" not in item.keywords:
                item.add_marker(skip_msg)
    else:
        # skipping only the test tagged as `okta`
        skip_msg = pytest.mark.skip(reason="Default behavior: no Okta test")

        def behavior(item):
            if "okta" in item.keywords:
                item.add_marker(skip_msg)
    for item in items:
        behavior(item)
