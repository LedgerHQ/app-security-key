import pytest
import sys

from fido2.ctap import CtapError

from client import TESTS_SPECULOS_DIR
from utils import generate_random_bytes, generate_get_assertion_params
from utils import HAVE_NO_RESET_GENERATION_INCREMENT


def test_reset(client, test_name):
    for validate_step in [0, 2, 3]:
        if validate_step == 2 and "--fast" in sys.argv:
            # Skip additional step on fast mode
            continue
        compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + str(validate_step))

        # Create a credential
        rp, credential_data, _ = generate_get_assertion_params(client)

        # Validate the credential by getting an assertion
        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
        client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list)

        if validate_step == 3:  # Abort
            with pytest.raises(CtapError) as e:
                client.ctap2.reset(validate_step=validate_step, check_screens="full",
                                   compare_args=compare_args)
            assert e.value.code == CtapError.ERR.OPERATION_DENIED

            # Validate the credential is still valid by getting an assertion
            client_data_hash = generate_random_bytes(32)
            allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
            client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list)

        else:  # Confirm
            client.ctap2.reset(validate_step=validate_step, check_screens="full",
                               compare_args=compare_args)

            client_data_hash = generate_random_bytes(32)
            allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
            if HAVE_NO_RESET_GENERATION_INCREMENT:
                # Validate the credential is still valid by getting an assertion
                # ResetGeneration increment is disabled to avoid the UX hurdle when the app
                # is reinstalled. This means credential are not revocated.
                client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list)
            else:
                # Validate the credential is not valid anymore by getting an assertion
                with pytest.raises(CtapError) as e:
                    client.ctap2.get_assertion(rp["id"], client_data_hash, allow_list)
                assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_reset_cancel(client, test_name):
    if client.ctap2_u2f_proxy:
        pytest.skip("Does not work with this transport")

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    with pytest.raises(CtapError) as e:
        client.ctap2.reset(check_screens="full", check_cancel=True,
                           compare_args=compare_args)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL
