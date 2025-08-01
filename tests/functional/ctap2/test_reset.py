import pytest

from fido2.ctap import CtapError

from ..client import TESTS_SPECULOS_DIR
from ..utils import generate_random_bytes, ctap2_get_assertion, \
    HAVE_NO_RESET_GENERATION_INCREMENT, Nav


@pytest.mark.skip_endpoint("NFC", reason="CTAP2 reset is not available on NFC - 0x27")
def test_reset(client, test_name):
    for navigation in [Nav.USER_ACCEPT, Nav.USER_REFUSE]:
        compare_args = (TESTS_SPECULOS_DIR, test_name + "/" + navigation.name)

        # Create a credential
        t = ctap2_get_assertion(client)

        # Validate the credential by getting an assertion
        client_data_hash = generate_random_bytes(32)
        allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list)

        if navigation is Nav.USER_REFUSE:
            with pytest.raises(CtapError) as e:
                client.ctap2.reset(navigation=navigation, check_screens=True,
                                   compare_args=compare_args)
            assert e.value.code == CtapError.ERR.OPERATION_DENIED

            # Validate the credential is still valid by getting an assertion
            client_data_hash = generate_random_bytes(32)
            allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
            client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list)

        else:
            client.ctap2.reset(navigation=navigation, check_screens=True,
                               compare_args=compare_args)

            client_data_hash = generate_random_bytes(32)
            allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
            if HAVE_NO_RESET_GENERATION_INCREMENT:
                # Validate the credential is still valid by getting an assertion
                # ResetGeneration increment is disabled to avoid the UX hurdle when the app
                # is reinstalled. This means credential are not revocated.
                client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list)
            else:
                # Validate the credential is not valid anymore by getting an assertion
                with pytest.raises(CtapError) as e:
                    client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list)
                assert e.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.skip_endpoint("NFC", reason="CTAP2 reset is not available on NFC - 0x27")
def test_reset_cancel(client, test_name):
    if client.ctap2_u2f_proxy:
        pytest.skip("Does not work with this transport")

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    with pytest.raises(CtapError) as e:
        client.ctap2.reset(navigation=Nav.CLIENT_CANCEL, compare_args=compare_args)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL
