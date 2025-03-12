import pytest
from fido2.ctap import CtapError

from ..utils import generate_random_bytes, ctap2_get_assertion, Nav
from ..transport import TransportType

# This tests reflects the difference of flows depending on NFC or not, RKs or not, AllowList or not,
# when performing GET_(NEXT_)ASSERTION operations and *several IDs are available*
# - Not NFC -> User can choose the ID on the screen
#           -> Chosen ID is returned
#           -> GET_NEXT_ASSERTION *not* enabled
# - NFC with AllowList -> The first matching ID is returned
#                      -> GET_NEXT_ASSERTION *not* enabled
# - NFC without AllowList, meaning the ID(s) *must* be RK(s) -> The first matching ID is returned
#                                                            -> GET_NEXT_ASSERTION enabled


def test_get_next_assertion_no_context(client):
    # If there was no previous authenticatorGetAssertion request
    # the authenticator should return CTAP2_ERR_NOT_ALLOWED
    with pytest.raises(CtapError) as e:
        client.ctap2.get_next_assertion()

    assert e.value.code == CtapError.ERR.NOT_ALLOWED


def test_get_next_assertion_two_credentials_allowlist(client):
    # Only 'passwordless' (no AllowList) + NFC triggers GET_NEXT_ASSERTION
    t1 = ctap2_get_assertion(client)
    rp = t1.args.rp
    t2 = ctap2_get_assertion(client, rp=rp)

    registered_users = [t1.args.user, t1.args.user]
    client_data_hash = generate_random_bytes(32)
    allow_list = [
        {"id": t1.credential_data.credential_id, "type": "public-key"},
        {"id": t2.credential_data.credential_id, "type": "public-key"},
    ]
    assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                           allow_list,
                                           simple_login=False,
                                           check_users=registered_users)

    # Spec says that:
    # This member [numberOfCredentials] is required when more than one
    # account for the RP and the authenticator does not have a display.
    #
    # Our device has a display, so we check that the return value is
    # always absent, which ends-up with None in the assertion object.
    assert assertion.number_of_credentials is None

    # As numberOfCredentials was not returned, get_next_assertion()
    # request should be refused.
    with pytest.raises(CtapError) as e:
        client.ctap2.get_next_assertion()
    assert e.value.code == CtapError.ERR.NOT_ALLOWED


@pytest.mark.skip_if_not_rk_config_ui
def test_get_next_assertion_two_credentials_rk(client, transport):
    # Only 'passwordless' (no AllowList) + NFC triggers GET_NEXT_ASSERTION
    client.enable_rk_option()

    t1 = ctap2_get_assertion(client, rk=True)
    rp = t1.args.rp
    t2 = ctap2_get_assertion(client, rp=rp, rk=True)
    t3 = ctap2_get_assertion(client, rp=rp, rk=True)

    client_data_hash = generate_random_bytes(32)

    if transport is TransportType.NFC:
        # nothing displayed in this case
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash, navigation=Nav.NONE)
        # GET_NEXT_ASSERTION is enabled!
        # 3 credentials are available
        assert assertion.number_of_credentials == 3
        # they are sorted by age (youngest first)
        assertion.verify(client_data_hash, t3.credential_data.public_key)

        # then the two other credentials are returned (also sorted)
        assertion = client.ctap2.get_next_assertion()
        # only GET_ASSERTION fills the number of credentials
        assert assertion.number_of_credentials is None
        assertion.verify(client_data_hash, t2.credential_data.public_key)

        assertion = client.ctap2.get_next_assertion()
        assert assertion.number_of_credentials is None
        assertion.verify(client_data_hash, t1.credential_data.public_key)

        # Eventually all credentials are consumed, another call returns an error
        with pytest.raises(CtapError) as e:
            client.ctap2.get_next_assertion()
        assert e.value.code == CtapError.ERR.NOT_ALLOWED
    else:
        assertion = client.ctap2.get_assertion(rp["id"], client_data_hash,
                                               simple_login=False,
                                               check_users=None)
        assert assertion.number_of_credentials is None
        assertion.verify(client_data_hash, t3.credential_data.public_key)

        with pytest.raises(CtapError) as e:
            client.ctap2.get_next_assertion()
        assert e.value.code == CtapError.ERR.NOT_ALLOWED
