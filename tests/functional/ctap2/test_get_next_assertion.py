import pytest
from fido2.ctap import CtapError

from ..utils import generate_random_bytes, ctap2_get_assertion


def test_get_next_assertion_no_context(client):
    # If there was no previous authenticatorGetAssertion request
    # the authenticator should return CTAP2_ERR_NOT_ALLOWED
    with pytest.raises(CtapError) as e:
        client.ctap2.get_next_assertion()

    assert e.value.code == CtapError.ERR.NOT_ALLOWED


def test_get_next_assertion_two_credentials_allowlist(client):
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
                                           login_type="multi",
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
