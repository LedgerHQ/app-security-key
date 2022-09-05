import pytest

from fido2.ctap import CtapError


def test_selection(client):
    client.ctap2.selection()


def test_selection_refused(client):
    with pytest.raises(CtapError) as e:
        client.ctap2.selection(user_accept=False)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED


def test_selection_cancel(client):
    with pytest.raises(CtapError) as e:
        client.ctap2.selection(check_cancel=True)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL
