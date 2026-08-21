"""U2F confirmation latch (u2fUxPending).

Only the latch release is testable. The refusals it guards, in
u2f_handle_apdu_enroll() and u2f_handle_apdu_sign(), are unreachable:

  - HID/USB: the SDK transport answers CHANNEL_BUSY to any command arriving while a
    request is in flight, and no keepalive reopens the channel during a U2F prompt
    (app_ticker_event_callback() only sends them for ctap2UxState).

  - NFC: both handlers answer from the request and return before
    u2f_prompt_user_presence(), so the latch is never set.

The gate is therefore defensive, not a fix for an observable defect.
"""

import pytest
from ..utils import generate_random_bytes


def register(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)
    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)
    return app_param, registration_data


@pytest.mark.skip_endpoint("NFC", reason="CTAP1 is not available on NFC - 0x6D00")
def test_latch_released_after_response_is_built(client):
    # u2fUxPending is cleared once the response is built, so the next sign works.
    app_param, reg = register(client)

    for _ in range(2):
        challenge = generate_random_bytes(32)
        signature_data = client.ctap1.authenticate(challenge, app_param, reg.key_handle)
        signature_data.verify(app_param, challenge, reg.public_key)
