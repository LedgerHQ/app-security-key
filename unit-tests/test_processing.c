/*
 * Unit tests for src/ctap2/processing.c: how long a gated command's request stays in
 * ctap2RequestBuffer.
 *
 * The request can hold credential IDs decrypted in place, so it must be wiped once nothing
 * reads it, and must stay while a review or a getNextAssertion still does. The command
 * handlers are fakes that start a review or not, as each test needs.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "processing.c"

#define CBOR_EMPTY_MAP 0xA0

u2f_service_t G_io_u2f;

static uint8_t last_error;
static int handler_calls;
static uint8_t request_seen[4];
static ctap2_ux_state_t ux_state_to_start;
static bool enable_next_assertion;

static void fake_handler(uint8_t *buffer, uint16_t length) {
    handler_calls++;
    memcpy(request_seen, buffer, MIN(length, sizeof(request_seen)));
    ctap2UxState = ux_state_to_start;
    if (enable_next_assertion) {
        g.get_next_assertion_enabled = true;
    }
}

void ctap2_make_credential_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    (void) service;
    fake_handler(buffer, length);
}

void ctap2_get_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    (void) service;
    fake_handler(buffer, length);
}

void ctap2_get_next_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    (void) service;
    fake_handler(buffer, length);
}

void ctap2_get_info_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    (void) service;
    fake_handler(buffer, length);
}

void ctap2_client_pin_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    (void) service;
    fake_handler(buffer, length);
}

void ctap2_reset_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    (void) service;
    fake_handler(buffer, length);
}

void send_cbor_error(u2f_service_t *service, uint8_t error) {
    (void) service;
    last_error = error;
}

void ui_idle(void) {
}

bool nbgl_getTextMaxLenInNbLines(nbgl_font_id_e fontId,
                                 const char *text,
                                 uint16_t maxWidth,
                                 uint16_t nbLines,
                                 uint16_t *len,
                                 bool wrapping) {
    (void) fontId;
    (void) maxWidth;
    (void) nbLines;
    (void) wrapping;
    *len = strlen(text);
    return true;
}

void setUp(void) {
    last_error = 0;
    handler_calls = 0;
    memset(request_seen, 0, sizeof(request_seen));
    ux_state_to_start = CTAP2_UX_STATE_NONE;
    enable_next_assertion = false;
    ctap2UxState = CTAP2_UX_STATE_NONE;
    u2fUxPending = false;
    g.get_next_assertion_enabled = false;
    memset(ctap2RequestBuffer, 0, sizeof(ctap2RequestBuffer));
}

void tearDown(void) {
}

static void assert_request_wiped(void) {
    for (size_t i = 0; i < sizeof(ctap2RequestBuffer); i++) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0, ctap2RequestBuffer[i], "request left in memory");
    }
}

static void send_command(uint8_t command) {
    // Bytes after the empty map stand for the rest of a real request.
    uint8_t request[8] = {command, CBOR_EMPTY_MAP, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};
    ctap2_handle_cmd_cbor(&G_io_u2f, request, 2);
}

void test_command_without_review_wipes_its_request(void) {
    send_command(CBOR_MAKE_CREDENTIAL);

    TEST_ASSERT_EQUAL_INT(1, handler_calls);
    TEST_ASSERT_EQUAL_HEX8(CBOR_EMPTY_MAP, request_seen[0]);
    assert_request_wiped();
}

void test_invalid_cbor_wipes_the_request(void) {
    uint8_t request[] = {CBOR_GET_ASSERTION, 0xFF};

    ctap2_handle_cmd_cbor(&G_io_u2f, request, sizeof(request));

    TEST_ASSERT_EQUAL_INT(0, handler_calls);
    TEST_ASSERT_EQUAL_HEX8(ERROR_INVALID_CBOR, last_error);
    assert_request_wiped();
}

void test_review_keeps_the_request_until_it_ends(void) {
    ux_state_to_start = CTAP2_UX_STATE_GET_ASSERTION;
    send_command(CBOR_GET_ASSERTION);

    TEST_ASSERT_EQUAL_HEX8(CBOR_GET_ASSERTION, ctap2RequestBuffer[0]);
    TEST_ASSERT_EQUAL_HEX8(CBOR_EMPTY_MAP, ctap2RequestBuffer[1]);

    ctap2_ux_end();

    TEST_ASSERT_EQUAL_INT(CTAP2_UX_STATE_NONE, ctap2UxState);
    assert_request_wiped();
}

// A command refused while a review is pending must not touch the review's request.
void test_refused_command_keeps_the_pending_request(void) {
    memset(ctap2RequestBuffer, 0xEE, sizeof(ctap2RequestBuffer));
    ctap2UxState = CTAP2_UX_STATE_MAKE_CRED;

    send_command(CBOR_GET_ASSERTION);

    TEST_ASSERT_EQUAL_INT(0, handler_calls);
    TEST_ASSERT_EQUAL_HEX8(ERROR_OPERATION_PENDING, last_error);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, ctap2RequestBuffer, sizeof(ctap2RequestBuffer));
}

// Commands parsed in place never use ctap2RequestBuffer, so they leave a pending one alone.
void test_ungated_command_keeps_the_pending_request(void) {
    memset(ctap2RequestBuffer, 0xEE, sizeof(ctap2RequestBuffer));
    ctap2UxState = CTAP2_UX_STATE_MAKE_CRED;

    send_command(CBOR_CLIENT_PIN);

    TEST_ASSERT_EQUAL_INT(1, handler_calls);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, ctap2RequestBuffer, sizeof(ctap2RequestBuffer));
}

void test_cancel_wipes_the_pending_request(void) {
    memset(ctap2RequestBuffer, 0xEE, sizeof(ctap2RequestBuffer));
    ctap2UxState = CTAP2_UX_STATE_GET_ASSERTION;

    ctap2_handle_cmd_cancel(&G_io_u2f, NULL, 0);

    TEST_ASSERT_EQUAL_HEX8(ERROR_KEEPALIVE_CANCEL, last_error);
    TEST_ASSERT_EQUAL_INT(CTAP2_UX_STATE_NONE, ctap2UxState);
    assert_request_wiped();
}

// A CANCEL leaves nothing for a later getNextAssertion, review or not.
void test_cancel_clears_the_next_assertion_state(void) {
    ctap2_data_t *data = globals_get_ctap2_data();

    for (int ux = 0; ux < 2; ux++) {
        memset(data, 0xEE, sizeof(*data));
        memset(ctap2RequestBuffer, 0xEE, sizeof(ctap2RequestBuffer));
        g.get_next_assertion_enabled = true;
        ctap2UxState = ux ? CTAP2_UX_STATE_GET_ASSERTION : CTAP2_UX_STATE_NONE;

        ctap2_handle_cmd_cancel(&G_io_u2f, NULL, 0);

        TEST_ASSERT_FALSE(g.get_next_assertion_enabled);
        TEST_ASSERT_EACH_EQUAL_HEX8(0, (const uint8_t *) data, sizeof(*data));
        assert_request_wiped();
    }
}

// getNextAssertion reads the getAssertion request again, past its own one-byte request.
void test_get_next_assertion_keeps_the_get_assertion_request(void) {
    enable_next_assertion = true;
    send_command(CBOR_GET_ASSERTION);

    TEST_ASSERT_EQUAL_HEX8(CBOR_EMPTY_MAP, ctap2RequestBuffer[1]);

    uint8_t next[] = {CBOR_GET_NEXT_ASSERTION};
    ctap2_handle_cmd_cbor(&G_io_u2f, next, sizeof(next));

    TEST_ASSERT_EQUAL_INT(2, handler_calls);
    TEST_ASSERT_EQUAL_HEX8(CBOR_GET_NEXT_ASSERTION, ctap2RequestBuffer[0]);
    TEST_ASSERT_EQUAL_HEX8(CBOR_EMPTY_MAP, ctap2RequestBuffer[1]);
}

// The flag outlives its getAssertion, so it must not keep another command's request.
void test_stale_next_assertion_flag_keeps_no_other_request(void) {
    g.get_next_assertion_enabled = true;

    send_command(CBOR_MAKE_CREDENTIAL);

    assert_request_wiped();
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_command_without_review_wipes_its_request);
    RUN_TEST(test_invalid_cbor_wipes_the_request);
    RUN_TEST(test_review_keeps_the_request_until_it_ends);
    RUN_TEST(test_refused_command_keeps_the_pending_request);
    RUN_TEST(test_ungated_command_keeps_the_pending_request);
    RUN_TEST(test_cancel_wipes_the_pending_request);
    RUN_TEST(test_cancel_clears_the_next_assertion_state);
    RUN_TEST(test_get_next_assertion_keeps_the_get_assertion_request);
    RUN_TEST(test_stale_next_assertion_flag_keeps_no_other_request);
    return UNITY_END();
}
