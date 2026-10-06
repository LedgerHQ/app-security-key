/*
 * Unit tests for src/ctap2/get_next_assertion.c: the getAssertion sequence ends with its
 * last credential, so the request it was built from is not kept.
 *
 * The RK list is mocked; the response builder is a fake that only counts its calls.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "Mockrk_storage.h"

#include "get_next_assertion.c"

u2f_service_t G_io_u2f;

static uint8_t last_error;
static int responses_sent;

void send_cbor_error(u2f_service_t *service, uint8_t error) {
    (void) service;
    last_error = error;
}

void get_assertion_send(void) {
    responses_sent++;
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
    responses_sent = 0;
    g.get_next_assertion_enabled = true;
    memset(globals_get_ctap2_data(), 0xEE, sizeof(ctap2_data_t));
}

void tearDown(void) {
    Mockrk_storage_Verify();
}

static void assert_sequence_ended(void) {
    TEST_ASSERT_FALSE(g.get_next_assertion_enabled);
    TEST_ASSERT_EACH_EQUAL_HEX8(0,
                                (const uint8_t *) globals_get_ctap2_data(),
                                sizeof(ctap2_data_t));
}

void test_more_credentials_keep_the_sequence(void) {
    rk_next_credential_from_RKList_IgnoreAndReturn(1);
    rk_count_RKList_ExpectAndReturn(1);

    ctap2_get_next_assertion_handle(&G_io_u2f, NULL, 0);

    TEST_ASSERT_EQUAL_INT(1, responses_sent);
    TEST_ASSERT_TRUE(g.get_next_assertion_enabled);
}

// Clients stop after the count getAssertion gave, so the last credential ends the sequence.
void test_last_credential_ends_the_sequence(void) {
    rk_next_credential_from_RKList_IgnoreAndReturn(1);
    rk_count_RKList_ExpectAndReturn(0);

    ctap2_get_next_assertion_handle(&G_io_u2f, NULL, 0);

    TEST_ASSERT_EQUAL_INT(1, responses_sent);
    assert_sequence_ended();
}

void test_exhausted_list_ends_the_sequence(void) {
    rk_next_credential_from_RKList_IgnoreAndReturn(RK_NOT_FOUND);

    ctap2_get_next_assertion_handle(&G_io_u2f, NULL, 0);

    TEST_ASSERT_EQUAL_INT(0, responses_sent);
    TEST_ASSERT_EQUAL_HEX8(ERROR_NOT_ALLOWED, last_error);
    assert_sequence_ended();
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_more_credentials_keep_the_sequence);
    RUN_TEST(test_last_credential_ends_the_sequence);
    RUN_TEST(test_exhausted_list_ends_the_sequence);
    return UNITY_END();
}
