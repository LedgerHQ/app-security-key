/*
 * Unit tests for src/u2f_processing_flow.c: the credential nonce does not outlive the U2F
 * response built from it.
 *
 * The builders are called both after a user confirmation and straight from the NFC
 * fast path, so the nonce must be wiped by the builders themselves. The crypto and the
 * credential wrapping are mocked; the UI and IO calls are fakes.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_rng.h"
#include "Mocklcx_sha256.h"
#include "Mockconfig.h"
#include "Mockcredential.h"
#include "Mockcrypto.h"

// The device libc has strlcpy; older host glibc does not declare it.
size_t strlcpy(char *dst, const char *src, size_t size);

#include "u2f_processing_flow.c"

u2f_service_t G_io_u2f;

static const uint8_t zero_nonce[CREDENTIAL_NONCE_SIZE] = {0};
static uint8_t response[IO_APDU_BUFFER_SIZE];

void ui_idle(void) {
}

void app_nbgl_status(const char *message, bool is_success, nbgl_callback_t on_quit) {
    (void) message;
    (void) is_success;
    (void) on_quit;
}

void app_nbgl_start_review(uint8_t nb_pairs,
                           const nbgl_layoutTagValue_t *pairs,
                           const char *confirm_text,
                           nbgl_choiceCallback_t on_choice,
                           nbgl_callback_t on_select) {
    (void) nb_pairs;
    (void) pairs;
    (void) confirm_text;
    (void) on_choice;
    (void) on_select;
}

bool nfc_io_is_response_pending(void) {
    return false;
}

const char *fido_match_known_appid(const uint8_t *applicationParameter) {
    (void) applicationParameter;
    return NULL;
}

int format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    (void) in;
    (void) in_len;
    (void) out;
    (void) out_len;
    return 0;
}

// UX_WAKE_UP() calls the OS.
bolos_ux_params_t G_ux_params;

unsigned int os_ux(bolos_ux_params_t *params) {
    (void) params;
    return 0;
}

bolos_task_status_t os_sched_last_status(unsigned int task_idx) {
    (void) task_idx;
    return 0;
}

size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t len = strlen(src);
    if (size != 0) {
        size_t n = (len < size - 1) ? len : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
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

static void fake_rng(uint8_t *buffer, size_t len, int cmock_num_calls) {
    (void) cmock_num_calls;
    memset(buffer, 0x4E, len);
}

static int fake_wrap(const uint8_t *rpIdHash,
                     const uint8_t *nonce,
                     credential_data_t *credData,
                     uint8_t *buffer,
                     uint32_t bufferLen,
                     bool isCtap2,
                     bool alreadyResident,
                     int cmock_num_calls) {
    (void) rpIdHash;
    (void) nonce;
    (void) credData;
    (void) buffer;
    (void) isCtap2;
    (void) alreadyResident;
    (void) cmock_num_calls;
    return bufferLen;
}

void setUp(void) {
    memset(globals_get_u2f_data()->nonce, 0x4E, CREDENTIAL_NONCE_SIZE);
    cx_rng_no_throw_Stub(fake_rng);
    crypto_hash_Ignore();
    cx_sha256_init_no_throw_IgnoreAndReturn(CX_OK);
}

void tearDown(void) {
    Mocklcx_rng_Verify();
    Mocklcx_sha256_Verify();
    Mockconfig_Verify();
    Mockcredential_Verify();
    Mockcrypto_Verify();
    Mocklcx_rng_Destroy();
    Mocklcx_sha256_Destroy();
    Mockconfig_Destroy();
    Mockcredential_Destroy();
    Mockcrypto_Destroy();
}

static void assert_nonce_wiped(void) {
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(zero_nonce,
                                          globals_get_u2f_data()->nonce,
                                          CREDENTIAL_NONCE_SIZE,
                                          "credential nonce left in the U2F globals");
}

void test_sign_response_wipes_nonce(void) {
    uint16_t length;

    config_increase_and_get_authentification_counter_IgnoreAndReturn(4);
    crypto_generate_private_key_IgnoreAndReturn(0);
    crypto_sign_application_IgnoreAndReturn(70);

    TEST_ASSERT_EQUAL_HEX16(SW_NO_ERROR, u2f_prepare_sign_response(response, &length));
    assert_nonce_wiped();
}

void test_sign_response_wipes_nonce_on_failure(void) {
    uint16_t length;

    config_increase_and_get_authentification_counter_IgnoreAndReturn(4);
    crypto_generate_private_key_IgnoreAndReturn(-1);

    TEST_ASSERT_EQUAL_HEX16(SW_PROPRIETARY_INTERNAL, u2f_prepare_sign_response(response, &length));
    assert_nonce_wiped();
}

void test_enroll_response_wipes_nonce(void) {
    uint16_t length;

    crypto_generate_private_key_IgnoreAndReturn(0);
    crypto_generate_public_key_IgnoreAndReturn(U2F_ENROLL_USER_KEY_SIZE);
    credential_wrap_Stub(fake_wrap);
    crypto_sign_attestation_IgnoreAndReturn(70);

    TEST_ASSERT_EQUAL_HEX16(SW_NO_ERROR, u2f_prepare_enroll_response(response, &length));
    assert_nonce_wiped();
}

void test_enroll_response_wipes_nonce_on_failure(void) {
    uint16_t length;

    crypto_generate_private_key_IgnoreAndReturn(0);
    crypto_generate_public_key_IgnoreAndReturn(U2F_ENROLL_USER_KEY_SIZE);
    credential_wrap_IgnoreAndReturn(-1);

    TEST_ASSERT_EQUAL_HEX16(SW_PROPRIETARY_INTERNAL,
                            u2f_prepare_enroll_response(response, &length));
    assert_nonce_wiped();
}

// The NFC path takes the nonce generated while idle.
void test_enroll_response_from_pregenerated_nonce_wipes_both_copies(void) {
    uint16_t length;
    static const uint8_t zero[CREDENTIAL_NONCE_SIZE] = {0};

    crypto_generate_private_key_IgnoreAndReturn(0);
    crypto_generate_public_key_IgnoreAndReturn(U2F_ENROLL_USER_KEY_SIZE);
    nfc_idle_work();
    TEST_ASSERT_TRUE(nfc_nonce_and_pubkey_ready);

    credential_wrap_Stub(fake_wrap);
    crypto_sign_attestation_IgnoreAndReturn(70);

    TEST_ASSERT_EQUAL_HEX16(SW_NO_ERROR, u2f_prepare_enroll_response(response, &length));
    TEST_ASSERT_FALSE(nfc_nonce_and_pubkey_ready);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zero, nfc_nonce, CREDENTIAL_NONCE_SIZE);
    assert_nonce_wiped();
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sign_response_wipes_nonce);
    RUN_TEST(test_sign_response_wipes_nonce_on_failure);
    RUN_TEST(test_enroll_response_wipes_nonce);
    RUN_TEST(test_enroll_response_wipes_nonce_on_failure);
    RUN_TEST(test_enroll_response_from_pregenerated_nonce_wipes_both_copies);
    return UNITY_END();
}
