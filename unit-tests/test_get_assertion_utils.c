/*
 * Unit tests for src/ctap2/get_assertion/get_assertion_utils.c: what the hmac-secret extension
 * leaves in memory.
 *
 * The PIN protocol and crypto calls are mocked: they report where the code under test put the
 * shared secret and credRandom, and the test checks those buffers were wiped. The CBOR code is
 * the real one.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_hmac.h"
#include "Mockconfig.h"
#include "Mockcrypto.h"
#include "Mockctap2.h"

#include "wipe_check.h"

#include "get_assertion_utils.c"

config_t const N_u2f_real;
u2f_service_t G_io_u2f;

// The display helpers are not under test here.
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

int format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    (void) in;
    (void) in_len;
    if (out_len > 0) {
        out[0] = '\0';
    }
    return 0;
}

// {4: {"hmac-secret": {1: {}, 2: saltEnc (32 bytes), 3: saltAuth (16 bytes)}}}
static uint8_t request[] = {0xA1, 0x04, 0xA1, 0x6B, 'h',  'm',  'a',  'c',  '-',  's',  'e',  'c',
                            'r',  'e',  't',  0xA3, 0x01, 0xA0, 0x02, 0x58, 0x20, 0x11, 0x11, 0x11,
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x03, 0x50, 0x22, 0x22, 0x22, 0x22, 0x22,
                            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
static uint8_t request_buffer[CUSTOM_IO_APDU_BUFFER_SIZE];

// Where the code under test put each secret, as seen by the mocks.
static const uint8_t *shared_secret;
static const uint8_t *cred_random;
static int decapsulate_result;

static int capture_decapsulate(int protocol,
                               cbipDecoder_t *decoder,
                               cbipItem_t *mapItem,
                               int key,
                               uint8_t *sharedSecret,
                               int cmock_num_calls) {
    (void) protocol;
    (void) decoder;
    (void) mapItem;
    (void) key;
    (void) cmock_num_calls;
    shared_secret = sharedSecret;
    memset(sharedSecret, 0x5E, SHARED_SECRET_MAX_SIZE);
    return decapsulate_result;
}

static int fake_decrypt(int protocol,
                        const uint8_t *sharedSecret,
                        const uint8_t *dataIn,
                        uint32_t dataInLength,
                        uint8_t *dataOut,
                        uint32_t *dataOutLength,
                        int cmock_num_calls) {
    (void) protocol;
    (void) sharedSecret;
    (void) dataIn;
    (void) dataOut;
    (void) cmock_num_calls;
    *dataOutLength = dataInLength;
    return 0;
}

static int fake_encrypt(int protocol,
                        const uint8_t *sharedSecret,
                        const uint8_t *dataIn,
                        uint32_t dataInLength,
                        uint8_t *dataOut,
                        uint32_t *dataOutLength,
                        int cmock_num_calls) {
    (void) protocol;
    (void) sharedSecret;
    (void) dataIn;
    (void) dataOut;
    (void) cmock_num_calls;
    *dataOutLength = dataInLength;
    return 0;
}

static void capture_cred_random(const uint8_t *nonce,
                                uint8_t *credRandom,
                                bool with_uv,
                                int cmock_num_calls) {
    (void) nonce;
    (void) with_uv;
    (void) cmock_num_calls;
    cred_random = credRandom;
    memset(credRandom, 0xC4, CRED_RANDOM_SIZE);
}

void setUp(void) {
    ctap2_assert_data_t *assert_data = globals_get_ctap2_assert_data();

    memset(assert_data, 0, sizeof(*assert_data));
    memset(request_buffer, 0, sizeof(request_buffer));
    memcpy(request_buffer, request, sizeof(request));
    assert_data->buffer = request_buffer;
    assert_data->extensions = FLAG_EXTENSION_HMAC_SECRET;

    wipe_check_reset();
    shared_secret = NULL;
    cred_random = NULL;
    decapsulate_result = ERROR_NONE;
    ctap2_client_pin_decapsulate_Stub(capture_decapsulate);
    ctap2_client_pin_decrypt_Stub(fake_decrypt);
    ctap2_client_pin_encrypt_Stub(fake_encrypt);
    cx_hmac_sha256_IgnoreAndReturn(CX_SHA256_SIZE);
    crypto_generate_credRandom_key_Stub(capture_cred_random);
    config_increase_and_get_authentification_counter_IgnoreAndReturn(4);
}

void tearDown(void) {
}

static void assert_shared_secret_wiped(void) {
    TEST_ASSERT_NOT_NULL(shared_secret);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(shared_secret, SHARED_SECRET_MAX_SIZE),
                             "hmac-secret shared secret not wiped");
}

// V-013: the shared secret is wiped on every exit of compute_hmacSecret_output().
void test_hmac_secret_wipes_the_shared_secret_on_success(void) {
    uint8_t cred[CRED_RANDOM_SIZE] = {0};
    uint8_t *output = NULL;
    uint32_t output_len = 0;

    ctap2_client_pin_verify_IgnoreAndReturn(true);
    TEST_ASSERT_EQUAL_INT(ERROR_NONE, compute_hmacSecret_output(&output, &output_len, cred));
    TEST_ASSERT_EQUAL_UINT32(HMAC_SECRET_SALT_SIZE, output_len);
    assert_shared_secret_wiped();
}

void test_hmac_secret_wipes_the_shared_secret_on_decapsulate_failure(void) {
    uint8_t cred[CRED_RANDOM_SIZE] = {0};
    uint8_t *output = NULL;
    uint32_t output_len = 0;

    decapsulate_result = ERROR_INVALID_PAR;
    TEST_ASSERT_EQUAL_INT(ERROR_INVALID_PAR, compute_hmacSecret_output(&output, &output_len, cred));
    assert_shared_secret_wiped();
}

void test_hmac_secret_wipes_the_shared_secret_on_bad_salt_auth(void) {
    uint8_t cred[CRED_RANDOM_SIZE] = {0};
    uint8_t *output = NULL;
    uint32_t output_len = 0;

    ctap2_client_pin_verify_IgnoreAndReturn(false);
    TEST_ASSERT_EQUAL_INT(ERROR_INVALID_CBOR,
                          compute_hmacSecret_output(&output, &output_len, cred));
    assert_shared_secret_wiped();
}

// V-014: credRandom is wiped once the hmac-secret output is built, or has failed.
void test_auth_data_wipes_cred_random(void) {
    uint8_t buffer[512];
    uint32_t len = 0;

    ctap2_client_pin_verify_IgnoreAndReturn(true);
    TEST_ASSERT_EQUAL_INT(ERROR_NONE, build_authData(buffer, sizeof(buffer), &len));
    TEST_ASSERT_NOT_NULL(cred_random);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(cred_random, CRED_RANDOM_SIZE),
                             "credRandom not wiped");
}

void test_auth_data_wipes_cred_random_on_hmac_secret_failure(void) {
    uint8_t buffer[512];
    uint32_t len = 0;

    decapsulate_result = ERROR_INVALID_PAR;
    TEST_ASSERT_EQUAL_INT(ERROR_INVALID_PAR, build_authData(buffer, sizeof(buffer), &len));
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(cred_random, CRED_RANDOM_SIZE),
                             "credRandom not wiped");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_hmac_secret_wipes_the_shared_secret_on_success);
    RUN_TEST(test_hmac_secret_wipes_the_shared_secret_on_decapsulate_failure);
    RUN_TEST(test_hmac_secret_wipes_the_shared_secret_on_bad_salt_auth);
    RUN_TEST(test_auth_data_wipes_cred_random);
    RUN_TEST(test_auth_data_wipes_cred_random_on_hmac_secret_failure);
    return UNITY_END();
}
