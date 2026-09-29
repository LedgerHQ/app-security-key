/*
 * Unit tests for the PIN hash check and the PIN storage in src/ctap2/client_pin.c.
 *
 * Both helpers are static, so the source is included here. The SDK crypto, the app crypto
 * and the NVM config are mocked; the CBOR code is the real one.
 */

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "unity.h"

#include "Mocklcx_aes.h"
#include "Mocklcx_ecdh.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_hmac.h"
#include "Mocklcx_rng.h"
#include "Mocklcx_sha256.h"
#include "Mockconfig.h"
#include "Mockcose_keys.h"
#include "Mockcrypto.h"
#include "Mockctap2_utils.h"
#include "Mockledger_assert_internals.h"

#include "client_pin.c"

uint8_t responseBuffer[IO_APDU_BUFFER_SIZE];
u2f_service_t G_io_u2f;
config_t const N_u2f_real;

static const uint8_t shared_secret[SHARED_SECRET_MAX_SIZE] = {0x42};

// What the mocked AES-CBC decrypt writes and reports.
static const uint8_t *decrypt_plaintext;
static size_t decrypt_out_len;
static cx_err_t decrypt_result;

static cx_err_t fake_aes_iv(const cx_aes_key_t *key,
                            uint32_t mode,
                            const uint8_t *iv,
                            size_t iv_len,
                            const uint8_t *in,
                            size_t in_len,
                            uint8_t *out,
                            size_t *out_len,
                            int cmock_num_calls) {
    (void) key;
    (void) mode;
    (void) iv;
    (void) iv_len;
    (void) in;
    (void) cmock_num_calls;

    if (decrypt_plaintext != NULL) {
        memcpy(out, decrypt_plaintext, in_len);
    }
    *out_len = decrypt_out_len;
    return decrypt_result;
}

static size_t fake_sha256(const uint8_t *in,
                          size_t len,
                          uint8_t *out,
                          size_t out_len,
                          int cmock_num_calls) {
    (void) in;
    (void) len;
    (void) cmock_num_calls;

    memset(out, 0xC3, out_len);
    return out_len;
}

// N_u2f_real is const, so the host linker puts it in .rodata; the device keeps it in NVM.
static void set_pin_retries(uint8_t retries) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t) &N_u2f_real & ~((uintptr_t) page - 1);
    uintptr_t end = (uintptr_t) &N_u2f_real + sizeof(N_u2f_real);
    TEST_ASSERT_EQUAL_INT(0, mprotect((void *) start, end - start, PROT_READ | PROT_WRITE));
    ((config_t *) &N_u2f_real)->pinRetries = retries;
}

static void expect_decrypt(const uint8_t *plaintext, size_t out_len, cx_err_t result) {
    decrypt_plaintext = plaintext;
    decrypt_out_len = out_len;
    decrypt_result = result;
    cx_aes_init_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_aes_iv_no_throw_Stub(fake_aes_iv);
}

void setUp(void) {
    decrypt_plaintext = NULL;
    decrypt_out_len = 0;
    decrypt_result = CX_OK;
    ctap2TransientPinAuths = 0;
    set_pin_retries(8);
}

void tearDown(void) {
}

// =========================================================================
// check_pin_hash
// =========================================================================

// Refused before the retry counter or the AES: no mock is expected, so any call fails.
void test_check_pin_hash_refuses_bad_encrypted_length(void) {
    uint8_t pin_hash_enc[32] = {0};
    static const uint32_t lengths[] = {0, 15, 17, 32};

    for (unsigned int i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        TEST_ASSERT_EQUAL_INT(
            ERROR_INVALID_PAR,
            check_pin_hash(PIN_PROTOCOL_VERSION_V1, shared_secret, pin_hash_enc, lengths[i]));
    }
    TEST_ASSERT_EQUAL_UINT8(0, ctap2TransientPinAuths);
}

// A decrypt that reports a short output must not reach the compare.
void test_check_pin_hash_refuses_short_decrypted_hash(void) {
    uint8_t pin_hash_enc[PIN_HASH_SIZE];
    static const uint8_t plaintext[PIN_HASH_SIZE] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t zero[PIN_HASH_SIZE] = {0};

    memset(pin_hash_enc, 0xEE, sizeof(pin_hash_enc));
    config_decrease_ctap2_pin_retry_counter_Expect();
    expect_decrypt(plaintext, 0, CX_OK);

    TEST_ASSERT_EQUAL_INT(
        ERROR_PIN_INVALID,
        check_pin_hash(PIN_PROTOCOL_VERSION_V1, shared_secret, pin_hash_enc, PIN_HASH_SIZE));
    TEST_ASSERT_EQUAL_UINT8(1, ctap2TransientPinAuths);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zero, pin_hash_enc, PIN_HASH_SIZE);
}

void test_check_pin_hash_wipes_on_decrypt_failure(void) {
    uint8_t pin_hash_enc[PIN_HASH_SIZE];
    static const uint8_t plaintext[PIN_HASH_SIZE] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t zero[PIN_HASH_SIZE] = {0};

    memset(pin_hash_enc, 0xEE, sizeof(pin_hash_enc));
    config_decrease_ctap2_pin_retry_counter_Expect();
    expect_decrypt(plaintext, PIN_HASH_SIZE, CX_INTERNAL_ERROR);

    TEST_ASSERT_EQUAL_INT(
        ERROR_PIN_INVALID,
        check_pin_hash(PIN_PROTOCOL_VERSION_V1, shared_secret, pin_hash_enc, PIN_HASH_SIZE));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zero, pin_hash_enc, PIN_HASH_SIZE);
}

void test_check_pin_hash_wipes_on_match(void) {
    uint8_t pin_hash_enc[PIN_HASH_SIZE];
    static const uint8_t plaintext[PIN_HASH_SIZE] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t zero[PIN_HASH_SIZE] = {0};

    memset(pin_hash_enc, 0xEE, sizeof(pin_hash_enc));
    config_decrease_ctap2_pin_retry_counter_Expect();
    expect_decrypt(plaintext, PIN_HASH_SIZE, CX_OK);
    crypto_compare_ExpectAndReturn(pin_hash_enc, (uint8_t *) N_u2f.pin, PIN_HASH_SIZE, true);
    config_reset_ctap2_pin_retry_counter_Expect();

    TEST_ASSERT_EQUAL_INT(
        ERROR_NONE,
        check_pin_hash(PIN_PROTOCOL_VERSION_V1, shared_secret, pin_hash_enc, PIN_HASH_SIZE));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zero, pin_hash_enc, PIN_HASH_SIZE);
}

void test_check_pin_hash_wipes_on_mismatch(void) {
    uint8_t pin_hash_enc[PIN_HASH_SIZE];
    static const uint8_t plaintext[PIN_HASH_SIZE] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t zero[PIN_HASH_SIZE] = {0};

    memset(pin_hash_enc, 0xEE, sizeof(pin_hash_enc));
    config_decrease_ctap2_pin_retry_counter_Expect();
    expect_decrypt(plaintext, PIN_HASH_SIZE, CX_OK);
    crypto_compare_ExpectAndReturn(pin_hash_enc, (uint8_t *) N_u2f.pin, PIN_HASH_SIZE, false);
    cx_ecfp_generate_pair_no_throw_ExpectAnyArgsAndReturn(CX_OK);

    TEST_ASSERT_EQUAL_INT(
        ERROR_PIN_INVALID,
        check_pin_hash(PIN_PROTOCOL_VERSION_V1, shared_secret, pin_hash_enc, PIN_HASH_SIZE));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zero, pin_hash_enc, PIN_HASH_SIZE);
}

// =========================================================================
// handle_store_pin: the decrypted new PIN and its hash are wiped on every exit
// =========================================================================

static void assert_wiped(const uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, buffer[i], "PIN bytes left in the request buffer");
    }
}

void test_store_pin_wipes_on_decrypt_failure(void) {
    uint8_t pin_enc[MAX_PIN_LENGTH];
    uint8_t plaintext[MAX_PIN_LENGTH] = "aaaa";

    memset(pin_enc, 0xEE, sizeof(pin_enc));
    expect_decrypt(plaintext, sizeof(pin_enc), CX_INTERNAL_ERROR);
    send_cbor_error_Expect(&G_io_u2f, ERROR_PIN_POLICY_VIOLATION);

    handle_store_pin(&G_io_u2f, PIN_PROTOCOL_VERSION_V1, shared_secret, pin_enc, sizeof(pin_enc));
    assert_wiped(pin_enc, sizeof(pin_enc));
}

void test_store_pin_wipes_on_bad_padded_length(void) {
    uint8_t pin_enc[32];
    uint8_t plaintext[32] = "aaaa";

    memset(pin_enc, 0xEE, sizeof(pin_enc));
    expect_decrypt(plaintext, sizeof(pin_enc), CX_OK);
    send_cbor_error_Expect(&G_io_u2f, ERROR_INVALID_PAR);

    handle_store_pin(&G_io_u2f, PIN_PROTOCOL_VERSION_V1, shared_secret, pin_enc, sizeof(pin_enc));
    assert_wiped(pin_enc, sizeof(pin_enc));
}

void test_store_pin_wipes_on_short_pin(void) {
    uint8_t pin_enc[MAX_PIN_LENGTH];
    uint8_t plaintext[MAX_PIN_LENGTH] = "aaa";

    memset(pin_enc, 0xEE, sizeof(pin_enc));
    expect_decrypt(plaintext, sizeof(pin_enc), CX_OK);
    send_cbor_error_Expect(&G_io_u2f, ERROR_PIN_POLICY_VIOLATION);

    handle_store_pin(&G_io_u2f, PIN_PROTOCOL_VERSION_V1, shared_secret, pin_enc, sizeof(pin_enc));
    assert_wiped(pin_enc, sizeof(pin_enc));
}

void test_store_pin_wipes_on_success(void) {
    uint8_t pin_enc[MAX_PIN_LENGTH];
    uint8_t plaintext[MAX_PIN_LENGTH] = "aaaa";

    memset(pin_enc, 0xEE, sizeof(pin_enc));
    expect_decrypt(plaintext, sizeof(pin_enc), CX_OK);
    cx_hash_sha256_Stub(fake_sha256);
    config_set_ctap2_pin_Expect(pin_enc);
    send_cbor_response_Expect(&G_io_u2f, 1, NULL);

    handle_store_pin(&G_io_u2f, PIN_PROTOCOL_VERSION_V1, shared_secret, pin_enc, sizeof(pin_enc));
    assert_wiped(pin_enc, sizeof(pin_enc));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_check_pin_hash_refuses_bad_encrypted_length);
    RUN_TEST(test_check_pin_hash_refuses_short_decrypted_hash);
    RUN_TEST(test_check_pin_hash_wipes_on_decrypt_failure);
    RUN_TEST(test_check_pin_hash_wipes_on_match);
    RUN_TEST(test_check_pin_hash_wipes_on_mismatch);
    RUN_TEST(test_store_pin_wipes_on_decrypt_failure);
    RUN_TEST(test_store_pin_wipes_on_bad_padded_length);
    RUN_TEST(test_store_pin_wipes_on_short_pin);
    RUN_TEST(test_store_pin_wipes_on_success);
    return UNITY_END();
}
