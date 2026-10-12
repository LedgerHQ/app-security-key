/*
 * Unit tests for src/ctap2/client_pin.c: the PIN hash check, the PIN storage, and the wipe
 * of the key material each subcommand puts on the stack.
 *
 * The helpers are static, so the source is included here. The SDK crypto, the app crypto
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

#include "wipe_check.h"

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
static config_t *writable_config(void) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t) &N_u2f_real & ~((uintptr_t) page - 1);
    uintptr_t end = (uintptr_t) &N_u2f_real + sizeof(N_u2f_real);
    TEST_ASSERT_EQUAL_INT(0, mprotect((void *) start, end - start, PROT_READ | PROT_WRITE));
    return (config_t *) &N_u2f_real;
}

static void set_pin_retries(uint8_t retries) {
    writable_config()->pinRetries = retries;
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
    wipe_check_reset();
}

// Stubs and expectations would otherwise carry over to the next test.
void tearDown(void) {
    Mocklcx_aes_Verify();
    Mocklcx_ecdh_Verify();
    Mocklcx_ecfp_Verify();
    Mocklcx_hmac_Verify();
    Mocklcx_rng_Verify();
    Mocklcx_sha256_Verify();
    Mockconfig_Verify();
    Mockcose_keys_Verify();
    Mockcrypto_Verify();
    Mockctap2_utils_Verify();
    Mockledger_assert_internals_Verify();
    Mocklcx_aes_Destroy();
    Mocklcx_ecdh_Destroy();
    Mocklcx_ecfp_Destroy();
    Mocklcx_hmac_Destroy();
    Mocklcx_rng_Destroy();
    Mocklcx_sha256_Destroy();
    Mockconfig_Destroy();
    Mockcose_keys_Destroy();
    Mockcrypto_Destroy();
    Mockctap2_utils_Destroy();
    Mockledger_assert_internals_Destroy();
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

// A released PIN token is wiped, not only marked unused.
void test_new_pin_wipes_the_previous_pin_token(void) {
    uint8_t pin_enc[MAX_PIN_LENGTH];
    uint8_t plaintext[MAX_PIN_LENGTH] = "aaaa";

    memset(authToken, 0xAA, sizeof(authToken));
    authTokeninUse = true;
    memset(pin_enc, 0xEE, sizeof(pin_enc));
    expect_decrypt(plaintext, sizeof(pin_enc), CX_OK);
    cx_hash_sha256_Stub(fake_sha256);
    config_set_ctap2_pin_Expect(pin_enc);
    send_cbor_response_Expect(&G_io_u2f, 1, NULL);

    handle_store_pin(&G_io_u2f, PIN_PROTOCOL_VERSION_V1, shared_secret, pin_enc, sizeof(pin_enc));
    TEST_ASSERT_FALSE(authTokeninUse);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, authToken, sizeof(authToken));
}

void test_reset_wipes_the_pin_token(void) {
    memset(authToken, 0xAA, sizeof(authToken));
    authTokeninUse = true;
    cx_ecfp_generate_pair_no_throw_IgnoreAndReturn(CX_OK);

    ctap2_client_pin_reset_ctx();
    TEST_ASSERT_FALSE(authTokeninUse);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, authToken, sizeof(authToken));
}

// =========================================================================
// ctap2_client_pin_regenerate: the key agreement scalar never outlives a regeneration
// =========================================================================

static cx_ecfp_private_key_t *generated_key;
static cx_err_t generate_result;
// Result of a call that keeps the private key: the SDK only reads it then.
static cx_err_t keep_result;

static cx_err_t fake_generate_pair(cx_curve_t curve,
                                   cx_ecfp_public_key_t *pubkey,
                                   cx_ecfp_private_key_t *privkey,
                                   bool keepprivate,
                                   int cmock_num_calls) {
    (void) pubkey;
    (void) cmock_num_calls;

    if (keepprivate) {
        return keep_result;
    }
    generated_key = privkey;
    if (generate_result == CX_OK) {
        privkey->curve = curve;
        privkey->d_len = 32;
        memset(privkey->d, 0x5B, sizeof(privkey->d));
    }
    return generate_result;
}

static void prepare_regenerate(cx_err_t result) {
    memset(&ctap2KeyAgreement, 0xAA, sizeof(ctap2KeyAgreement));
    generated_key = NULL;
    generate_result = result;
    keep_result = CX_OK;
    cx_ecfp_generate_pair_no_throw_Stub(fake_generate_pair);
}

void test_regenerate_replaces_the_key_and_wipes_its_copy(void) {
    prepare_regenerate(CX_OK);

    TEST_ASSERT_EQUAL_INT(0, ctap2_client_pin_regenerate());
    TEST_ASSERT_EQUAL(CX_CURVE_SECP256R1, ctap2KeyAgreement.curve);
    TEST_ASSERT_EACH_EQUAL_UINT8(0x5B, ctap2KeyAgreement.d, sizeof(ctap2KeyAgreement.d));
    TEST_ASSERT_NOT_NULL(generated_key);
    TEST_ASSERT_TRUE_MESSAGE(generated_key != &ctap2KeyAgreement,
                             "key generated in place over the old one");
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(generated_key, sizeof(*generated_key)),
                             "new scalar left on the stack");
}

void test_failed_regenerate_wipes_the_old_key(void) {
    prepare_regenerate(CX_INTERNAL_ERROR);

    TEST_ASSERT_EQUAL_INT(-1, ctap2_client_pin_regenerate());
    TEST_ASSERT_EACH_EQUAL_UINT8(0,
                                 (const uint8_t *) &ctap2KeyAgreement,
                                 sizeof(ctap2KeyAgreement));
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(generated_key, sizeof(*generated_key)),
                             "partial scalar left on the stack");
}

// The reset ignores the result, so a failed regeneration must not leave the old key behind.
void test_failed_reset_leaves_no_key_agreement_key(void) {
    prepare_regenerate(CX_INTERNAL_ERROR);

    ctap2_client_pin_reset_ctx();
    TEST_ASSERT_EACH_EQUAL_UINT8(0,
                                 (const uint8_t *) &ctap2KeyAgreement,
                                 sizeof(ctap2KeyAgreement));
}

void test_failed_get_key_agreement_replaces_the_key(void) {
    prepare_regenerate(CX_OK);
    keep_result = CX_INTERNAL_ERROR;
    send_cbor_error_Expect(&G_io_u2f, ERROR_OTHER);

    ctap2_handle_get_key_agreement(&G_io_u2f, NULL, NULL, PIN_PROTOCOL_VERSION_V1);
    TEST_ASSERT_EACH_EQUAL_UINT8(0x5B, ctap2KeyAgreement.d, sizeof(ctap2KeyAgreement.d));
}

void test_failed_get_key_agreement_and_regenerate_wipe_the_key(void) {
    prepare_regenerate(CX_INTERNAL_ERROR);
    keep_result = CX_INTERNAL_ERROR;
    send_cbor_error_Expect(&G_io_u2f, ERROR_OTHER);

    ctap2_handle_get_key_agreement(&G_io_u2f, NULL, NULL, PIN_PROTOCOL_VERSION_V1);
    TEST_ASSERT_EACH_EQUAL_UINT8(0,
                                 (const uint8_t *) &ctap2KeyAgreement,
                                 sizeof(ctap2KeyAgreement));
}

// =========================================================================
// Key material on the stack is wiped before every return
// =========================================================================

// Where the code under test put each key, as seen by the mocks.
static cx_aes_key_t *aes_keys[4];
static int aes_key_count;
static uint8_t *ecdh_secret;
static uint8_t *shared_secret_out;
static cx_hmac_sha256_t *hmac_ctx;

static cx_err_t capture_aes_init_key(const uint8_t *raw_key,
                                     size_t key_len,
                                     cx_aes_key_t *key,
                                     int cmock_num_calls) {
    (void) raw_key;
    (void) key_len;
    (void) cmock_num_calls;

    TEST_ASSERT_LESS_THAN_INT(4, aes_key_count);
    memset(key, 0xA5, sizeof(*key));
    aes_keys[aes_key_count++] = key;
    return CX_OK;
}

static cx_err_t capture_ecdh(const cx_ecfp_private_key_t *private_key,
                             uint32_t mode,
                             const uint8_t *point,
                             size_t point_len,
                             uint8_t *secret,
                             size_t secret_len,
                             int cmock_num_calls) {
    (void) private_key;
    (void) mode;
    (void) point;
    (void) point_len;
    (void) cmock_num_calls;

    memset(secret, 0x5A, secret_len);
    ecdh_secret = secret;
    return CX_OK;
}

static size_t capture_shared_secret(const uint8_t *in,
                                    size_t len,
                                    uint8_t *out,
                                    size_t out_len,
                                    int cmock_num_calls) {
    (void) in;
    (void) len;
    (void) cmock_num_calls;

    memset(out, 0x3C, out_len);
    shared_secret_out = out;
    return out_len;
}

static cx_err_t capture_hmac_init(cx_hmac_sha256_t *hmac,
                                  const uint8_t *key,
                                  size_t key_len,
                                  int cmock_num_calls) {
    (void) key;
    (void) key_len;
    (void) cmock_num_calls;

    memset(hmac, 0x77, sizeof(*hmac));
    hmac_ctx = hmac;
    return CX_OK;
}

static void reset_captures(void) {
    memset(aes_keys, 0, sizeof(aes_keys));
    aes_key_count = 0;
    ecdh_secret = NULL;
    shared_secret_out = NULL;
    hmac_ctx = NULL;
}

static void assert_aes_keys_wiped(int expected) {
    TEST_ASSERT_EQUAL_INT(expected, aes_key_count);
    for (int i = 0; i < aes_key_count; i++) {
        TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(aes_keys[i], sizeof(cx_aes_key_t)),
                                 "AES key schedule left on the stack");
    }
}

static void assert_shared_secret_wiped(void) {
    TEST_ASSERT_NOT_NULL(ecdh_secret);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(ecdh_secret, 32), "ECDH output left on the stack");
    TEST_ASSERT_NOT_NULL(shared_secret_out);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(shared_secret_out, SHARED_SECRET_MAX_SIZE),
                             "shared secret left on the stack");
}

static void expect_decapsulate(void) {
    decode_cose_key_ExpectAnyArgsAndReturn(0);
    cx_ecdh_no_throw_Stub(capture_ecdh);
    cx_hash_sha256_Stub(capture_shared_secret);
}

typedef void (*subcommand_handler_t)(u2f_service_t *service,
                                     cbipDecoder_t *decoder,
                                     cbipItem_t *mapItem,
                                     int protocol);

static void run_subcommand(subcommand_handler_t handler, uint8_t *request, size_t length) {
    cbipDecoder_t decoder;
    cbipItem_t mapItem;

    cbip_decoder_init(&decoder, request, length);
    cbip_first(&decoder, &mapItem);
    handler(&G_io_u2f, &decoder, &mapItem, PIN_PROTOCOL_VERSION_V1);
}

void test_decrypt_wipes_aes_key(void) {
    uint8_t data[16] = {0};
    uint32_t out_len;

    reset_captures();
    cx_aes_init_key_no_throw_Stub(capture_aes_init_key);
    decrypt_out_len = sizeof(data);
    cx_aes_iv_no_throw_Stub(fake_aes_iv);

    TEST_ASSERT_EQUAL_INT(0,
                          ctap2_client_pin_decrypt(PIN_PROTOCOL_VERSION_V1,
                                                   shared_secret,
                                                   data,
                                                   sizeof(data),
                                                   data,
                                                   &out_len));
    assert_aes_keys_wiped(1);
}

void test_decrypt_wipes_aes_key_on_failure(void) {
    uint8_t data[16] = {0};
    uint32_t out_len;

    reset_captures();
    cx_aes_init_key_no_throw_Stub(capture_aes_init_key);
    decrypt_result = CX_INTERNAL_ERROR;
    cx_aes_iv_no_throw_Stub(fake_aes_iv);

    TEST_ASSERT_EQUAL_INT(-1,
                          ctap2_client_pin_decrypt(PIN_PROTOCOL_VERSION_V1,
                                                   shared_secret,
                                                   data,
                                                   sizeof(data),
                                                   data,
                                                   &out_len));
    assert_aes_keys_wiped(1);
}

void test_encrypt_wipes_aes_key(void) {
    uint8_t data[16] = {0};
    uint32_t out_len;

    reset_captures();
    cx_aes_init_key_no_throw_Stub(capture_aes_init_key);
    decrypt_out_len = sizeof(data);
    cx_aes_iv_no_throw_Stub(fake_aes_iv);

    TEST_ASSERT_EQUAL_INT(0,
                          ctap2_client_pin_encrypt(PIN_PROTOCOL_VERSION_V1,
                                                   shared_secret,
                                                   data,
                                                   sizeof(data),
                                                   data,
                                                   &out_len));
    assert_aes_keys_wiped(1);
}

// changePin is the only caller that MACs two messages, through an HMAC context.
void test_verify_wipes_hmac_context(void) {
    static const uint8_t msg[16] = {0};
    static const uint8_t signature[AUTH_PROT_V1_SIZE] = {0};

    reset_captures();
    cx_hmac_sha256_init_no_throw_Stub(capture_hmac_init);
    cx_hmac_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hmac_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    crypto_compare_ExpectAnyArgsAndReturn(true);

    TEST_ASSERT_TRUE(ctap2_client_pin_verify(PIN_PROTOCOL_VERSION_V1,
                                             shared_secret,
                                             sizeof(shared_secret),
                                             msg,
                                             sizeof(msg),
                                             msg,
                                             sizeof(msg),
                                             signature,
                                             sizeof(signature)));
    TEST_ASSERT_NOT_NULL(hmac_ctx);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(hmac_ctx, sizeof(*hmac_ctx)),
                             "HMAC context left on the stack");
}

// {3: {}}: a key agreement, then nothing else, so each subcommand stops right after it.
static uint8_t key_agreement_only[] = {0xA1, 0x03, 0xA0};

void test_set_pin_wipes_shared_secret_on_error(void) {
    reset_captures();
    writable_config()->pinSet = 0;
    expect_decapsulate();
    send_cbor_error_Expect(&G_io_u2f, ERROR_MISSING_PARAMETER);

    run_subcommand(ctap2_handle_set_pin, key_agreement_only, sizeof(key_agreement_only));
    assert_shared_secret_wiped();
}

void test_change_pin_wipes_shared_secret_on_error(void) {
    reset_captures();
    writable_config()->pinSet = 1;
    expect_decapsulate();
    send_cbor_error_Expect(&G_io_u2f, ERROR_MISSING_PARAMETER);

    run_subcommand(ctap2_handle_change_pin, key_agreement_only, sizeof(key_agreement_only));
    assert_shared_secret_wiped();
}

void test_get_pin_token_wipes_shared_secret_on_error(void) {
    reset_captures();
    writable_config()->pinSet = 1;
    expect_decapsulate();
    send_cbor_error_Expect(&G_io_u2f, ERROR_MISSING_PARAMETER);

    run_subcommand(ctap2_handle_get_pin_token, key_agreement_only, sizeof(key_agreement_only));
    assert_shared_secret_wiped();
}

void test_get_pin_token_wipes_shared_secret_and_keys_on_success(void) {
    // {3: {}, 6: h'EE..EE'}: a key agreement and a 16-byte pinHashEnc.
    uint8_t request[5 + PIN_HASH_SIZE] = {0xA2, 0x03, 0xA0, 0x06, 0x40 | PIN_HASH_SIZE};
    static const uint8_t plaintext[PIN_HASH_SIZE] = {0x11};

    memset(request + 5, 0xEE, PIN_HASH_SIZE);
    reset_captures();
    writable_config()->pinSet = 1;
    expect_decapsulate();
    config_decrease_ctap2_pin_retry_counter_Expect();
    cx_aes_init_key_no_throw_Stub(capture_aes_init_key);
    decrypt_plaintext = plaintext;
    decrypt_out_len = PIN_HASH_SIZE;
    cx_aes_iv_no_throw_Stub(fake_aes_iv);
    crypto_compare_ExpectAnyArgsAndReturn(true);
    config_reset_ctap2_pin_retry_counter_Expect();
    cx_rng_no_throw_Ignore();
    send_cbor_response_ExpectAnyArgs();

    run_subcommand(ctap2_handle_get_pin_token, request, sizeof(request));
    assert_shared_secret_wiped();
    // One key to decrypt the PIN hash, one to encrypt the token.
    assert_aes_keys_wiped(2);
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
    RUN_TEST(test_new_pin_wipes_the_previous_pin_token);
    RUN_TEST(test_reset_wipes_the_pin_token);
    RUN_TEST(test_regenerate_replaces_the_key_and_wipes_its_copy);
    RUN_TEST(test_failed_regenerate_wipes_the_old_key);
    RUN_TEST(test_failed_reset_leaves_no_key_agreement_key);
    RUN_TEST(test_failed_get_key_agreement_replaces_the_key);
    RUN_TEST(test_failed_get_key_agreement_and_regenerate_wipe_the_key);
    RUN_TEST(test_decrypt_wipes_aes_key);
    RUN_TEST(test_decrypt_wipes_aes_key_on_failure);
    RUN_TEST(test_encrypt_wipes_aes_key);
    RUN_TEST(test_verify_wipes_hmac_context);
    RUN_TEST(test_set_pin_wipes_shared_secret_on_error);
    RUN_TEST(test_change_pin_wipes_shared_secret_on_error);
    RUN_TEST(test_get_pin_token_wipes_shared_secret_on_error);
    RUN_TEST(test_get_pin_token_wipes_shared_secret_and_keys_on_success);
    return UNITY_END();
}
