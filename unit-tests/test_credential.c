/*
 * Unit tests for src/credential.c: what credential wrapping leaves in memory.
 *
 * The AES-SIV calls are mocked: they report where the code under test put the wrapping key,
 * and the test checks those buffers were wiped. The CBOR code is the real one.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_aes_siv.h"
#include "Mockconfig.h"
#include "Mockcose_keys.h"
#include "Mockcrypto.h"
#include "Mockrk_storage.h"

#include "wipe_check.h"

#include "credential.c"

config_t const N_u2f_real;

static const uint8_t rp_id_hash[CX_SHA256_SIZE] = {0x01};
static const uint8_t nonce[CREDENTIAL_NONCE_SIZE] = {0x4E};

// Where the code under test put the key, as seen by cx_aes_siv_set_key.
static cx_aes_siv_context_t *siv_ctx;
static cx_cipher_context_t *cipher_ctx;
static const cipher_key_t *cipher_key;
static cx_err_t crypt_result;

static cx_err_t fake_siv_init(cx_aes_siv_context_t *ctx, int cmock_num_calls) {
    (void) ctx;
    (void) cmock_num_calls;
    return CX_OK;
}

static cx_err_t capture_siv_set_key(cx_aes_siv_context_t *ctx,
                                    const uint8_t *key,
                                    size_t key_bitlen,
                                    int cmock_num_calls) {
    (void) cmock_num_calls;

    // As the SDK does: both halves in the SIV context, and a key schedule in the cipher key.
    memcpy(ctx->key1, key, key_bitlen / 16);
    memcpy(ctx->key2, key + key_bitlen / 16, key_bitlen / 16);
    memset((void *) ctx->cipher_ctx->cipher_key, 0xA5, sizeof(cipher_key_t));
    memset(ctx->cipher_ctx->iv, 0xA5, sizeof(ctx->cipher_ctx->iv));
    siv_ctx = ctx;
    cipher_ctx = ctx->cipher_ctx;
    cipher_key = ctx->cipher_ctx->cipher_key;
    return CX_OK;
}

static cx_err_t fake_siv_encrypt(cx_aes_siv_context_t *ctx,
                                 const uint8_t *input,
                                 size_t in_len,
                                 const uint8_t *aad,
                                 size_t aad_len,
                                 uint8_t *output,
                                 uint8_t *tag,
                                 int cmock_num_calls) {
    (void) ctx;
    (void) aad;
    (void) aad_len;
    (void) cmock_num_calls;

    memmove(output, input, in_len);
    memset(tag, 0x7A, CREDENTIAL_TAG_SIZE);
    return crypt_result;
}

// The SDK writes the plaintext before it checks the tag, so it is there even on a failure.
static cx_err_t fake_siv_decrypt(cx_aes_siv_context_t *ctx,
                                 const uint8_t *input,
                                 size_t in_len,
                                 const uint8_t *aad,
                                 size_t aad_len,
                                 uint8_t *output,
                                 uint8_t *tag,
                                 int cmock_num_calls) {
    (void) ctx;
    (void) input;
    (void) aad;
    (void) aad_len;
    (void) tag;
    (void) cmock_num_calls;

    memset(output, 0x4E, in_len);
    return crypt_result;
}

void setUp(void) {
    siv_ctx = NULL;
    cipher_ctx = NULL;
    cipher_key = NULL;
    crypt_result = CX_OK;
    wipe_check_reset();
    cx_aes_siv_init_Stub(fake_siv_init);
    cx_aes_siv_set_key_Stub(capture_siv_set_key);
    cx_aes_siv_encrypt_Stub(fake_siv_encrypt);
    cx_aes_siv_decrypt_Stub(fake_siv_decrypt);
}

void tearDown(void) {
    Mocklcx_aes_siv_Verify();
    Mockconfig_Verify();
    Mockcose_keys_Verify();
    Mockcrypto_Verify();
    Mockrk_storage_Verify();
    Mocklcx_aes_siv_Destroy();
    Mockconfig_Destroy();
    Mockcose_keys_Destroy();
    Mockcrypto_Destroy();
    Mockrk_storage_Destroy();
}

static void assert_wrapping_key_wiped(void) {
    TEST_ASSERT_NOT_NULL(siv_ctx);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(siv_ctx, sizeof(*siv_ctx)),
                             "AES-SIV context left on the stack");
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(cipher_ctx, sizeof(*cipher_ctx)),
                             "cipher context left on the stack");
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(cipher_key, sizeof(*cipher_key)),
                             "wrapping key schedule left on the stack");
}

static int wrap_u2f(uint8_t *key_handle, uint32_t length) {
    return credential_wrap(rp_id_hash, nonce, NULL, key_handle, length, false, false);
}

void test_wrap_wipes_wrapping_key(void) {
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];

    TEST_ASSERT_EQUAL_INT(sizeof(key_handle), wrap_u2f(key_handle, sizeof(key_handle)));
    assert_wrapping_key_wiped();
}

void test_wrap_wipes_wrapping_key_on_failure(void) {
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];

    crypt_result = CX_INTERNAL_ERROR;
    TEST_ASSERT_LESS_THAN_INT(0, wrap_u2f(key_handle, sizeof(key_handle)));
    assert_wrapping_key_wiped();
}

void test_unwrap_wipes_wrapping_key(void) {
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];
    uint8_t *unwrapped_nonce = NULL;

    TEST_ASSERT_EQUAL_INT(sizeof(key_handle), wrap_u2f(key_handle, sizeof(key_handle)));
    wipe_check_reset();
    siv_ctx = NULL;

    TEST_ASSERT_EQUAL_INT(0,
                          credential_unwrap(rp_id_hash,
                                            key_handle,
                                            sizeof(key_handle),
                                            &unwrapped_nonce,
                                            NULL,
                                            NULL));
    TEST_ASSERT_EQUAL_PTR(key_handle + CREDENTIAL_VERSION_SIZE + CREDENTIAL_TAG_SIZE,
                          unwrapped_nonce);
    assert_wrapping_key_wiped();
}

// A credential ID wrapped for another site fails the tag check, but its nonce has been
// decrypted into the caller's buffer by then.
void test_failed_unwrap_wipes_decrypted_data(void) {
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];
    static const uint8_t zero[CREDENTIAL_NONCE_SIZE] = {0};

    TEST_ASSERT_EQUAL_INT(sizeof(key_handle), wrap_u2f(key_handle, sizeof(key_handle)));
    crypt_result = CX_INVALID_PARAMETER_VALUE;

    TEST_ASSERT_LESS_THAN_INT(
        0,
        credential_unwrap(rp_id_hash, key_handle, sizeof(key_handle), NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(
        zero,
        key_handle + CREDENTIAL_VERSION_SIZE + CREDENTIAL_TAG_SIZE,
        CREDENTIAL_NONCE_SIZE,
        "decrypted nonce left in the caller's buffer");
    // Still wrapped: a later parse must not take it for an unwrapped credential.
    TEST_ASSERT_EQUAL_HEX8(CREDENTIAL_VERSION_U2F, key_handle[0]);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_wrap_wipes_wrapping_key);
    RUN_TEST(test_wrap_wipes_wrapping_key_on_failure);
    RUN_TEST(test_unwrap_wipes_wrapping_key);
    RUN_TEST(test_failed_unwrap_wipes_decrypted_data);
    return UNITY_END();
}
