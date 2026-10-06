/*
 * Unit tests for src/crypto.c: what key derivation leaves in memory.
 *
 * The hash and EC calls are mocked: they report where the code under test put the buffer it
 * hashes with the seed, and the test checks that buffer was wiped.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_ecfp.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_sha256.h"
#include "Mockledger_assert_internals.h"

#include "wipe_check.h"

#include "crypto.c"

config_t const N_u2f_real;

// Signing is not under test here.
cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length) {
    (void) cv;
    *length = 32;
    return CX_OK;
}

cx_err_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                uint32_t mode,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t *sig_len,
                                uint32_t *info) {
    (void) pvkey;
    (void) mode;
    (void) hashID;
    (void) hash;
    (void) hash_len;
    (void) sig;
    (void) sig_len;
    (void) info;
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t sig_len) {
    (void) pvkey;
    (void) hashID;
    (void) hash;
    (void) hash_len;
    (void) sig;
    (void) sig_len;
    return CX_OK;
}

static const uint8_t nonce[CREDENTIAL_NONCE_SIZE] = {0x4E};

// The first block hashed: the role byte and the nonce, in front of the seed.
static const uint8_t *extended_nonce;
// The context the digest is computed in: it ends up holding the digest.
static const cx_hash_t *hash_ctx;
static unsigned int hash_calls;

static cx_err_t capture_hash(cx_hash_t *hash,
                             uint32_t mode,
                             const uint8_t *in,
                             size_t len,
                             uint8_t *out,
                             size_t out_len,
                             int cmock_num_calls) {
    (void) mode;
    (void) len;
    (void) cmock_num_calls;
    if (hash_calls++ == 0) {
        extended_nonce = in;
        hash_ctx = hash;
    }
    if (out) {
        memset(out, 0xA5, out_len);
    }
    return CX_OK;
}

void setUp(void) {
    wipe_check_reset();
    extended_nonce = NULL;
    hash_ctx = NULL;
    hash_calls = 0;
    cx_sha256_init_no_throw_IgnoreAndReturn(CX_OK);
    cx_hash_no_throw_Stub(capture_hash);
}

void tearDown(void) {
}

void test_private_key_derivation_wipes_the_extended_nonce(void) {
    cx_ecfp_private_key_t private_key;

    cx_ecfp_init_private_key_no_throw_IgnoreAndReturn(CX_OK);
    TEST_ASSERT_EQUAL_INT(0, crypto_generate_private_key(nonce, &private_key, CX_CURVE_SECP256R1));
    TEST_ASSERT_NOT_NULL(extended_nonce);
    TEST_ASSERT_TRUE(wipe_check_covered(extended_nonce, 32));
}

void test_private_key_derivation_failure_wipes_the_extended_nonce(void) {
    cx_ecfp_private_key_t private_key;

    cx_ecfp_init_private_key_no_throw_IgnoreAndReturn(CX_INVALID_PARAMETER);
    TEST_ASSERT_EQUAL_INT(-1, crypto_generate_private_key(nonce, &private_key, CX_CURVE_SECP256R1));
    TEST_ASSERT_TRUE(wipe_check_covered(extended_nonce, 32));
}

void test_credRandom_derivation_wipes_the_extended_nonce(void) {
    uint8_t credRandom[CX_SHA256_SIZE];

    crypto_generate_credRandom_key(nonce, credRandom, true);
    TEST_ASSERT_TRUE(wipe_check_covered(extended_nonce, 32));

    wipe_check_reset();
    hash_calls = 0;
    crypto_generate_credRandom_key(nonce, credRandom, false);
    TEST_ASSERT_TRUE(wipe_check_covered(extended_nonce, 32));
}

// The context holds the digest, which is a private key or credRandom here.
void test_sha256_wipes_its_context(void) {
    static const uint8_t in1[4] = {1, 2, 3, 4};
    static const uint8_t in2[4] = {5, 6, 7, 8};
    uint8_t out[CX_SHA256_SIZE];

    crypto_compute_sha256(in1, sizeof(in1), in2, sizeof(in2), out);
    TEST_ASSERT_NOT_NULL(hash_ctx);
    TEST_ASSERT_TRUE(wipe_check_covered(hash_ctx, sizeof(cx_sha256_t)));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_private_key_derivation_wipes_the_extended_nonce);
    RUN_TEST(test_private_key_derivation_failure_wipes_the_extended_nonce);
    RUN_TEST(test_credRandom_derivation_wipes_the_extended_nonce);
    RUN_TEST(test_sha256_wipes_its_context);
    return UNITY_END();
}
