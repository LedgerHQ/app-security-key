/*
 * Unit tests for src/ctap2/make_credential/make_credential_utils.c: the credential nonce,
 * pre-generated for NFC or not, does not outlive the makeCredential response.
 *
 * The crypto, the credential wrapping and the CBOR send are mocked; the CBOR encoder is
 * the real one.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_ecfp.h"
#include "Mocklcx_rng.h"
#include "Mocklcx_sha256.h"
#include "Mockconfig.h"
#include "Mockcose_keys.h"
#include "Mockcredential.h"
#include "Mockcrypto.h"
#include "Mockctap2_utils.h"
#include "Mockrk_storage.h"

#include "wipe_check.h"

#include "make_credential_utils.c"

u2f_service_t G_io_u2f;
const uint8_t AAGUID[16];

void performBuiltInUv(void) {
}

static const uint8_t zero_nonce[CREDENTIAL_NONCE_SIZE] = {0};
static uint8_t client_data_hash[CX_SHA256_SIZE];
static const uint8_t *wrapped_nonce;
static int wrap_result;

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

static int capture_wrap(const uint8_t *rpIdHash,
                        const uint8_t *nonce,
                        credential_data_t *credData,
                        uint8_t *buffer,
                        uint32_t bufferLen,
                        bool isCtap2,
                        bool alreadyResident,
                        int cmock_num_calls) {
    (void) rpIdHash;
    (void) credData;
    (void) buffer;
    (void) bufferLen;
    (void) isCtap2;
    (void) alreadyResident;
    (void) cmock_num_calls;

    wrapped_nonce = nonce;
    return wrap_result;
}

void setUp(void) {
    memset(&shared_ctx, 0, sizeof(shared_ctx));
    globals_get_ctap2_register_data()->coseAlgorithm = COSE_ALG_ES256;
    globals_get_ctap2_register_data()->clientDataHash = client_data_hash;
    nfc_nonce_and_pubkey_ready = false;
    memset(nfc_nonce, 0, sizeof(nfc_nonce));
    wrapped_nonce = NULL;
    wrap_result = CREDENTIAL_MINIMAL_SIZE;
    wipe_check_reset();

    cx_rng_no_throw_Stub(fake_rng);
    ctap2_send_keepalive_processing_Ignore();
    config_increase_and_get_authentification_counter_IgnoreAndReturn(4);
    credential_wrap_Stub(capture_wrap);
    cose_alg_to_cx_IgnoreAndReturn(CX_CURVE_SECP256R1);
    crypto_generate_private_key_IgnoreAndReturn(0);
    cx_ecfp_generate_pair_no_throw_IgnoreAndReturn(CX_OK);
    encode_cose_key_IgnoreAndReturn(0);
    cx_hash_sha256_IgnoreAndReturn(CX_SHA256_SIZE);
    crypto_sign_attestation_IgnoreAndReturn(70);
}

void tearDown(void) {
    Mocklcx_ecfp_Verify();
    Mocklcx_rng_Verify();
    Mocklcx_sha256_Verify();
    Mockconfig_Verify();
    Mockcose_keys_Verify();
    Mockcredential_Verify();
    Mockcrypto_Verify();
    Mockctap2_utils_Verify();
    Mockrk_storage_Verify();
    Mocklcx_ecfp_Destroy();
    Mocklcx_rng_Destroy();
    Mocklcx_sha256_Destroy();
    Mockconfig_Destroy();
    Mockcose_keys_Destroy();
    Mockcredential_Destroy();
    Mockcrypto_Destroy();
    Mockctap2_utils_Destroy();
    Mockrk_storage_Destroy();
}

static void assert_nonces_wiped(void) {
    TEST_ASSERT_NOT_NULL(wrapped_nonce);
    TEST_ASSERT_TRUE_MESSAGE(wipe_check_covered(wrapped_nonce, CREDENTIAL_NONCE_SIZE),
                             "credential nonce left on the stack");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(zero_nonce,
                                          nfc_nonce,
                                          CREDENTIAL_NONCE_SIZE,
                                          "pre-generated nonce left in memory");
}

void test_confirm_wipes_fresh_nonce(void) {
    send_cbor_response_ExpectAnyArgs();

    ctap2_make_credential_confirm();
    assert_nonces_wiped();
}

void test_confirm_wipes_pregenerated_nonce(void) {
    check_and_generate_new_pubkey();
    TEST_ASSERT_TRUE(nfc_nonce_and_pubkey_ready);
    send_cbor_response_ExpectAnyArgs();

    ctap2_make_credential_confirm();
    TEST_ASSERT_FALSE(nfc_nonce_and_pubkey_ready);
    assert_nonces_wiped();
}

// A failure before the pre-generated public key is used must not leave it marked ready
// next to a wiped nonce: the next credential would get a public key from another nonce.
void test_failed_confirm_wipes_pregenerated_nonce_and_its_keys(void) {
    check_and_generate_new_pubkey();
    wrap_result = -1;
    send_cbor_error_ExpectAnyArgs();

    ctap2_make_credential_confirm();
    TEST_ASSERT_FALSE(nfc_nonce_and_pubkey_ready);
    assert_nonces_wiped();
}

// A nonce whose public keys are not all ready is never used, whichever derivation failed.
void test_failed_pregeneration_wipes_the_nonce(void) {
    crypto_generate_private_key_StopIgnore();
    for (int failing = 0; failing < 3; failing++) {
        for (int i = 0; i < failing; i++) {
            crypto_generate_private_key_ExpectAnyArgsAndReturn(0);
        }
        crypto_generate_private_key_ExpectAnyArgsAndReturn(-1);

        check_and_generate_new_pubkey();
        TEST_ASSERT_FALSE(nfc_nonce_and_pubkey_ready);
        TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(zero_nonce,
                                              nfc_nonce,
                                              CREDENTIAL_NONCE_SIZE,
                                              "unusable pre-generated nonce left in memory");
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_confirm_wipes_fresh_nonce);
    RUN_TEST(test_confirm_wipes_pregenerated_nonce);
    RUN_TEST(test_failed_confirm_wipes_pregenerated_nonce_and_its_keys);
    RUN_TEST(test_failed_pregeneration_wipes_the_nonce);
    return UNITY_END();
}
