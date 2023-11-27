/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2022 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include <string.h>

#include "os.h"
#include "cx.h"

#include "config.h"
#include "crypto_data.h"
#include "credential.h"
#include "ctap2.h"

#define ROLE_PRIVATE_KEY           0
#define ROLE_CRED_RANDOM_KEY_UV    1
#define ROLE_CRED_RANDOM_KEY_NO_UV 2

bool crypto_compare(const uint8_t *a, const uint8_t *b, uint16_t length) {
    uint16_t given_length = length;
    uint8_t status = 0;
    uint16_t counter = 0;

    if (length == 0) {
        return false;
    }
    while ((length--) != 0) {
        status |= a[length] ^ b[length];
        counter++;
    }
    if (counter != given_length) {
        return false;
    }
    return (status == 0);
}

void crypto_compute_sha256(const uint8_t *in1,
                           uint32_t in1_len,
                           const uint8_t *in2,
                           uint32_t in2_len,
                           uint8_t *out) {
    cx_sha256_t hash;

    cx_sha256_init(&hash);
    cx_hash_no_throw(&hash.header, 0, in1, in1_len, NULL, 0);
    cx_hash_no_throw(&hash.header, CX_LAST, in2, in2_len, out, CX_SHA256_SIZE);
}

int crypto_generate_private_key(const uint8_t *nonce,
                                cx_ecfp_private_key_t *private_key,
                                cx_curve_t curve) {
    int status = 0;
    uint8_t extended_nonce[32];
    uint8_t private_key_data[CREDENTIAL_PRIVATE_KEY_SIZE];

    // private = SHA256((0 << 128 | nonce) || privateKeySeed)
    memset(extended_nonce, 0, sizeof(extended_nonce));
    extended_nonce[15] = ROLE_PRIVATE_KEY;
    memcpy(extended_nonce + 16, nonce, CREDENTIAL_NONCE_SIZE);
    crypto_compute_sha256(extended_nonce,
                          sizeof(extended_nonce),
                          (const uint8_t *) N_u2f.privateKeySeed,
                          sizeof(N_u2f.privateKeySeed),
                          private_key_data);

    if (cx_ecfp_init_private_key_no_throw(curve,
                                          private_key_data,
                                          CREDENTIAL_PRIVATE_KEY_SIZE,
                                          private_key) != CX_OK) {
        PRINTF("Fail to init private key\n");
        status = -1;
    }

    // Reset the private key so that it doesn't stay in RAM.
    explicit_bzero(private_key_data, CREDENTIAL_PRIVATE_KEY_SIZE);

    return status;
}

int crypto_generate_public_key(cx_ecfp_private_key_t *private_key,
                               uint8_t *public_key,
                               cx_curve_t curve) {
    cx_ecfp_public_key_t app_public_key;

    if (cx_ecfp_generate_pair_no_throw(curve, &app_public_key, private_key, 1) != CX_OK) {
        PRINTF("Fail to generate pair\n");
        return -1;
    }
    memmove(public_key, app_public_key.W, app_public_key.W_len);

    return app_public_key.W_len;
}

void crypto_generate_credRandom_key(const uint8_t *nonce, uint8_t *credRandom, bool with_uv) {
    uint8_t extended_nonce[32];

    // credRandomKey = SHA256((1 << 128 | nonce) || privateKeySeed)
    memset(extended_nonce, 0, sizeof(extended_nonce));
    if (with_uv) {
        extended_nonce[15] = ROLE_CRED_RANDOM_KEY_UV;
    } else {
        extended_nonce[15] = ROLE_CRED_RANDOM_KEY_NO_UV;
    }
    memcpy(extended_nonce + 16, nonce, CREDENTIAL_NONCE_SIZE);
    crypto_compute_sha256(extended_nonce,
                          sizeof(extended_nonce),
                          (const uint8_t *) N_u2f.privateKeySeed,
                          sizeof(N_u2f.privateKeySeed),
                          credRandom);
}

static int crypto_sign(const uint8_t *data_hash,
                       cx_ecfp_private_key_t *private_key,
                       uint8_t *signature) {
    size_t length;
    size_t domain_length;

    if (cx_ecdomain_parameters_length(CX_CURVE_SECP256R1, &domain_length) != CX_OK) {
        return -1;
    }

    length = 6 + 2 * (domain_length + 1);
    if (cx_ecdsa_sign_no_throw(private_key,
                               CX_RND_TRNG | CX_LAST,
                               CX_NONE,
                               data_hash,
                               CX_SHA256_SIZE,
                               signature,
                               &length,
                               NULL) != CX_OK) {
        PRINTF("Fail to sign\n");
        return -1;
    }
    signature[0] = 0x30;
    return length;
}

int crypto_sign_application_eddsa(cx_ecfp_private_key_t *private_key,
                                  const uint8_t *message,
                                  uint16_t length,
                                  uint8_t *signature) {
    size_t size;

    if (cx_eddsa_sign_no_throw(private_key, CX_SHA512, message, length, signature, 72) != CX_OK) {
        return -1;
    }

    if (cx_ecdomain_parameters_length(private_key->curve, &size) != CX_OK) {
        return -1;
    }

    return 2 * size;
}

int crypto_sign_application(const uint8_t *data_hash,
                            cx_ecfp_private_key_t *private_key,
                            uint8_t *signature) {
    return crypto_sign(data_hash, private_key, signature);
}

int crypto_sign_attestation(const uint8_t *data_hash, uint8_t *signature, bool fido2) {
    cx_ecfp_private_key_t attestation_private_key;

    if (cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256R1,
                                          (fido2 ? FIDO2_ATTESTATION_KEY : ATTESTATION_KEY),
                                          32,
                                          &attestation_private_key) != CX_OK) {
        return -1;
    }
    return crypto_sign(data_hash, &attestation_private_key, signature);
}
