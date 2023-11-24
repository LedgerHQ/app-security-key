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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

/**
 * Compare two buffer a and b.
 * Return true if they match, else false.
 */
bool crypto_compare(const uint8_t *a, const uint8_t *b, uint16_t length);

/**
 * Compute the sha256 of in1 and in2.
 */
void crypto_compute_sha256(uint8_t *in1,
                           uint32_t in1_len,
                           uint8_t *in2,
                           uint32_t in2_len,
                           uint8_t *out);

/**
 * Generate private key for specific curve from nonce.
 */
int crypto_generate_private_key(const uint8_t *nonce,
                                cx_ecfp_private_key_t *private_key,
                                cx_curve_t curve);

/**
 * Generate public key for specific curve from private key.
 */
int crypto_generate_public_key(cx_ecfp_private_key_t *private_key,
                               uint8_t *public_key,
                               cx_curve_t curve);

/**
 * Generate credRandom key from nonce.
 */
void crypto_generate_credRandom_key(const uint8_t *nonce, uint8_t *credRandom, bool with_uv);

/**
 * Sign data_hash with private_key and store it in signature.
 * Return the length of the signature.
 */
int crypto_sign_application(const uint8_t *data_hash,
                            cx_ecfp_private_key_t *private_key,
                            uint8_t *signature);

/**
 * Sign data_hash with the attestation private key and store it in signature.
 * Return the length of the signature.
 */
int crypto_sign_attestation(const uint8_t *data_hash, uint8_t *signature, bool fido2);

/**
 * Sign message with private_key and store it in signature.
 * Return the length of the signature.
 */
int crypto_sign_application_eddsa(cx_ecfp_private_key_t *private_key,
                                  const uint8_t *message,
                                  uint16_t length,
                                  uint8_t *signature);

#endif
