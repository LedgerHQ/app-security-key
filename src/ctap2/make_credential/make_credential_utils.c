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

#include <os_io.h>

#include "cbip_helper.h"
#include "config.h"
#include "cose_keys.h"
#include "crypto.h"
#include "crypto_data.h"
#include "ctap2.h"
#include "ctap2_utils.h"
#include "globals.h"
#include "rk_storage.h"
#include "ui_messages.h"

#include "make_credential_utils.h"

#define TAG_RESP_FMT      0x01
#define TAG_RESP_AUTHDATA 0x02
#define TAG_RESP_ATTSTMT  0x03

#define ATTESTATION_FORMAT_PACKED "packed"

static int generate_pubkey(const uint8_t *nonce, int coseAlgorithm, cx_ecfp_public_key_t *pubkey) {
    cx_ecfp_private_key_t privateKey;
    cx_curve_t bolosCurve = cose_alg_to_cx(coseAlgorithm);

    if (crypto_generate_private_key(nonce, &privateKey, bolosCurve) != 0) {
        return -1;
    }
    if (cx_ecfp_generate_pair_no_throw(bolosCurve, pubkey, &privateKey, 1) != CX_OK) {
        explicit_bzero(&privateKey, sizeof(privateKey));
        return -1;
    }
    explicit_bzero(&privateKey, sizeof(privateKey));
    return 0;
}

#ifdef HAVE_NFC
static bool nfc_nonce_and_pubkey_ready;
static uint8_t nfc_nonce[CREDENTIAL_NONCE_SIZE];
static cx_ecfp_public_key_t nfc_pubkey_ES256;
static cx_ecfp_public_key_t nfc_pubkey_ES256K;
static cx_ecfp_public_key_t nfc_pubkey_EDDSA;

void check_and_generate_new_pubkey(void) {
    // Generate a new nonce/pubkey pair only if not already available and in idle
    if (nfc_nonce_and_pubkey_ready) {
        return;
    }

    cx_rng_no_throw(nfc_nonce, CREDENTIAL_NONCE_SIZE);

    if (generate_pubkey(nfc_nonce, COSE_ALG_ES256, &nfc_pubkey_ES256) != 0) {
        return;
    }

    if (generate_pubkey(nfc_nonce, COSE_ALG_ES256K, &nfc_pubkey_ES256K) != 0) {
        return;
    }

    if (generate_pubkey(nfc_nonce, COSE_ALG_EDDSA, &nfc_pubkey_EDDSA) != 0) {
        return;
    }

    nfc_nonce_and_pubkey_ready = true;
}
#endif

static int encode_makeCred_public_key(const uint8_t *nonce,
                                      int coseAlgorithm,
                                      uint8_t *buffer,
                                      uint32_t bufferLength) {
    cbipEncoder_t encoder;
    cx_ecfp_public_key_t publicKey;
    int status;

#ifdef HAVE_NFC
    // Spare response time by pre-generating part of the answer
    if (nfc_nonce_and_pubkey_ready) {
        switch (coseAlgorithm) {
            case COSE_ALG_ES256:
                memcpy(&publicKey, &nfc_pubkey_ES256, sizeof(publicKey));
                break;
            case COSE_ALG_ES256K:
                memcpy(&publicKey, &nfc_pubkey_ES256K, sizeof(publicKey));
                break;
            case COSE_ALG_EDDSA:
                memcpy(&publicKey, &nfc_pubkey_EDDSA, sizeof(publicKey));
                break;
            default:
                return -1;
        }

        nfc_nonce_and_pubkey_ready = false;
    } else
#endif
    {
        if (generate_pubkey(nonce, coseAlgorithm, &publicKey) != 0) {
            return -1;
        }
    }

    cbip_encoder_init(&encoder, buffer, bufferLength);
    status = encode_cose_key(&encoder, &publicKey, false);

    if ((status < 0) || encoder.fault) {
        PRINTF("Public key encoding failed\n");
        return -1;
    }

    return encoder.offset;
}

static int build_makeCred_authData(uint8_t *nonce, uint8_t *buffer, uint32_t bufferLength) {
    credential_data_t ctap2CredentailData;
    int status;
    uint32_t offset = 0;
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    memmove(buffer, ctap2RegisterData->rpIdHash, CX_SHA256_SIZE);
    offset += CX_SHA256_SIZE;

    buffer[offset] = AUTHDATA_FLAG_USER_PRESENCE | AUTHDATA_FLAG_ATTESTED_CREDENTIAL_DATA_PRESENT;
    if (ctap2RegisterData->pinRequired || ctap2RegisterData->clientPinAuthenticated) {
        buffer[offset] |= AUTHDATA_FLAG_USER_VERIFIED;
    }
    if (ctap2RegisterData->extensions != 0) {
        buffer[offset] |= AUTHDATA_FLAG_EXTENSION_DATA_PRESENT;
    }
    offset++;

    // Add Counter
    config_increase_and_get_authentification_counter(buffer + offset);
    offset += 4;

    // Add AAGUID
    memmove(buffer + offset, AAGUID, sizeof(AAGUID));
    offset += sizeof(AAGUID);

    // Add the credential
    memset(&ctap2CredentailData, 0, sizeof(ctap2CredentailData));
    ctap2CredentailData.userId = ctap2RegisterData->userId;
    ctap2CredentailData.userIdLen = ctap2RegisterData->userIdLen;
    ctap2CredentailData.userStr = ctap2RegisterData->userStr;
    ctap2CredentailData.userStrLen = ctap2RegisterData->userStrLen;
    ctap2CredentailData.coseAlgorithm = ctap2RegisterData->coseAlgorithm;
    ctap2CredentailData.residentKey = ctap2RegisterData->residentKey;
    status = credential_wrap(ctap2RegisterData->rpIdHash,
                             nonce,
                             &ctap2CredentailData,
                             buffer + offset + 2,  // Reserve 2 bytes to insert credential length
                             bufferLength - offset - 2,
                             true,
                             false);
    if (status < 0) {
        return status;
    }

    // Fill the 2 reserved bytes for credential length
    U2BE_ENCODE(buffer, offset, status);
    offset += 2 + status;

    // Add the public key
    status = encode_makeCred_public_key(nonce,
                                        ctap2RegisterData->coseAlgorithm,
                                        buffer + offset,
                                        bufferLength - offset);
    if (status < 0) {
        return status;
    }
    offset += status;

    // Add extensions
    if (ctap2RegisterData->extensions != 0) {
        cbipEncoder_t encoder;

        cbip_encoder_init(&encoder, buffer + offset, bufferLength - offset);
        cbip_add_map_header(&encoder, 1);
        cbip_add_string(&encoder, EXTENSION_HMAC_SECRET, sizeof(EXTENSION_HMAC_SECRET) - 1);
        cbip_add_boolean(&encoder, true);
        if (encoder.fault) {
            PRINTF("Error encoding extensions\n");
            return -1;
        }
        offset += encoder.offset;
    }

    return offset;
}

static int sign_and_build_makeCred_response(uint8_t *authData,
                                            uint32_t authDataLen,
                                            uint8_t *buffer,
                                            uint32_t bufferLen) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    uint8_t hashData[CX_SHA256_SIZE];
    uint8_t attestationSignature[72];
    int status;
    uint32_t signatureLength;
    cbipEncoder_t encoder;

    PRINTF("Data to attest %.*H\n", authDataLen, authData);

    // Add client data hash for the attestation.
    // We can add it after authData has it has been checked in ctap2_make_credential_confirm().
    // It can be avoided if we compute the hash in two part, but that would mean allocating
    // an hash context that is heavy and can be avoided.
    memmove(authData + authDataLen, ctap2RegisterData->clientDataHash, CX_SHA256_SIZE);

    cx_hash_sha256(authData, authDataLen + CX_SHA256_SIZE, hashData, sizeof(hashData));

    status = crypto_sign_attestation(hashData, attestationSignature, true);
    if (status < 0) {
        return -1;
    }
    signatureLength = status;
    PRINTF("Attestation signature %.*H\n", signatureLength, attestationSignature);

    // Build the response
    cbip_encoder_init(&encoder, buffer, bufferLen);

    cbip_add_map_header(&encoder, 3);

    cbip_add_int(&encoder, TAG_RESP_FMT);
    cbip_add_string(&encoder, ATTESTATION_FORMAT_PACKED, sizeof(ATTESTATION_FORMAT_PACKED) - 1);

    cbip_add_int(&encoder, TAG_RESP_AUTHDATA);
    cbip_add_byte_string(&encoder, authData, authDataLen);

    cbip_add_int(&encoder, TAG_RESP_ATTSTMT);
    cbip_add_map_header(&encoder, 3);

    cbip_add_string(&encoder, TAG_ALGORITHM, sizeof(TAG_ALGORITHM) - 1);
    cbip_add_int(&encoder, COSE_ALG_ES256);

    cbip_add_string(&encoder, TAG_SIGNATURE, sizeof(TAG_SIGNATURE) - 1);
    cbip_add_byte_string(&encoder, attestationSignature, signatureLength);

    cbip_add_string(&encoder, TAG_CERTIFICATE_X509, sizeof(TAG_CERTIFICATE_X509) - 1);
    cbip_add_array_header(&encoder, 1);
    cbip_add_byte_string(&encoder, FIDO2_ATTESTATION_CERT, sizeof(FIDO2_ATTESTATION_CERT));

    return encoder.offset;
}

void ctap2_make_credential_confirm() {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    uint32_t dataLen;
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
    int status;

    PRINTF("ctap2_make_credential_confirm\n");

    ctap2_send_keepalive_processing();

    // Perform User Verification if required
    if (ctap2RegisterData->pinRequired) {
        performBuiltInUv();
    }

    ctap2_send_keepalive_processing();

    // Generate nonce
#ifdef HAVE_NFC
    // Spare response time by pre-generating part of the answer
    if (nfc_nonce_and_pubkey_ready) {
        memcpy(nonce, nfc_nonce, CREDENTIAL_NONCE_SIZE);
    } else
#endif
    {
        cx_rng_no_throw(nonce, CREDENTIAL_NONCE_SIZE);
    }

    // Build auth data
    status =
        build_makeCred_authData(nonce, shared_ctx.sharedBuffer, sizeof(shared_ctx.sharedBuffer));
    if (status < 0) {
        status = (status == RK_STORAGE_FULL ? ERROR_KEY_STORE_FULL : ERROR_OTHER);
        goto exit;
    }
    dataLen = status;

    // Check that sign_and_build_makeCred_response() can add clientDataHash
    // (CX_SHA256_SIZE bytes) at the end of authData for hash computing.
    if (dataLen + CX_SHA256_SIZE > sizeof(shared_ctx.sharedBuffer)) {
        PRINTF("Shared buffer size issue!\n");
        status = ERROR_OTHER;
        goto exit;
    }

    // Compute standard attestation then build CBOR response
    status = sign_and_build_makeCred_response(shared_ctx.sharedBuffer,
                                              dataLen,
                                              responseBuffer + 1,
                                              CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    if (status < 0) {
        status = ERROR_OTHER;
        goto exit;
    }
    dataLen = status;
    status = 0;

    responseBuffer[0] = ERROR_NONE;

exit:
    if (status == 0) {
        send_cbor_response(&G_io_u2f, 1 + dataLen, CTAP2_REGISTRATION, false);
    } else {
        send_cbor_error(&G_io_u2f, status);
    }
}

void ctap2_make_credential_user_cancel() {
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
}
