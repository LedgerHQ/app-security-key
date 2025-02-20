/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2022-2025 Ledger
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
#include "lcx_aes_siv.h"

#include "app_storage_data.h"
#include "ctap2.h"
#include "credential.h"
#include "crypto.h"
#include "config.h"
#include "cbip_helper.h"
#include "cose_keys.h"
#include "rk_storage.h"

#define TAG_HANDLE_VERSION        1
#define TAG_HANDLE_FLAGS          2
#define TAG_HANDLE_COSE_ALGORITHM 3
#define TAG_HANDLE_USERID         4
#define TAG_HANDLE_USERNAME       5

#define CTAP2_HANDLE_VERSION 1

#define FLAG_RK 0x01

static int credential_encode(credential_data_t *credData,
                             uint8_t *buffer,
                             uint32_t bufferLen,
                             bool fullCredentials) {
    cbipEncoder_t encoder;
    uint8_t mapSize;
    uint32_t flags = 0;

    mapSize = 3;
    if (fullCredentials) {
        mapSize++;
        if (credData->userStr != NULL) {
            mapSize++;  // can find a real name
        }
    }

    if (credData->residentKey) {
        flags |= FLAG_RK;
    }

    cbip_encoder_init(&encoder, buffer, bufferLen);

    cbip_add_map_header(&encoder, mapSize);

    cbip_add_int(&encoder, TAG_HANDLE_VERSION);
    cbip_add_int(&encoder, CTAP2_HANDLE_VERSION);

    cbip_add_int(&encoder, TAG_HANDLE_FLAGS);
    cbip_add_int(&encoder, flags);

    if (fullCredentials) {
        cbip_add_int(&encoder, TAG_HANDLE_COSE_ALGORITHM);
        cbip_add_int(&encoder, credData->coseAlgorithm);

        cbip_add_int(&encoder, TAG_HANDLE_USERID);
        cbip_add_byte_string(&encoder, credData->userId, credData->userIdLen);

        if (credData->userStr != NULL) {
            cbip_add_int(&encoder, TAG_HANDLE_USERNAME);
            cbip_add_string(&encoder, credData->userStr, credData->userStrLen);
        }
    }

    if (encoder.fault) {
        PRINTF("Credential generation failed\n");
        return -1;
    }

    return encoder.offset;
}

int credential_decode(credential_data_t *credData,
                      uint8_t *encodedCredential,
                      uint32_t encodedCredentialLen,
                      bool fullCredentials) {
    int status;
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int tmp;

    memset(credData, 0, sizeof(credential_data_t));

    // Handle U2F credentials
    if (encodedCredentialLen == 0) {
        credData->coseAlgorithm = COSE_ALG_ES256;
        return 0;
    }

    cbip_decoder_init(&decoder, encodedCredential, encodedCredentialLen);
    if ((cbip_first(&decoder, &mapItem) < 0) || (mapItem.type != cbipMap)) {
        PRINTF("Invalid credential map\n");
        return -1;
    }

    // Check handle version
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_HANDLE_VERSION, &tmp);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Invalid credential version\n");
        return -1;
    }
    if (tmp != CTAP2_HANDLE_VERSION) {
        PRINTF("Invalid credential version %d / %d", tmp, CTAP2_HANDLE_VERSION);
        return -1;
    }

    // Check and retrieve flags
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_HANDLE_FLAGS, &tmp);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Invalid credential flags\n");
        return -1;
    }
    if (tmp == FLAG_RK) {
        credData->residentKey = 1;
    } else if (tmp != 0) {
        PRINTF("Invalid credential flags %d\n", tmp);
    }

    if (fullCredentials) {
        // Check and retrieve alg
        status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_HANDLE_COSE_ALGORITHM, &tmp);
        if (status != CBIPH_STATUS_FOUND) {
            PRINTF("Invalid credential alg\n");
            return -1;
        }
        credData->coseAlgorithm = tmp;

        // Check and retrieve userid
        status = cbiph_get_map_key_bytes(&decoder,
                                         &mapItem,
                                         TAG_HANDLE_USERID,
                                         &credData->userId,
                                         &credData->userIdLen);
        if (status != CBIPH_STATUS_FOUND) {
            PRINTF("Invalid credential userId\n");
            return -1;
        }

        // Check and retrieve username
        cbiph_get_map_key_text(&decoder,
                               &mapItem,
                               TAG_HANDLE_USERNAME,
                               &credData->userStr,
                               &credData->userStrLen);
        if (status < CBIPH_STATUS_NOT_FOUND) {
            PRINTF("Invalid credential username\n");
            return -1;
        }
    }

    return 0;
}

static int credential_handle_ciphering(bool is_encrypt,
                                       bool isCtap2,
                                       uint8_t *in,
                                       uint32_t in_len,
                                       const uint8_t *aad,
                                       uint32_t aad_len,
                                       uint8_t *output,
                                       uint8_t *tag) {
    int status = 0;
    uint8_t *key;
    cx_aes_siv_context_t siv_ctx;
    cx_cipher_context_t cipher;
    cipher_key_t cipher_key;

    if (isCtap2) {
        key = config.wrappingKeyCTAP2;
    } else {
        key = config.wrappingKeyU2F;
    }

    siv_ctx.cipher_ctx = &cipher;
    siv_ctx.cipher_type = CX_CIPHER_AES_128;
    if (cx_aes_siv_init(&siv_ctx) != CX_OK) {
        status = -1;
        goto exit;
    }
    siv_ctx.cipher_ctx->cipher_key = &cipher_key;
    if (cx_aes_siv_set_key(&siv_ctx, key, 32 * 8) != CX_OK) {
        status = -1;
        goto exit;
    }

    if (is_encrypt) {
        if (cx_aes_siv_encrypt(&siv_ctx, in, in_len, aad, aad_len, output, tag) != CX_OK) {
            status = -1;
            goto exit;
        }
    } else {
        if (cx_aes_siv_decrypt(&siv_ctx, in, in_len, aad, aad_len, output, tag) != CX_OK) {
            status = -1;
            goto exit;
        }
    }

exit:
    explicit_bzero(&siv_ctx, sizeof(siv_ctx));

    return status;
}

int credential_wrap(const uint8_t *rpIdHash,
                    const uint8_t *nonce,
                    credential_data_t *credData,
                    uint8_t *buffer,
                    uint32_t bufferLen,
                    bool isCtap2,
                    bool alreadyResident) {
    int status;
    int offset = 0;
    uint32_t encodedCredentialLen = 0;

    // Check for minimal size
    if (bufferLen < CREDENTIAL_MINIMAL_SIZE) {
        PRINTF("Bad size\n");
        return -1;
    }

    // Add version field and check credData parameter consistency
    if (isCtap2) {
        buffer[offset] = CREDENTIAL_VERSION_CTAP2;
        if (credData == NULL) {
            return -1;
        }
    } else {
        buffer[offset] = CREDENTIAL_VERSION_U2F;
        if (credData != NULL) {
            return -1;
        }
    }
    offset += CREDENTIAL_VERSION_SIZE;

    // Skip tag size
    uint8_t *tag = buffer + offset;
    offset += CREDENTIAL_TAG_SIZE;

    // Add nonce to the credential
    if (nonce == NULL) {
        PRINTF("Missing nonce\n");
        return -1;
    }
    memcpy(buffer + offset, nonce, CREDENTIAL_NONCE_SIZE);
    offset += CREDENTIAL_NONCE_SIZE;

    if (isCtap2) {
        // Encode credentials
        uint8_t *encodedCredential = buffer + offset;
        uint32_t encodedMaxSize = bufferLen - offset;

        if (alreadyResident) {
            // Encode limited credentials
            status = credential_encode(credData, encodedCredential, encodedMaxSize, false);
            if (status < 0) {
                PRINTF("Fail to encode short\n");
                return status;
            }
            encodedCredentialLen = status;
        } else {
            // Encode full credentials
            status = credential_encode(credData, encodedCredential, encodedMaxSize, true);
            if (status < 0) {
                PRINTF("Fail to encode\n");
                return status;
            }
            encodedCredentialLen = status;

            if (credData->residentKey) {
                // Erase before storing in case a credential is already present for this account
                rk_storage_erase_account(rpIdHash, credData->userId, credData->userIdLen);

                status = rk_storage_store(rpIdHash, nonce, encodedCredential, encodedCredentialLen);
                if (status < 0) {
                    PRINTF("Failed to store resident key\n");
                    return status;
                }

                // Re-encode limited credentials
                status = credential_encode(credData, encodedCredential, encodedMaxSize, false);
                if (status < 0) {
                    PRINTF("Fail to encode short\n");
                    return status;
                }
                encodedCredentialLen = status;
            }
        }
    }

    // Encrypt in place the nonce and the credentials and store the tag in buffer
    status = credential_handle_ciphering(true,
                                         isCtap2,
                                         tag + CREDENTIAL_TAG_SIZE,
                                         CREDENTIAL_NONCE_SIZE + encodedCredentialLen,
                                         rpIdHash,
                                         CX_SHA256_SIZE,
                                         tag + CREDENTIAL_TAG_SIZE,
                                         tag);
    if (status != 0) {
        PRINTF("Credential encryption failed\n");
        return status;
    }
    offset += encodedCredentialLen;

    return offset;
}

static int credential_parse(const uint8_t *rpIdHash,
                            uint8_t *credId,
                            uint32_t credIdLen,
                            uint8_t **noncePtr,
                            uint8_t **encodedCredential,
                            uint32_t *encodedCredentialLen,
                            bool unwrap) {
    int status;
    int offset = 0;
    bool isCtap2;
    uint8_t cred_version;
    uint8_t *nonce;
    credential_data_t credData;

    // Check for minimal size
    if (credIdLen < CREDENTIAL_MINIMAL_SIZE) {
        PRINTF("wrong size\n");
        return -1;
    }

    // Parse version field
    cred_version = credId[offset];
    if (unwrap) {
        if (cred_version == CREDENTIAL_VERSION_CTAP2) {
            isCtap2 = true;
        } else if (cred_version == CREDENTIAL_VERSION_U2F) {
            isCtap2 = false;
        } else {
            PRINTF("wrong version\n");
            return -1;
        }
    } else {
        if (cred_version == (CREDENTIAL_VERSION_CTAP2 | CREDENTIAL_UNWRAPPED_BIT)) {
            isCtap2 = true;
        } else if (cred_version == (CREDENTIAL_VERSION_U2F | CREDENTIAL_UNWRAPPED_BIT)) {
            isCtap2 = false;
        } else {
            PRINTF("Credential not unwrapped or bad version\n");
            return -1;
        }
    }
    offset += CREDENTIAL_VERSION_SIZE;

    // Skip tag size
    uint8_t *tag = credId + offset;
    offset += CREDENTIAL_TAG_SIZE;

    // Decrypt and check authenticity
    if (unwrap) {
        status = credential_handle_ciphering(false,
                                             isCtap2,
                                             credId + offset,
                                             credIdLen - offset,
                                             rpIdHash,
                                             CX_SHA256_SIZE,
                                             credId + offset,
                                             tag);
        if (status != 0) {
            PRINTF("Credential decryption failed\n");
            return status;
        }
        // Set UNWRAPPED bit on version byte to indicate that data have been
        // unwrapped in place and therefore future calls should be parse only.
        credId[0] = cred_version | CREDENTIAL_UNWRAPPED_BIT;
    }

    // Parse nonce field
    nonce = credId + offset;
    if (noncePtr != NULL) {
        *noncePtr = nonce;
    }

    offset += CREDENTIAL_NONCE_SIZE;

    if (isCtap2) {
        status = credential_decode(&credData, credId + offset, credIdLen - offset, false);
        if (status != 0) {
            PRINTF("Credential decoding failed\n");
            return -1;
        }

        if (credData.residentKey) {
            status =
                rk_storage_find_account(rpIdHash, nonce, encodedCredential, encodedCredentialLen);
            if (status < 0) {
                PRINTF("Error finding associated resident credential\n");
                return status;
            }
            if (status == 0) {
                PRINTF("Associated resident credential not found\n");
                return -1;
            }

            return STATUS_RK_CREDENTIAL;
        } else {
            if (encodedCredential != NULL) {
                *encodedCredential = credId + offset;
            }
            if (encodedCredentialLen != NULL) {
                *encodedCredentialLen = credIdLen - offset;
            }
        }
    } else {
        if (encodedCredential != NULL) {
            *encodedCredential = NULL;
        }
        if (encodedCredentialLen != NULL) {
            *encodedCredentialLen = 0;
        }
    }

    return 0;
}

int credential_unwrap(const uint8_t *rpIdHash,
                      uint8_t *credId,
                      uint32_t credIdLen,
                      uint8_t **nonce,
                      uint8_t **encodedCredential,
                      uint32_t *encodedCredentialLen) {
    return credential_parse(rpIdHash,
                            credId,
                            credIdLen,
                            nonce,
                            encodedCredential,
                            encodedCredentialLen,
                            true);
}

int credential_extract(const uint8_t *rpIdHash,
                       const uint8_t *credId,
                       uint32_t credIdLen,
                       uint8_t **nonce,
                       uint8_t **encodedCredential,
                       uint32_t *encodedCredentialLen) {
    return credential_parse(rpIdHash,
                            (uint8_t *) credId,
                            credIdLen,
                            nonce,
                            encodedCredential,
                            encodedCredentialLen,
                            false);
}

int credential_rewrap_in_place(const uint8_t *rpIdHash, uint8_t *credId, uint32_t credIdLen) {
    // Encrypt again a credId that was previously decrypted, when the
    // user was prompted to choose among several accounts.
    // This works because the AES key was not modified and IV is deterministic.
    bool isCtap2;
    uint8_t tag[CREDENTIAL_TAG_SIZE];
    int offset = 0;
    uint8_t cred_version;

    // Parse version field, check its value and overwrite it to remove CREDENTIAL_UNWRAPPED_BIT bit.
    cred_version = credId[offset];
    if (cred_version == (CREDENTIAL_VERSION_CTAP2 | CREDENTIAL_UNWRAPPED_BIT)) {
        isCtap2 = true;
        credId[offset] = CREDENTIAL_VERSION_CTAP2;
    } else if (cred_version == (CREDENTIAL_VERSION_U2F | CREDENTIAL_UNWRAPPED_BIT)) {
        isCtap2 = false;
        credId[offset] = CREDENTIAL_VERSION_U2F;
    } else {
        PRINTF("Credential not unwrapped or bad version\n");
        return -1;
    }

    offset += CREDENTIAL_VERSION_SIZE;

    // Encrypt credentials and tag
    if (credential_handle_ciphering(true,
                                    isCtap2,
                                    credId + offset + CREDENTIAL_TAG_SIZE,
                                    credIdLen - offset - CREDENTIAL_TAG_SIZE,
                                    rpIdHash,
                                    CX_SHA256_SIZE,
                                    credId + 1 + CREDENTIAL_TAG_SIZE,
                                    tag) != 0) {
        PRINTF("Credential encryption failed\n");
        return -1;
    }

    // Check tag
    if (!crypto_compare(credId + 1, tag, CREDENTIAL_TAG_SIZE)) {
        PRINTF("Tag don't match\n");
        return -1;
    }

    return credIdLen;
}
