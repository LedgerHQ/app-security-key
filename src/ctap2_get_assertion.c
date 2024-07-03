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
#include "os_io_seproxyhal.h"

#include "ctap2.h"
#include "cbip_helper.h"
#include "credential.h"
#include "crypto.h"
#include "config.h"
#include "ui_shared.h"
#include "cose_keys.h"
#include "rk_storage.h"
#include "globals.h"

#define TAG_RP_ID            0x01
#define TAG_CLIENT_DATA_HASH 0x02
#define TAG_ALLOWLIST        0x03
#define TAG_EXTENSIONS       0x04
#define TAG_OPTIONS          0x05
#define TAG_PIN_AUTH         0x06
#define TAG_PIN_PROTOCOL     0x07

#define TAG_RESP_CREDENTIAL 0x01
#define TAG_RESP_AUTH_DATA  0x02
#define TAG_RESP_SIGNATURE  0x03
#define TAG_RESP_USER       0x04

static int parse_getAssert_authnr_rpid(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    if (cbiph_get_map_key_text(decoder,
                               mapItem,
                               TAG_RP_ID,
                               &ctap2AssertData->rpId,
                               &ctap2AssertData->rpIdLen) != CBIPH_STATUS_FOUND) {
        return ERROR_MISSING_PARAMETER;
    }

#ifdef HAVE_FIDO2_RPID_FILTER
    if (CMD_IS_OVER_U2F_CMD && !CMD_IS_OVER_U2F_NFC) {
        if (ctap2_check_rpid_filter(ctap2AssertData->rpId, ctap2AssertData->rpIdLen)) {
            PRINTF("rpId denied by filter\n");
            return ERROR_PROP_RPID_MEDIA_DENIED;
        }
    }
#endif

    // Compute RP ID hash
    cx_hash_sha256((uint8_t *) ctap2AssertData->rpId,
                   ctap2AssertData->rpIdLen,
                   ctap2AssertData->rpIdHash,
                   CX_SHA256_SIZE);

    // TODO: UTF-8 characters that are not ASCII will be dropped when displaying

    return 0;
}

static int parse_getAssert_authnr_clientDataHash(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    uint32_t itemLength;
    int status;

    status = cbiph_get_map_key_bytes(decoder,
                                     mapItem,
                                     TAG_CLIENT_DATA_HASH,
                                     &ctap2AssertData->clientDataHash,
                                     &itemLength);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Error fetching clientDataHash\n");
        return cbiph_map_cbor_error(status);
    }
    if (itemLength != CX_SHA256_SIZE) {
        PRINTF("Invalid clientDataHash length\n");
        return ERROR_INVALID_CBOR;
    }
    return 0;
}

static int handle_getAssert_allowList_item(cbipDecoder_t *decoder, cbipItem_t *item, bool unwrap) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;

    // Check that credential 'type' exists and is 'public-key'
    status = cbiph_check_credential(decoder, item);
    if (status == CBIPH_STATUS_NOT_FOUND) {
        return ERROR_INVALID_CREDENTIAL;
    }
    if (status < CBIPH_STATUS_NOT_FOUND) {
        PRINTF("Error fetching allowList entry\n");
        return cbiph_map_cbor_error(status);
    }

    status = cbiph_get_map_key_str_bytes(decoder,
                                         item,
                                         CREDENTIAL_DESCRIPTOR_ID,
                                         &ctap2AssertData->credId,
                                         &ctap2AssertData->credIdLen);
    if (status != CBIPH_STATUS_FOUND) {
        return cbiph_map_cbor_error(status);
    }
    PRINTF("Trying credential %.*H\n", ctap2AssertData->credIdLen, ctap2AssertData->credId);
    if (unwrap) {
        status = credential_unwrap(ctap2AssertData->rpIdHash,
                                   ctap2AssertData->credId,
                                   ctap2AssertData->credIdLen,
                                   &ctap2AssertData->nonce,
                                   &ctap2AssertData->credential,
                                   &ctap2AssertData->credentialLen);
    } else {
        status = credential_extract(ctap2AssertData->rpIdHash,
                                    ctap2AssertData->credId,
                                    ctap2AssertData->credIdLen,
                                    &ctap2AssertData->nonce,
                                    &ctap2AssertData->credential,
                                    &ctap2AssertData->credentialLen);
    }

    if (status < 0) {
        PRINTF("Skipping invalid credential candidate\n");
        return ERROR_INVALID_CREDENTIAL;
    }

    return 0;
}

static int process_getAssert_authnr_allowList(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t tmpItem;
    int arrayLen;
    int status;
    uint8_t *prevCredId = NULL;
    uint32_t prevCredIdLen = 0;

    ctap2AssertData->allowListPresent = 0;
    ctap2AssertData->availableCredentials = 0;

    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_ALLOWLIST, tmpItem, cbipArray);
    arrayLen = tmpItem.value;
    if ((status == CBIPH_STATUS_FOUND) && (arrayLen > 0)) {
        ctap2AssertData->allowListPresent = 1;

        for (int i = 0; i < arrayLen; i++) {
            if (i == 0) {
                cbip_next(decoder, &tmpItem);
            } else {
                cbiph_next_deep(decoder, &tmpItem);
            }

            status = handle_getAssert_allowList_item(decoder, &tmpItem, true);
            if (status == ERROR_INVALID_CREDENTIAL) {
                // Just ignore this credential
                continue;
            } else if (status != ERROR_NONE) {
                return status;
            }

            /* Weird behavior seen on Safari on MacOs, allowList entries are duplicated.
             * seen order is: 1, 2, ..., n, 1', 2', ..., n'.
             * In order to improve user experience while this might be fix in Safari side,
             * we decided to filter out the duplicate in a specific scenario:
             * - they are only 2 credentials in the allowList
             * - the first and second credentials are valid and are exactly the same.
             */
            if (arrayLen == 2) {
                if (i == 0) {
                    // Backup credId and credIdLen before parsing next credential
                    prevCredId = ctap2AssertData->credId;
                    prevCredIdLen = ctap2AssertData->credIdLen;
                } else {
                    if ((ctap2AssertData->availableCredentials == 1) &&
                        (ctap2AssertData->credIdLen == prevCredIdLen) &&
                        (memcmp(ctap2AssertData->credId, prevCredId, prevCredIdLen) == 0)) {
                        // Just ignore this duplicate credential
                        continue;
                    }
                }
            }

            PRINTF("Valid candidate %d\n", i);
            ctap2AssertData->availableCredentials += 1;
        }
    }

    PRINTF("allowListPresent %d entries %d\n",
           ctap2AssertData->allowListPresent,
           ctap2AssertData->availableCredentials);

    return 0;
}

static int process_getAssert_authnr_extensions(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t extensionsItem, hmacSecretItem;
    int status;

    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_EXTENSIONS, extensionsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        // Check hmacSecret extension
        CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder,
                                        &extensionsItem,
                                        EXTENSION_HMAC_SECRET,
                                        hmacSecretItem,
                                        cbipMap);
        if (status == CBIPH_STATUS_FOUND) {
            // All processing and check is done in ctap2_compute_hmacSecret_output()
            // when building the response
            ctap2AssertData->extensions |= FLAG_EXTENSION_HMAC_SECRET;
        }
    }
    return 0;
}

static int process_getAssert_authnr_options(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t optionsItem;
    int status;
    bool boolValue;

    ctap2AssertData->userPresenceRequired = true;
    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_OPTIONS, optionsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        // Forbidden option
        status = cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_RESIDENT_KEY, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && boolValue) {
            PRINTF("Forbidden resident key option\n");
            return ERROR_INVALID_OPTION;
        }

        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_VERIFICATION, &boolValue);
        if (status == CBIPH_STATUS_FOUND) {
            ctap2AssertData->pinRequired = boolValue;
        }

        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_PRESENCE, &boolValue);
        if (status == CBIPH_STATUS_FOUND) {
            ctap2AssertData->userPresenceRequired = boolValue;
        }
    }

    PRINTF("up %d uv %d\n", ctap2AssertData->userPresenceRequired, ctap2AssertData->pinRequired);

    return 0;
}

static int process_getAssert_authnr_pin(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;
    int pinProtocolVersion = 0;
    uint8_t *pinAuth;
    uint32_t pinAuthLen;

    status = cbiph_get_map_key_int(decoder, mapItem, TAG_PIN_PROTOCOL, &pinProtocolVersion);
    if (status == CBIPH_STATUS_FOUND) {
        if (pinProtocolVersion != PIN_PROTOCOL_VERSION_V1) {
            PRINTF("Unsupported PIN protocol version\n");
            return ERROR_PIN_AUTH_INVALID;
        }
    }

    status = cbiph_get_map_key_bytes(decoder, mapItem, TAG_PIN_AUTH, &pinAuth, &pinAuthLen);
    if (status > 0) {
        if (!N_u2f.pinSet) {
            PRINTF("PIN not set\n");
            return ERROR_PIN_NOT_SET;
        }

        if (pinAuthLen == 0) {
            // DEVIATION from FIDO2.0 spec: "If platform sends zero length pinAuth,
            // authenticator needs to wait for user touch and then returns [...]"
            // Impact is minor because user as still manually unlocked it's device.
            // therefore user presence is somehow guarantee.
            return ERROR_PIN_INVALID;
        }

        status = ctap2_client_pin_verify_auth_token(pinProtocolVersion,
                                                    ctap2AssertData->clientDataHash,
                                                    CX_SHA256_SIZE,
                                                    pinAuth,
                                                    pinAuthLen);
        if (status != ERROR_NONE) {
            return ERROR_PIN_AUTH_INVALID;
        }

        ctap2AssertData->clientPinAuthenticated = 1;
        PRINTF("Client PIN authenticated\n");
    }

    return 0;
}

void ctap2_get_assertion_handle(u2f_service_t *service,
                                uint8_t *buffer,
                                uint16_t length) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int status;

    PRINTF("ctap2_get_assertion_handle\n");

    memset(ctap2AssertData, 0, sizeof(ctap2_assert_data_t));
    ctap2AssertData->buffer = buffer;

    // Init CBIP decoder
    cbip_decoder_init(&decoder, buffer, length);
    cbip_first(&decoder, &mapItem);
    if (mapItem.type != cbipMap) {
        PRINTF("Invalid top item\n");
        status = ERROR_INVALID_CBOR;
        goto exit;
    }

    ctap2_send_keepalive_processing();

    // Check rpid
    status = parse_getAssert_authnr_rpid(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check clientDataHash
    status = parse_getAssert_authnr_clientDataHash(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check allowlist
    status = process_getAssert_authnr_allowList(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check extensions
    status = process_getAssert_authnr_extensions(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check options
    status = process_getAssert_authnr_options(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    if (((ctap2AssertData->extensions & FLAG_EXTENSION_HMAC_SECRET) != 0) &&
        !ctap2AssertData->userPresenceRequired) {
        PRINTF("hmac-secret not allowed without up\n");
        status = ERROR_INVALID_OPTION;
        goto exit;
    }

    // Check PIN
    status = process_getAssert_authnr_pin(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    if (CMD_IS_OVER_U2F_NFC) {
        // No up nor uv requested, skip UX and reply immediately
        // TODO: is this what we want?
        // TODO: Handle cases where availableCredentials is != 1
        //  -> which credentials should be chosen?
        //  -> when credentials comes from allowListPresent, I think the spec allow to choose for
        //  the user
        //  -> when credentials comes from rk, the spec ask to use authenticatorGetNextAssertion
        //  features
        g.is_nfc = true;
        ctap2_get_assertion_confirm(1);
    } else if (!ctap2AssertData->userPresenceRequired && !ctap2AssertData->pinRequired) {
        // No up nor uv required, skip UX and reply immediately
        ctap2_get_assertion_confirm(1);
    } else {
        // Look for a potential rk entry if no allow list was provided
        if (!ctap2AssertData->allowListPresent) {
            ctap2AssertData->availableCredentials = rk_storage_count(ctap2AssertData->rpIdHash);
            if (ctap2AssertData->availableCredentials == 1) {
                // Single resident credential load it to go through the usual flow
                PRINTF("Single resident credential\n");
                status = rk_storage_find_youngest(ctap2AssertData->rpIdHash,
                                                  NULL,
                                                  &ctap2AssertData->nonce,
                                                  &ctap2AssertData->credential,
                                                  &ctap2AssertData->credentialLen);
                if (status == RK_NOT_FOUND) {
                    // This can theoretically never happen.
                    // But still, if it does, fall back to the "No resident credentials" case
                    ctap2AssertData->availableCredentials = 0;
                }
            }
        }

        if (ctap2AssertData->availableCredentials == 0) {
            ctap2_get_assertion_ux(CTAP2_UX_STATE_NO_ASSERTION);
        } else if (ctap2AssertData->availableCredentials > 1) {
            // DEVIATION from FIDO2.0 spec in case of allowList presence:
            // "select any applicable credential and proceed".
            // We always ask the user to choose.
            ctap2_get_assertion_ux(CTAP2_UX_STATE_MULTIPLE_ASSERTION);
        } else {
            ctap2_get_assertion_ux(CTAP2_UX_STATE_GET_ASSERTION);
        }
    }
    status = 0;

exit:
    if (status != 0) {
        PRINTF("Get_assertion request parsing error %x\n", status);
        send_cbor_error(service, status);
    }
    return;
}

void ctap2_get_assertion_credential_idx(uint16_t idx) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;

    while (1) {
        if (ctap2AssertData->currentCredentialIndex == idx) {
            return;
        }

        if (!ctap2AssertData->allowListPresent) {
            if (ctap2AssertData->currentCredentialIndex > idx) {
                ctap2AssertData->currentCredentialIndex = 0;
                ctap2AssertData->multipleFlowData.rk.minAge = 0;
            }

            // Find the next entry in rk
            status = rk_storage_find_youngest(ctap2AssertData->rpIdHash,
                                              &ctap2AssertData->multipleFlowData.rk.minAge,
                                              &ctap2AssertData->nonce,
                                              &ctap2AssertData->credential,
                                              &ctap2AssertData->credentialLen);
            if (status <= 0) {
                // Should not happen, just continue a credential will be picked eventually
                PRINTF("Unexpected failure rk\n");
            }

            ctap2AssertData->currentCredentialIndex++;
            continue;
        } else {
            cbipDecoder_t decoder;
            cbip_decoder_init(&decoder, ctap2AssertData->buffer, CUSTOM_IO_APDU_BUFFER_SIZE);

            if (ctap2AssertData->multipleFlowData.allowList.currentCredential == 0 ||
                ctap2AssertData->currentCredentialIndex > idx) {
                cbipItem_t mapItem;
                cbip_first(&decoder, &mapItem);
                status =
                    cbiph_get_map_item(&decoder,
                                       &mapItem,
                                       TAG_ALLOWLIST,
                                       NULL,
                                       &ctap2AssertData->multipleFlowData.allowList.credentialItem,
                                       cbipArray);
                if (status != CBIPH_STATUS_FOUND) {
                    PRINTF("Unexpected failure allowlist\n");
                }

                ctap2AssertData->multipleFlowData.allowList.currentCredential = 0;
                ctap2AssertData->currentCredentialIndex = 0;
            }

            if (ctap2AssertData->multipleFlowData.allowList.currentCredential == 0) {
                cbip_next(&decoder, &ctap2AssertData->multipleFlowData.allowList.credentialItem);
            } else {
                cbiph_next_deep(&decoder,
                                &ctap2AssertData->multipleFlowData.allowList.credentialItem);
            }
            ctap2AssertData->multipleFlowData.allowList.currentCredential++;

            status = handle_getAssert_allowList_item(
                &decoder,
                &ctap2AssertData->multipleFlowData.allowList.credentialItem,
                false);
            if (status == ERROR_INVALID_CREDENTIAL) {
                // Just ignore this credential
                continue;
            } else if (status < 0) {
                // Should not occurs, but anyway, ignore this one
                continue;
            }

            ctap2AssertData->currentCredentialIndex++;
            continue;
        }
    }
}

static int compute_getAssert_hmacSecret_output(uint8_t **output,
                                               uint32_t *outputLen,
                                               uint8_t *credRandom) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem, tmpItem;
    uint32_t saltLength;
    uint8_t *saltAuth;
    uint32_t saltAuthLength;
    uint8_t *saltEnc;
    uint32_t saltEncLength;
    int status;
    uint8_t sharedSecret[SHARED_SECRET_MAX_SIZE];
    uint8_t *salt;

    // Attempt to process hmac-secret extension if flagged for processing
    cbip_decoder_init(&decoder, ctap2AssertData->buffer, CUSTOM_IO_APDU_BUFFER_SIZE);
    cbip_first(&decoder, &mapItem);

    GET_MAP_KEY_ITEM(&decoder, &mapItem, TAG_EXTENSIONS, tmpItem, cbipMap);
    GET_MAP_STR_KEY_ITEM(&decoder, &tmpItem, EXTENSION_HMAC_SECRET, mapItem, cbipMap);

    // Check KEY_AGREEMENT
    status = ctap2_client_pin_decapsulate(PIN_PROTOCOL_VERSION_V1,
                                          &decoder,
                                          &mapItem,
                                          TAG_HMAC_SECRET_KEY_AGREEMENT,
                                          sharedSecret);
    if (status != ERROR_NONE) {
        PRINTF("Fail to decapsulate\n");
        return status;
    }

    // Check SALT_ENC
    if (cbiph_get_map_key_bytes(&decoder,
                                &mapItem,
                                TAG_HMAC_SECRET_SALT_ENC,
                                &saltEnc,
                                &saltEncLength) != CBIPH_STATUS_FOUND) {
        PRINTF("Unexpected modification of CBOR data\n");
        return ERROR_INVALID_CBOR;
    }

    // Check SALT_AUTH
    if (cbiph_get_map_key_bytes(&decoder,
                                &mapItem,
                                TAG_HMAC_SECRET_SALT_AUTH,
                                &saltAuth,
                                &saltAuthLength) != CBIPH_STATUS_FOUND) {
        PRINTF("Unexpected modification of CBOR data\n");
        return ERROR_INVALID_CBOR;
    }

    // Verify saltAuth
    if (!ctap2_client_pin_verify(PIN_PROTOCOL_VERSION_V1,
                                 sharedSecret,
                                 sizeof(sharedSecret),
                                 saltEnc,
                                 saltEncLength,
                                 NULL,
                                 0,
                                 saltAuth,
                                 saltAuthLength)) {
        return ERROR_INVALID_CBOR;
    }

    // Decrypt salt in place
    status = ctap2_client_pin_decrypt(PIN_PROTOCOL_VERSION_V1,
                                      sharedSecret,
                                      saltEnc,
                                      saltEncLength,
                                      saltEnc,
                                      &saltLength);
    if (status < 0) {
        PRINTF("Salt decryption failed\n");
        return ERROR_INVALID_CBOR;
    }

    if ((saltLength != HMAC_SECRET_SALT_SIZE) && (saltLength != HMAC_SECRET_SALT_SIZE * 2)) {
        PRINTF("Invalid hmac-secret salt enc length %d\n", saltLength);
        return ERROR_INVALID_CBOR;
    }

    PRINTF("hmac-secret salt %.*H\n", saltLength, saltEnc);

    // Prepare the salt in "saltEnc" "buffer"
    salt = saltEnc;
    cx_hmac_sha256(credRandom, CRED_RANDOM_SIZE, saltEnc, CX_SHA256_SIZE, salt, CX_SHA256_SIZE);
    PRINTF("hmac-secret prepared salt1 %.*H\n", CX_SHA256_SIZE, salt);

    if (saltLength == HMAC_SECRET_SALT_SIZE * 2) {
        cx_hmac_sha256(credRandom,
                       CRED_RANDOM_SIZE,
                       salt + HMAC_SECRET_SALT_SIZE,
                       CX_SHA256_SIZE,
                       salt + HMAC_SECRET_SALT_SIZE,
                       CX_SHA256_SIZE);
        PRINTF("hmac-secret prepared salt2 %.*H\n", CX_SHA256_SIZE, salt + HMAC_SECRET_SALT_SIZE);
    }

    // Encrypt salt into saltEnc
    status = ctap2_client_pin_encrypt(PIN_PROTOCOL_VERSION_V1,
                                      sharedSecret,
                                      salt,
                                      saltLength,
                                      saltEnc,
                                      &saltEncLength);
    if (status < 0) {
        PRINTF("Salt encryption failed\n");
        return ERROR_INVALID_CBOR;
    }

    PRINTF("hmac-secret return %.*H\n", saltEncLength, saltEnc);

    *output = saltEnc;
    *outputLen = saltEncLength;
    return ERROR_NONE;
}

static int build_getAssert_authData(uint8_t *buffer, uint32_t bufferLength, uint32_t *authDataLen) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    uint16_t offset = 0;
    cbipEncoder_t encoder;
    int status;

    memmove(buffer, ctap2AssertData->rpIdHash, CX_SHA256_SIZE);
    offset += CX_SHA256_SIZE;
    buffer[offset] = 0;
    if (ctap2AssertData->pinRequired || ctap2AssertData->clientPinAuthenticated) {
        buffer[offset] |= AUTHDATA_FLAG_USER_VERIFIED;
    }
    if (ctap2AssertData->userPresenceRequired) {
        buffer[offset] |= AUTHDATA_FLAG_USER_PRESENCE;
    }
    if (ctap2AssertData->extensions != 0) {
        buffer[offset] |= AUTHDATA_FLAG_EXTENSION_DATA_PRESENT;
    }
    offset++;
    config_increase_and_get_authentification_counter(buffer + offset);
    offset += 4;
    if (ctap2AssertData->extensions != 0) {
        uint8_t extensionsSize = 0;
        if ((ctap2AssertData->extensions & FLAG_EXTENSION_HMAC_SECRET) != 0) {
            extensionsSize++;
        }
        cbip_encoder_init(&encoder, buffer + offset, bufferLength - offset);
        cbip_add_map_header(&encoder, extensionsSize);

        if ((ctap2AssertData->extensions & FLAG_EXTENSION_HMAC_SECRET) != 0) {
            cbip_add_string(&encoder, EXTENSION_HMAC_SECRET, sizeof(EXTENSION_HMAC_SECRET) - 1);
            uint8_t credRandom[CRED_RANDOM_SIZE];
            uint8_t *salt = NULL;
            uint32_t saltLength = 0;

            crypto_generate_credRandom_key(ctap2AssertData->nonce,
                                           credRandom,
                                           ctap2AssertData->pinRequired);

            status = compute_getAssert_hmacSecret_output(&salt, &saltLength, credRandom);
            if (status != ERROR_NONE) {
                return status;
            }
            cbip_add_byte_string(&encoder, salt, saltLength);
        }

        if (encoder.fault) {
            PRINTF("Error encoding extensions\n");
            return ERROR_OTHER;
        }
        offset += encoder.offset;
    }

    *authDataLen = offset;
    return ERROR_NONE;
}

#define WRAPPED_CREDENTIAL_OFFSET 200

static int sign_and_build_getAssert_authData(uint8_t *authData,
                                             uint32_t authDataLen,
                                             uint8_t *buffer,
                                             uint32_t bufferLen,
                                             credential_data_t *credData) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    uint8_t attestationSignature[72];
    uint32_t signatureLength;
    cbipEncoder_t encoder;
    uint8_t mapSize;
    int status;

    PRINTF("Data to sign %.*H\n", authDataLen, authData);

    // Add client data hash for the attestation.
    // We consider we can add it after authData.
    // It can be avoided if we compute the hash in two part, but that would mean allocating
    // an hash context that is heavy and can be avoided
    memmove(authData + authDataLen, ctap2AssertData->clientDataHash, CX_SHA256_SIZE);

    {
        // Use a new block scope to reduce the impact of privateKey on the stack.
        cx_ecfp_private_key_t privateKey;
        cx_curve_t bolosCurve = cose_alg_to_cx(credData->coseAlgorithm);

        if (crypto_generate_private_key(ctap2AssertData->nonce, &privateKey, bolosCurve) != 0) {
            return -1;
        }
        if (credData->coseAlgorithm == COSE_ALG_EDDSA) {
            status = crypto_sign_application_eddsa(&privateKey,
                                                   authData,
                                                   authDataLen + CX_SHA256_SIZE,
                                                   attestationSignature);
        } else {
            uint8_t hashData[CX_SHA256_SIZE];
            cx_hash_sha256(authData, authDataLen + CX_SHA256_SIZE, hashData, CX_SHA256_SIZE);

            status = crypto_sign_application(hashData, &privateKey, attestationSignature);
        }

        explicit_bzero(&privateKey, sizeof(privateKey));

        if (status < 0) {
            return -1;
        }
        signatureLength = status;
    }

    PRINTF("Signature %.*H\n", signatureLength, attestationSignature);

    ctap2_send_keepalive_processing();

    mapSize = 3;
    if (credData->residentKey) {
        mapSize++;
    }

    cbip_encoder_init(&encoder, buffer, bufferLen);

    cbip_add_map_header(&encoder, mapSize);

    {
        // Rewrap credentials then encoded in the CBOR response
        // This could be optimized but this would means bypassing the
        // cbip_add_byte_string helper and the encoder.
        // This is not so easy as the credentials length is not known
        // and can be <0xFF or >0xFF which change the CBOR header size...
        uint8_t *credential;
        uint32_t credentialLength;

        if (ctap2AssertData->credId != NULL) {
            credential = ctap2AssertData->credId;
            credentialLength = ctap2AssertData->credIdLen;
            status =
                credential_rewrap_in_place(ctap2AssertData->rpIdHash, credential, credentialLength);
            if (status < 0) {
                PRINTF("Fail to rewrap\n");
                return status;
            }
            credentialLength = status;
        } else {
            // No allow list scenario, which mean the credential is already resident
            credential_data_t tmpCredData;

            status = credential_decode(&tmpCredData,
                                       ctap2AssertData->credential,
                                       ctap2AssertData->credentialLen,
                                       false);
            if (status < 0) {
                PRINTF("fail to decode\n");
                return -1;
            }

            credential = buffer + WRAPPED_CREDENTIAL_OFFSET;
            credentialLength = bufferLen - WRAPPED_CREDENTIAL_OFFSET;
            status = credential_wrap(ctap2AssertData->rpIdHash,
                                     ctap2AssertData->nonce,
                                     &tmpCredData,
                                     credential,
                                     credentialLength,
                                     true,
                                     true);
            if (status < 0) {
                PRINTF("Fail to rewrap\n");
                return status;
            }
            credentialLength = status;
        }

        ctap2_send_keepalive_processing();

        PRINTF("Adding credential %.*H\n", credentialLength, credential);
        cbip_add_int(&encoder, TAG_RESP_CREDENTIAL);
        cbip_add_map_header(&encoder, 2);
        cbip_add_string(&encoder, CREDENTIAL_DESCRIPTOR_ID, sizeof(CREDENTIAL_DESCRIPTOR_ID) - 1);
        cbip_add_byte_string(&encoder, credential, credentialLength);
        cbip_add_string(&encoder,
                        CREDENTIAL_DESCRIPTOR_TYPE,
                        sizeof(CREDENTIAL_DESCRIPTOR_TYPE) - 1);
        cbip_add_string(&encoder,
                        CREDENTIAL_TYPE_PUBLIC_KEY,
                        sizeof(CREDENTIAL_TYPE_PUBLIC_KEY) - 1);
    }

    cbip_add_int(&encoder, TAG_RESP_AUTH_DATA);
    cbip_add_byte_string(&encoder, authData, authDataLen);

    cbip_add_int(&encoder, TAG_RESP_SIGNATURE);
    cbip_add_byte_string(&encoder, attestationSignature, signatureLength);

    if (credData->residentKey) {
        cbip_add_int(&encoder, TAG_RESP_USER);
        cbip_add_map_header(&encoder, 1);
        cbip_add_string(&encoder, KEY_USER_ID, sizeof(KEY_USER_ID) - 1);
        // credData->userId can still be used even after ctap2_rewrap_credential as
        // the credential is resident, and therefore userId is pointing to an area in nvm and
        // not in ctap2AssertData->credId
        cbip_add_byte_string(&encoder, credData->userId, credData->userIdLen);

        PRINTF("Adding user %.*H\n", credData->userIdLen, credData->userId);
    }

    return encoder.offset;
}

void ctap2_get_assertion_confirm(uint16_t idx) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;
    uint32_t dataLen;
    credential_data_t credData;

    PRINTF("ctap2_get_assertion_confirm %d\n", idx);

    ctap2_send_keepalive_processing();

    // Perform User Verification if required
    if (ctap2AssertData->pinRequired) {
        performBuiltInUv();
    }

    ctap2_send_keepalive_processing();

    // Return immediately in case there is no available credentials
    if (ctap2AssertData->availableCredentials == 0) {
        send_cbor_error(&G_io_u2f, ERROR_NO_CREDENTIALS);
        return;
    }

    // Retrieve needed data from credential
    ctap2_get_assertion_credential_idx(idx);
    status = credential_decode(&credData,
                               ctap2AssertData->credential,
                               ctap2AssertData->credentialLen,
                               true);

    if (status != 0) {
        PRINTF("Unexpected modification of CBOR credential data\n");
        status = ERROR_INVALID_CBOR;
        goto exit;
    }

    // Build authenticator data
    status = build_getAssert_authData(shared_ctx.sharedBuffer,
                                      sizeof(shared_ctx.sharedBuffer),
                                      &dataLen);
    if (status != ERROR_NONE) {
        goto exit;
    }

    ctap2_send_keepalive_processing();

    // Check that sign_and_build_getAssert_authData() can add clientDataHash
    // (CX_SHA256_SIZE bytes) at the end of authData for hash computing.
    if (dataLen + CX_SHA256_SIZE > sizeof(shared_ctx.sharedBuffer)) {
        PRINTF("Shared buffer size issue!\n");
        status = ERROR_OTHER;
        goto exit;
    }

    // Build the response
    status = sign_and_build_getAssert_authData(shared_ctx.sharedBuffer,
                                               dataLen,
                                               responseBuffer + 1,
                                               CUSTOM_IO_APDU_BUFFER_SIZE - 1,
                                               &credData);
    if (status < 0) {
        goto exit;
    }
    dataLen = status;
    status = 0;

    responseBuffer[0] = ERROR_NONE;

exit:
    if (status == 0) {
        send_cbor_response(&G_io_u2f, 1 + dataLen);
    } else {
        send_cbor_error(&G_io_u2f, status);
    }
}

void ctap2_get_assertion_user_cancel() {
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
}
