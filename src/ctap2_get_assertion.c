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

#define TAG_RESP_CREDENTIAL    0x01
#define TAG_RESP_AUTH_DATA     0x02
#define TAG_RESP_SIGNATURE     0x03
#define TAG_RESP_USER          0x04
#define TAG_RESP_USER_SELECTED 0x06

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
    if (CMD_IS_OVER_U2F_CMD) {
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

static int parse_getAssert_authnr_pinAuth(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;

    status = cbiph_get_map_key_bytes(decoder,
                                     mapItem,
                                     TAG_PIN_AUTH,
                                     &ctap2AssertData->pinAuth,
                                     &ctap2AssertData->pinAuthLen);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        return ERROR_INVALID_CBOR;
    }
    return 0;
}

static int parse_getAssert_authnr_extensions(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
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

        // Check txAuthSimple extension
        if (cbiph_get_map_key_str_text(decoder,
                                       &extensionsItem,
                                       EXTENSION_TX_AUTH_SIMPLE,
                                       &ctap2AssertData->txAuthMessage,
                                       &ctap2AssertData->txAuthLength) == CBIPH_STATUS_FOUND) {
            // Avoid displaying an empty string, just in case
            if (ctap2AssertData->txAuthLength == 0) {
                PRINTF("Invalid empty txAuthSimple\n");
                return ERROR_INVALID_CBOR;
            }
            // TODO : check that the text is displayable
            ctap2AssertData->extensions |= FLAG_EXTENSION_TX_AUTH_SIMPLE;
        }
    }
    return 0;
}

static int process_getAssert_authnr_alg_step1(bool *silentExit) {
    /* Step 1: Handle zero length pinUvAuthParam */

    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    uint8_t selectionConfirmedCode;

    *silentExit = false;
    if (ctap2AssertData->pinAuth != NULL) {
        if (ctap2AssertData->pinAuthLen == 0) {
            if (N_u2f.pinSet) {
                selectionConfirmedCode = ERROR_PIN_INVALID;
            } else {
                selectionConfirmedCode = ERROR_PIN_NOT_SET;
            }
            ctap2_selection_ux(selectionConfirmedCode);

            // Request answer will be sent at the end of ctap2_selection_ux,
            // therefore exit without response
            *silentExit = true;
        }
    }
    return 0;
}

static int process_getAssert_authnr_alg_step2(cbipDecoder_t *decoder,
                                              cbipItem_t *mapItem,
                                              int *protocol) {
    /* Step 2: Check pinUvAuthProtocol consistency */

    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;

    if (ctap2AssertData->pinAuth != NULL) {
        status = cbiph_get_map_key_int(decoder, mapItem, TAG_PIN_PROTOCOL, protocol);
        if (status != CBIPH_STATUS_FOUND) {
            return ERROR_MISSING_PARAMETER;
        }

        if ((*protocol != PIN_PROTOCOL_VERSION_V1) && (*protocol != PIN_PROTOCOL_VERSION_V2)) {
            return ERROR_INVALID_PAR;
        }
    }
    return 0;
}

static int process_getAssert_authnr_alg_step3(void) {
    /* Step 3: Create a new response structure and initialize both its "uv" bit and "up" bit as
     * false */

    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    ctap2AssertData->responseUvBit = 0;
    ctap2AssertData->responseUpBit = 0;
    return 0;
}

static int process_getAssert_authnr_alg_step4(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    /* Step 4: Process all options */

    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t optionsItem;
    int status;
    bool boolValue;

    ctap2AssertData->uvOption = 0;
    ctap2AssertData->upOption = 1;
    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_OPTIONS, optionsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        // Uv option
        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_VERIFICATION, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && boolValue) {
            ctap2AssertData->uvOption = 1;
        }

        if (ctap2AssertData->pinAuth != NULL) {
            // "Note: pinUvAuthParam and the "uv" option are processed as mutually
            // exclusive with pinUvAuthParam taking precedence."
            ctap2AssertData->uvOption = 0;
        }

        // Rk option
        status = cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_RESIDENT_KEY, &boolValue);
        if (status == CBIPH_STATUS_FOUND) {
            PRINTF("Forbidden resident key option\n");
            return ERROR_UNSUPPORTED_OPTION;
        }

        // Up option
        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_VERIFICATION, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && !boolValue) {
            ctap2AssertData->uvOption = 0;
        }
    }

    return 0;
}

static int process_getAssert_authnr_alg_step5(void) {
    /* Step 5: Handle alwaysUv option
     * => Do nothing as this option is not enabled */
    return 0;
}

static int process_getAssert_authnr_alg_step6(int protocol) {
    /* Step 6: Check for user verification */

    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;

    if (ctap2AssertData->pinAuth != NULL) {
        // Verify pinAuth, check permissions and userVerifiedFlagValue
        status = ctap2_client_pin_verify_auth_token(protocol,
                                                    AUTH_TOKEN_PERM_GET_ASSERTION,
                                                    ctap2AssertData->rpIdHash,
                                                    ctap2AssertData->clientDataHash,
                                                    CX_SHA256_SIZE,
                                                    ctap2AssertData->pinAuth,
                                                    ctap2AssertData->pinAuthLen,
                                                    true);
        if (status != ERROR_NONE) {
            return ERROR_PIN_AUTH_INVALID;
        }

        ctap2AssertData->responseUvBit = 1;
        PRINTF("Client PIN authenticated\n");
    } else if (ctap2AssertData->uvOption == 1) {
        // DEVIATION from spec: move BuiltInUV check in ctap2_get_assertion_confirm() after step 9 (user consent)
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

static int process_getAssert_authnr_alg_step7(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    /* Step 7: Locate all credentials that are eligible */

    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t tmpItem;
    int arrayLen;
    int status;

    ctap2AssertData->allowListPresent = 0;
    ctap2AssertData->numberOfCredentials = 0;

    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_ALLOWLIST, tmpItem, cbipArray);
    arrayLen = tmpItem.value;
    if (status == CBIPH_STATUS_FOUND) {
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

            PRINTF("Valid candidate %d\n", i);

            // TODO handle credential credProtect value
            ctap2AssertData->numberOfCredentials += 1;
        }
        PRINTF("allowListPresent %d entries %d\n",
               ctap2AssertData->allowListPresent,
               ctap2AssertData->numberOfCredentials);
    } else if (ctap2AssertData->allowListPresent == 0) {
        ctap2AssertData->numberOfCredentials = rk_storage_count(ctap2AssertData->rpIdHash);
        if (ctap2AssertData->numberOfCredentials == 1) {
            status = rk_storage_find_youngest(ctap2AssertData->rpIdHash,
                                              NULL,
                                              &ctap2AssertData->nonce,
                                              &ctap2AssertData->credential,
                                              &ctap2AssertData->credentialLen);
            if (status == RK_NOT_FOUND) {
                // This can theoretically never happen.
                return ERROR_NO_CREDENTIALS;
            }
        }

        // TODO handle credential credProtect value
    }

    if (ctap2AssertData->numberOfCredentials == 0) {
        return ERROR_NO_CREDENTIALS;
    }

    return 0;
}

static int process_getAssert_authnr_alg_step8(void) {
    /* Step 8: Skip user presence (user consent) if performBuiltInUv() was called in step 6
     * => DEVIATION from spec: Do nothing as we don't want to skip user consent */
    return 0;
}

void ctap2_get_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int protocol;
    int status;
    bool silentExit;

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

    /* Extract data from CBOR */
    status = parse_getAssert_authnr_rpid(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_getAssert_authnr_clientDataHash(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_getAssert_authnr_pinAuth(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_getAssert_authnr_extensions(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    /* Process each step of specification authenticatorGetAssertion Algorithm */
    status = process_getAssert_authnr_alg_step1(&silentExit);
    if (status != 0) {
        goto exit;
    }
    if (silentExit) {
        return;
    }

    status = process_getAssert_authnr_alg_step2(&decoder, &mapItem, &protocol);
    if (status != 0) {
        goto exit;
    }

    status = process_getAssert_authnr_alg_step3();
    if (status != 0) {
        goto exit;
    }

    status = process_getAssert_authnr_alg_step4(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = process_getAssert_authnr_alg_step5();
    if (status != 0) {
        goto exit;
    }

    status = process_getAssert_authnr_alg_step6(protocol);
    if (status != 0) {
        goto exit;
    }

    status = process_getAssert_authnr_alg_step7(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = process_getAssert_authnr_alg_step8();
    if (status != 0) {
        goto exit;
    }

    /* authenticatorGetAssertion Algorithm step 9:
     * - => DEVIATION from spec: Always require user consent, even when up option is not requested. TODO enable silent auth?
     * - => DEVIATION from spec: Always ask the user to select the credential to use.
     *      Credential selection should be done in latter steps 11 and 12, and sometimes
     *      should be done without user action.
     */
    ctap2_get_assertion_ux();
    ctap2AssertData->responseUpBit = 1;
    clearUserPresentFlag();
    clearUserVerifiedFlag();
    clearPinUvAuthTokenPermissionsExceptLbw();

    /* authenticatorGetAssertion Algorithm next steps:
     * - step 10: Extension output generation is done after user consent in
     *   - ctap2_get_assertion_confirm()
     *     -> build_getAssert_authData()
     * - step 11-12: Credential selection is always done during UX flow (ctap2_get_assertion_ux())
     *   that is called just above in step 9.
     *   The remaining part of theses steps is done when building the response. Mainly:
     *   - never include numberOfCredentials
     *   - set userSelected member to true when an allowList was not present but multiple
     *     resident credential were found and presented to the user.
     * - step 13: Generation of the signature is done done after user consent in
     *   - ctap2_get_assertion_confirm()
     -     -> sign_and_build_getAssert_authData()
     */

exit:
    if (status != 0) {
        PRINTF("Get_assertion request parsing error %x\n", status);
        send_cbor_error(service, status);
    }
    return;
}

void ctap2_get_assertion_next_credential_ux_helper(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;

    while (1) {
        if (!ctap2AssertData->allowListPresent) {
            if (ctap2AssertData->currentCredentialIndex == ctap2AssertData->numberOfCredentials) {
                ctap2AssertData->currentCredentialIndex = 0;
                ctap2AssertData->multipleFlowData.rk.minAge = 0;
            }
            ctap2AssertData->currentCredentialIndex++;

            // Find the next entry in rk
            status = rk_storage_find_youngest(ctap2AssertData->rpIdHash,
                                              &ctap2AssertData->multipleFlowData.rk.minAge,
                                              &ctap2AssertData->nonce,
                                              &ctap2AssertData->credential,
                                              &ctap2AssertData->credentialLen);
            if (status <= 0) {
                // Should not happen, just continue a credential will be picked eventually
                continue;
            }
            break;
        } else {
            cbipDecoder_t decoder;
            cbip_decoder_init(&decoder, ctap2AssertData->buffer, CUSTOM_IO_APDU_BUFFER_SIZE);

            if (ctap2AssertData->multipleFlowData.allowList.currentCredential ==
                ctap2AssertData->multipleFlowData.allowList.credentialsNumber) {
                cbipItem_t mapItem;
                cbip_first(&decoder, &mapItem);
                status =
                    cbiph_get_map_item(&decoder,
                                       &mapItem,
                                       TAG_ALLOWLIST,
                                       NULL,
                                       &ctap2AssertData->multipleFlowData.allowList.credentialItem,
                                       cbipArray);
                if (status == CBIPH_STATUS_FOUND) {
                    ctap2AssertData->multipleFlowData.allowList.credentialsNumber =
                        ctap2AssertData->multipleFlowData.allowList.credentialItem.value;
                } else {
                    ctap2AssertData->multipleFlowData.allowList.credentialsNumber = 0;
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

            // Process the item to display
            ctap2AssertData->currentCredentialIndex++;
            break;
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
    int protocol = 1;
    uint8_t *salt;

    // TODO use CredRandomWithUV and CredRandomWithoutUV

    // Attempt to process hmac-secret extension if flagged for processing
    cbip_decoder_init(&decoder, ctap2AssertData->buffer, CUSTOM_IO_APDU_BUFFER_SIZE);
    cbip_first(&decoder, &mapItem);

    GET_MAP_KEY_ITEM(&decoder, &mapItem, TAG_EXTENSIONS, tmpItem, cbipMap);
    GET_MAP_STR_KEY_ITEM(&decoder, &tmpItem, EXTENSION_HMAC_SECRET, mapItem, cbipMap);

    if (!ctap2AssertData->upOption) {
        PRINTF("hmac-secret not allowed without up\n");
        return ERROR_INVALID_OPTION;
    }

    // Get pin protocol
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_HMAC_SECRET_PROTOCOL, &protocol);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        return ERROR_INVALID_CBOR;
    }

    // Check KEY_AGREEMENT
    status = ctap2_client_pin_decapsulate(protocol,
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
        return ERROR_MISSING_PARAMETER;
    }

    // Check SALT_AUTH
    if (cbiph_get_map_key_bytes(&decoder,
                                &mapItem,
                                TAG_HMAC_SECRET_SALT_AUTH,
                                &saltAuth,
                                &saltAuthLength) != CBIPH_STATUS_FOUND) {
        return ERROR_MISSING_PARAMETER;
    }

    // Verify saltAuth
    if (!ctap2_client_pin_verify(protocol,
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
    status = ctap2_client_pin_decrypt(protocol,
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
    if (protocol == PIN_PROTOCOL_VERSION_V2) {
        // Use an offset that will be used for IV, so that encryption in place works
        salt += IV_PROT_V2_SIZE;
    }
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
    status =
        ctap2_client_pin_encrypt(protocol, sharedSecret, salt, saltLength, saltEnc, &saltEncLength);
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
    if (ctap2AssertData->responseUvBit) {
        buffer[offset] |= AUTHDATA_FLAG_USER_VERIFIED;
    }
    if (ctap2AssertData->responseUpBit) {
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
        if ((ctap2AssertData->extensions & FLAG_EXTENSION_TX_AUTH_SIMPLE) != 0) {
            extensionsSize++;
        }
        cbip_encoder_init(&encoder, buffer + offset, bufferLength - offset);
        cbip_add_map_header(&encoder, extensionsSize);

        if ((ctap2AssertData->extensions & FLAG_EXTENSION_HMAC_SECRET) != 0) {
            cbip_add_string(&encoder, EXTENSION_HMAC_SECRET, sizeof(EXTENSION_HMAC_SECRET) - 1);
            uint8_t credRandom[CRED_RANDOM_SIZE];
            uint8_t *salt = NULL;
            uint32_t saltLength = 0;

            crypto_generate_credRandom_key(ctap2AssertData->nonce, credRandom);

            status = compute_getAssert_hmacSecret_output(&salt, &saltLength, credRandom);
            if (status != ERROR_NONE) {
                return status;
            }
            cbip_add_byte_string(&encoder, salt, saltLength);
        }

        if ((ctap2AssertData->extensions & FLAG_EXTENSION_TX_AUTH_SIMPLE) != 0) {
            cbip_add_string(&encoder,
                            EXTENSION_TX_AUTH_SIMPLE,
                            sizeof(EXTENSION_TX_AUTH_SIMPLE) - 1);
            if (ctap2AssertData->txAuthLength > MAX_TX_AUTH_SIMPLE_SIZE) {
                ctap2AssertData->txAuthLength = 0;
            }
            cbip_add_string(&encoder,
                            ctap2AssertData->txAuthMessage,
                            ctap2AssertData->txAuthLength);
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
        mapSize++;  // for user member
        if (ctap2AssertData->numberOfCredentials > 1) {
            mapSize++;  // for userSelected member
        }
    }

    cbip_encoder_init(&encoder, buffer, bufferLen);

    cbip_add_map_header(&encoder, mapSize);

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
        credential_data_t credData;

        status = credential_decode(&credData,
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
                                 &credData,
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
    cbip_add_string(&encoder, CREDENTIAL_DESCRIPTOR_TYPE, sizeof(CREDENTIAL_DESCRIPTOR_TYPE) - 1);
    cbip_add_string(&encoder, CREDENTIAL_TYPE_PUBLIC_KEY, sizeof(CREDENTIAL_TYPE_PUBLIC_KEY) - 1);

    cbip_add_int(&encoder, TAG_RESP_AUTH_DATA);
    cbip_add_byte_string(&encoder, authData, authDataLen);

    cbip_add_int(&encoder, TAG_RESP_SIGNATURE);
    cbip_add_byte_string(&encoder, attestationSignature, signatureLength);

    if (credData->residentKey) {
        PRINTF("Adding user %.*H\n", credData->userIdLen, credData->userId);
        cbip_add_int(&encoder, TAG_RESP_USER);
        cbip_add_map_header(&encoder, 1);
        cbip_add_string(&encoder, KEY_USER_ID, sizeof(KEY_USER_ID) - 1);
        // credData->userId can still be used even after ctap2_rewrap_credential as
        // the credential is resident, and therefore userId is pointing to an area in nvm and
        // not in ctap2AssertData->credId
        cbip_add_byte_string(&encoder, credData->userId, credData->userIdLen);

        if (ctap2AssertData->numberOfCredentials > 1) {
            cbip_add_int(&encoder, TAG_RESP_USER_SELECTED);
            cbip_add_boolean(&encoder, true);
        }
    }

    return encoder.offset;
}

void ctap2_get_assertion_confirm() {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    int status;
    uint32_t dataLen;
    credential_data_t credData;

    ctap2UxState = CTAP2_UX_STATE_NONE;

    PRINTF("ctap2_get_assertion_confirm\n");

    ctap2_send_keepalive_processing();

    ui_idle();

    // Perform User Verification if required
    if (ctap2AssertData->uvOption) {
        performBuiltInUv();
        ctap2AssertData->responseUvBit = 1;
    }

    ctap2_send_keepalive_processing();

    // Restore the original last char in the CBOR buffer if a TX Auth was displayed
    if (ctap2AssertData->txAuthMessage != NULL) {
        ctap2AssertData->txAuthMessage[ctap2AssertData->txAuthLength] = ctap2AssertData->txAuthLast;
    }

    // Retrieve needed data from credential
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
                                               G_io_apdu_buffer + 1,
                                               CUSTOM_IO_APDU_BUFFER_SIZE - 1,
                                               &credData);
    if (status < 0) {
        goto exit;
    }
    dataLen = status;
    status = 0;

    G_io_apdu_buffer[0] = ERROR_NONE;

exit:
    if (status == 0) {
        send_cbor_response(&G_io_u2f, 1 + dataLen);
    } else {
        send_cbor_error(&G_io_u2f, status);
    }
}

void ctap2_get_assertion_user_cancel() {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
    ui_idle();
}

void ctap2_get_assertion_no_assertion_confirm() {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_NO_CREDENTIALS);
    ui_idle();
}
