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

#include "ctap2.h"
#include "config.h"
#include "ui_shared.h"
#include "globals.h"
#include "rk_storage.h"

#include "get_assertion_ui.h"
#include "get_assertion_utils.h"

static int decode_rpid(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
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

static int decode_clientDataHash(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    uint32_t itemLength;
    int status;
    uint8_t *tmp_ptr;

    status = cbiph_get_map_key_bytes(decoder, mapItem, TAG_CLIENT_DATA_HASH, &tmp_ptr, &itemLength);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Error fetching clientDataHash\n");
        return cbiph_map_cbor_error(status);
    }
    if (itemLength != CX_SHA256_SIZE) {
        PRINTF("Invalid clientDataHash length\n");
        return ERROR_INVALID_CBOR;
    }
    // The clientDataHash can be reused on successive calls (GET_ASSERTION / GET_NEXT_ASSERTION),
    // thus it must be stored in static memory so its content  won't change across several calls
    memcpy(ctap2AssertData->clientDataHash, tmp_ptr, CX_SHA256_SIZE);
    return 0;
}

static int decode_allowList(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t tmpItem;
    int arrayLen;
    int status = CBIPH_STATUS_NOT_FOUND;
    uint8_t *prevCredId = NULL;
    uint32_t prevCredIdLen = 0;

    ctap2AssertData->allowListPresent = 0;
    ctap2AssertData->numberOfCredentials = 0;

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

            status = handle_allowList_item(decoder, &tmpItem, true);
            if (status == ERROR_INVALID_CREDENTIAL) {
                // Just ignore this credential
                continue;
            } else if (status != ERROR_NONE) {
                return status;
            }

            /* Weird behavior seen on Safari on MacOs, allowList entries are duplicated.
             * Observed order is: 1, 2, ..., n, 1', 2', ..., n'.
             * In order to improve the user experience until this might be fixed in Safari side,
             * we decided to filter out the duplicates in a specific scenario:
             * - they are only 2 credentials in the allowList
             * - the first and second credentials are valid and are exactly the same.
             */
            if (arrayLen == 2) {
                if (i == 0) {
                    // Backup credId and credIdLen before parsing next credential
                    prevCredId = ctap2AssertData->credId;
                    prevCredIdLen = ctap2AssertData->credIdLen;
                } else {
                    if ((ctap2AssertData->numberOfCredentials == 1) &&
                        (ctap2AssertData->credIdLen == prevCredIdLen) &&
                        (memcmp(ctap2AssertData->credId, prevCredId, prevCredIdLen) == 0)) {
                        // Just ignore this duplicate credential
                        continue;
                    }
                }
            }

            PRINTF("Valid candidate %d\n", i);
            ctap2AssertData->numberOfCredentials += 1;
        }
    }

    PRINTF("allowListPresent %d entries %d\n",
           ctap2AssertData->allowListPresent,
           ctap2AssertData->numberOfCredentials);

    return 0;
}

static int decode_extensions(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t extensionsItem, hmacSecretItem;
    int status = CBIPH_STATUS_NOT_FOUND;

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

static int decode_options(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t optionsItem;
    int status = CBIPH_STATUS_NOT_FOUND;
    bool boolValue;

    ctap2AssertData->responseUpBit = true;
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
            ctap2AssertData->uvOption = boolValue;
        }

        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_PRESENCE, &boolValue);
        if (status == CBIPH_STATUS_FOUND) {
            ctap2AssertData->responseUpBit = boolValue;
        }
    }

    PRINTF("up %d uv %d\n", ctap2AssertData->responseUpBit, ctap2AssertData->uvOption);

    return 0;
}

static int decode_pin(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
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
                                                    AUTH_TOKEN_PERM_GET_ASSERTION,
                                                    ctap2AssertData->rpIdHash,
                                                    ctap2AssertData->clientDataHash,
                                                    CX_SHA256_SIZE,
                                                    pinAuth,
                                                    pinAuthLen,
                                                    true);
        if (status != ERROR_NONE) {
            return ERROR_PIN_AUTH_INVALID;
        }

        PRINTF("Client PIN authenticated\n");
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

            status = handle_allowList_item(decoder, &tmpItem, true);
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

static void nfc_handle_get_assertion() {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    if (ctap2AssertData->allowListPresent) {
        // Allow list -> non-RK credentials.
        // Falling back to previous behavior: login with the first compatible credential
        get_assertion_confirm(1);
    } else {
        // No allow list -> RK credentials
        // Spec getnextAssertion behavior: creating a list of compatible credentials, returning
        // the first one & the number of compatible credentials, so that the client is able then to
        // call getNextAssertion to fetch other possible credentials.
        uint16_t slotIdx;
        ctap2AssertData->numberOfCredentials =
            rk_build_RKList_from_rpID(ctap2AssertData->rpIdHash);
        if (ctap2AssertData->numberOfCredentials > 1) {
            // This settings will disable the app_nbgl_status call (nothing displayed on SK)
            // Else, this would lead the app to respond too slowly, and the client to bug out
            g.display_status = false;
            // This settings will allow the client to get info from possibly
            // following GET_NEXT_ASSERTION calls
            g.get_next_assertion_enabled = true;
        }
        if (ctap2AssertData->numberOfCredentials == 0) {
            send_cbor_error(&G_io_u2f, ERROR_NO_CREDENTIALS);
            return;
        }
        PRINTF("Matching credentials: %d\n", ctap2AssertData->numberOfCredentials);
        rk_next_credential_from_RKList(&slotIdx,
                                       &ctap2AssertData->nonce,
                                       &ctap2AssertData->credential,
                                       &ctap2AssertData->credentialLen);
        PRINTF("Go for index %d - %.*H\n",
               slotIdx,
               ctap2AssertData->credentialLen,
               ctap2AssertData->credential);
        get_assertion_send();
    }
}

void ctap2_get_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int protocol;
    int status;
    bool silentExit;

    PRINTF("CTAP2 get_assertion_handle\n");

    // GET_NEXT_ASSERTION flow is disabled by default.
    g.get_next_assertion_enabled = false;
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
    status = decode_rpid(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check clientDataHash
    status = decode_clientDataHash(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_getAssert_authnr_pinAuth(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check extensions
    status = decode_extensions(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check options
    status = decode_options(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    if (((ctap2AssertData->extensions & FLAG_EXTENSION_HMAC_SECRET) != 0) &&
        !ctap2AssertData->responseUpBit) {
        PRINTF("hmac-secret not allowed without up\n");
        status = ERROR_INVALID_OPTION;
        goto exit;
    }

    // Check PIN
    status = decode_pin(&decoder, &mapItem);
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

    if (CMD_IS_OVER_U2F_NFC) {
        // No up nor uv requested, skip UX and reply immediately
        nfc_handle_get_assertion();
    } else if (!ctap2AssertData->responseUpBit && !ctap2AssertData->uvOption) {
        // No up nor uv required, skip UX and reply immediately
        get_assertion_confirm(1);
    } else {
        // Look for a potential rk entry if no allow list was provided
        if (!ctap2AssertData->allowListPresent) {
            // This value will be set to 1 further into the code, because in this case (non-NFC,
            // non-RK), credential is chosen authenticator-side, *not* client-side (through
            // getNextAssertion).
            ctap2AssertData->numberOfCredentials =
                rk_build_RKList_from_rpID(ctap2AssertData->rpIdHash);
            if (ctap2AssertData->numberOfCredentials == 1) {
                // Single resident credential load it to go through the usual flow
                PRINTF("Single resident credential\n");
                status = rk_next_credential_from_RKList(NULL,
                                                        &ctap2AssertData->nonce,
                                                        &ctap2AssertData->credential,
                                                        &ctap2AssertData->credentialLen);
                if (status == RK_NOT_FOUND) {
                    // This can theoretically never happen.
                    // But still, if it does, fall back to the "No resident credentials" case
                    ctap2AssertData->numberOfCredentials = 0;
                }
            }
        }

        get_assertion_ux();
    }
    status = 0;

    /* authenticatorGetAssertion Algorithm step 9:
     * - => DEVIATION from spec: Always require user consent, even when up option is not requested. TODO enable silent auth?
     * - => DEVIATION from spec: Always ask the user to select the credential to use.
     *      Credential selection should be done in latter steps 11 and 12, and sometimes
     *      should be done without user action.
     */
    // ctap2_get_assertion_ux();
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
