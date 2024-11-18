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
#include <lib_standard_app/format.h>

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

static int decode_allowList(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipItem_t tmpItem;
    int arrayLen;
    int status = CBIPH_STATUS_NOT_FOUND;
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

static void nfc_handle_get_assertion() {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    if (ctap2AssertData->allowListPresent) {
        // Allow list -> non-RK credentials.
        // Falling back to previous behavior: login with the first compatible credential
        g.is_getNextAssertion = false;
        get_assertion_confirm(1);
    } else {
        // No allow list -> RK credentials
        // Spec getnextAssertion behavior: creating a list of compatible credentials, returning
        // the first one & the number of compatible credentials, so that the client is able then to
        // call getNextAssertion to fetch other possible credentials.
        uint16_t slotIdx;
        ctap2AssertData->availableCredentials =
            rk_build_RKList_from_rpID(ctap2AssertData->rpIdHash);
        if (ctap2AssertData->availableCredentials > 1) {
            // This settings will disable the app_nbgl_status call (nothing displayed on SK)
            // Else, this would lead the app to respond too slowly, and the client to bug out
            g.is_getNextAssertion = true;
        }
        PRINTF("Matching credentials: %d\n", ctap2AssertData->availableCredentials);
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

static void copy_assert_info_on_buffers(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    ctap2_display_copy_rp(ctap2AssertData->rpId, ctap2AssertData->rpIdLen);

    if (ctap2AssertData->credId) {
        ctap2_display_copy_username((char *) ctap2AssertData->credId, ctap2AssertData->credIdLen);
    } else {
        uint8_t nameLength = MIN(CX_SHA256_SIZE, (sizeof(g.buffer2_65) - 1) / 2);
        format_hex(ctap2AssertData->clientDataHash, nameLength, g.buffer2_65, sizeof(g.buffer2_65));
    }
    PRINTF("After copy, buffer content:\n1 - '%s'\n2 - '%s'\n", g.buffer1_65, g.buffer2_65);
}

void ctap2_get_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int status;

    PRINTF("CTAP2 get_assertion_handle\n");

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

    // Check allowList
    status = decode_allowList(&decoder, &mapItem);
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
        !ctap2AssertData->userPresenceRequired) {
        PRINTF("hmac-secret not allowed without up\n");
        status = ERROR_INVALID_OPTION;
        goto exit;
    }

    // Check PIN
    status = decode_pin(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    copy_assert_info_on_buffers();

    /* if (true) { */
    /*     nfc_handle_get_assertion(); */

    /* } else */

    if (CMD_IS_OVER_U2F_NFC) {
        // No up nor uv requested, skip UX and reply immediately
        nfc_handle_get_assertion();
    } else if (!ctap2AssertData->userPresenceRequired && !ctap2AssertData->pinRequired) {
        // No up nor uv required, skip UX and reply immediately
        get_assertion_confirm(1);
    } else {
        // Look for a potential rk entry if no allow list was provided
        if (!ctap2AssertData->allowListPresent) {
            // This value will be set to 1 further into the code, because in this case (non-NFC,
            // non-RK), credential is chosen authenticator-side, *not* client-side (through
            // getNextAssertion).
            ctap2AssertData->availableCredentials =
                rk_build_RKList_from_rpID(ctap2AssertData->rpIdHash);
            if (ctap2AssertData->availableCredentials == 1) {
                // Single resident credential load it to go through the usual flow
                PRINTF("Single resident credential\n");
                status = rk_next_credential_from_RKList(NULL,
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
            get_assertion_ux(CTAP2_UX_STATE_NO_ASSERTION);
        } else if (ctap2AssertData->availableCredentials > 1) {
            // DEVIATION from FIDO2.0 spec in case of allowList presence:
            // "select any applicable credential and proceed".
            // We always ask the user to choose.
            get_assertion_ux(CTAP2_UX_STATE_MULTIPLE_ASSERTION);
        } else {
            get_assertion_ux(CTAP2_UX_STATE_GET_ASSERTION);
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
