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
#include "cbip_helper.h"
#include "ui_shared.h"
#include "config.h"
#include "globals.h"

#include "make_credential_ui.h"
#include "make_credential_utils.h"

#define TAG_CLIENT_DATA_HASH       0x01
#define TAG_RP                     0x02
#define TAG_USER                   0x03
#define TAG_PUB_KEY_CRED_PARAMS    0x04
#define TAG_EXCLUDE_LIST           0x05
#define TAG_EXTENSIONS             0x06
#define TAG_OPTIONS                0x07
#define TAG_PIN_AUTH               0x08
#define TAG_PIN_PROTOCOL           0x09
#define TAG_ENTREPRISE_ATTESTATION 0x0A

#define KEY_RP_NAME "name"
#define KEY_RP_ICON "icon"

static int parse_makeCred_authnr_clientDataHash(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    uint32_t itemLength;
    int status;

    status = cbiph_get_map_key_bytes(decoder,
                                     mapItem,
                                     TAG_CLIENT_DATA_HASH,
                                     &ctap2RegisterData->clientDataHash,
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

static int parse_makeCred_authnr_rp(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t rpItem, tmpItem;
    int status;

    GET_MAP_KEY_ITEM(decoder, mapItem, TAG_RP, rpItem, cbipMap);

    if (cbiph_get_map_key_str_text(decoder,
                                   &rpItem,
                                   KEY_RP_ID,
                                   &ctap2RegisterData->rpId,
                                   &ctap2RegisterData->rpIdLen) != CBIPH_STATUS_FOUND) {
        return ERROR_MISSING_PARAMETER;
    }

#ifdef HAVE_FIDO2_RPID_FILTER
    if (CMD_IS_OVER_U2F_CMD && !CMD_IS_OVER_U2F_NFC) {
        if (ctap2_check_rpid_filter(ctap2RegisterData->rpId, ctap2RegisterData->rpIdLen)) {
            PRINTF("rpId denied by filter\n");
            return ERROR_PROP_RPID_MEDIA_DENIED;
        }
    }
#endif

    CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder, &rpItem, KEY_RP_NAME, tmpItem, cbipTextString);
    CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder, &rpItem, KEY_RP_ICON, tmpItem, cbipTextString);

    // Compute RP ID hash
    cx_hash_sha256((uint8_t *) ctap2RegisterData->rpId,
                   ctap2RegisterData->rpIdLen,
                   ctap2RegisterData->rpIdHash,
                   CX_SHA256_SIZE);

    // TODO: UTF-8 characters that are not ASCII will be dropped when displaying

    return 0;
}

static int parse_makeCred_authnr_user(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t userItem, tmpItem;
    int status;

    GET_MAP_KEY_ITEM(decoder, mapItem, TAG_USER, userItem, cbipMap);

    // check consistency
    if (cbiph_get_map_key_str_bytes(decoder,
                                    &userItem,
                                    KEY_USER_ID,
                                    &ctap2RegisterData->userId,
                                    &ctap2RegisterData->userIdLen) != CBIPH_STATUS_FOUND) {
        return ERROR_MISSING_PARAMETER;
    }

    CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder,
                                    &userItem,
                                    KEY_USER_DISPLAYNAME,
                                    tmpItem,
                                    cbipTextString);
    CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder, &userItem, KEY_USER_NAME, tmpItem, cbipTextString);
    CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder, &userItem, KEY_USER_ICON, tmpItem, cbipTextString);

    if (cbiph_get_map_key_str_text(decoder,
                                   &userItem,
                                   KEY_USER_DISPLAYNAME,
                                   &ctap2RegisterData->userStr,
                                   &ctap2RegisterData->userStrLen) == CBIPH_STATUS_FOUND) {
        // Avoid displaying an empty name, just in case
        if (ctap2RegisterData->userStrLen == 0) {
            ctap2RegisterData->userStr = NULL;
        }
    }
    if (ctap2RegisterData->userStr == NULL) {
        if (cbiph_get_map_key_str_text(decoder,
                                       &userItem,
                                       KEY_USER_NAME,
                                       &ctap2RegisterData->userStr,
                                       &ctap2RegisterData->userStrLen) == CBIPH_STATUS_FOUND) {
            // Avoid displaying an empty name, just in case
            if (ctap2RegisterData->userStrLen == 0) {
                ctap2RegisterData->userStr = NULL;
            }
        }
    }

    // TODO: UTF-8 characters that are not ASCII will be dropped when displaying

    if (ctap2RegisterData->userStr != NULL) {
        // Display name can be truncated to 64bytes
        // https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname
        if (ctap2RegisterData->userStrLen > 64) {
            // TODO show that user.display is truncated
            // TODO: on Flex, there is enough place for 3x18 characters (54), so it currently
            //       overflows under the "Register" button. We'll need to clean that (new page?)
            ctap2RegisterData->userStrLen = 64;
        }
        PRINTF("MAKE_CREDENTIAL: userStr %.*s\n",
               ctap2RegisterData->userStrLen,
               ctap2RegisterData->userStr);
    } else {
        PRINTF("MAKE_CREDENTIAL: userID %.*H\n",
               ctap2RegisterData->userIdLen,
               ctap2RegisterData->userId);
    }

    return 0;
}

static int parse_makeCred_authnr_pinAuth(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    int status;

    status = cbiph_get_map_key_bytes(decoder,
                                     mapItem,
                                     TAG_PIN_AUTH,
                                     &ctap2RegisterData->pinAuth,
                                     &ctap2RegisterData->pinAuthLen);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        return ERROR_INVALID_CBOR;
    }
    return 0;
}

static int parse_makeCred_authnr_extensions(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t extensionsItem;
    int status;
    bool value;

    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_EXTENSIONS, extensionsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        status =
            cbiph_get_map_key_str_bool(decoder, &extensionsItem, EXTENSION_HMAC_SECRET, &value);
        if (status == CBIPH_STATUS_FOUND) {
            if (value) {
                ctap2RegisterData->extensions |= FLAG_EXTENSION_HMAC_SECRET;
            }
        } else if (status != CBIPH_STATUS_NOT_FOUND) {
            return cbiph_map_cbor_error(status);
        }
    }

    return 0;
}

static int process_makeCred_authnr_alg_step1(bool *silentExit) {
    /* Step 1: Handle zero length pinUvAuthParam */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    uint8_t selectionConfirmedCode;

    *silentExit = false;
    if (ctap2RegisterData->pinAuth != NULL) {
        if (ctap2RegisterData->pinAuthLen == 0) {
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

static int process_makeCred_authnr_alg_step2(cbipDecoder_t *decoder,
                                             cbipItem_t *mapItem,
                                             int *protocol) {
    /* Step 2: Check pinUvAuthProtocol consistency */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    int status;

    if (ctap2RegisterData->pinAuth != NULL) {
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

static int process_makeCred_authnr_alg_step3(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    /* Step 3: Validate pubKeyCredParams */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t tmpItem;
    int arrayLen;
    int algorithmType;
    int status;

    GET_MAP_KEY_ITEM(decoder, mapItem, TAG_PUB_KEY_CRED_PARAMS, tmpItem, cbipArray);
    arrayLen = tmpItem.value;
    if (arrayLen == 0) {
        PRINTF("No valid pubkeyCredParams entry found");
        return ERROR_MISSING_PARAMETER;
    }
    for (int i = 0; i < arrayLen; i++) {
        if (i == 0) {
            cbip_next(decoder, &tmpItem);
        } else {
            cbiph_next_deep(decoder, &tmpItem);
        }
        status = cbiph_check_credential(decoder, &tmpItem);
        if (status == CBIPH_STATUS_NOT_FOUND) {
            continue;
        }
        if (status < 0) {
            PRINTF("Error fetching pubkeyCredParams entry\n");
            return cbiph_map_cbor_error(status);
        }

        status = cbiph_get_map_key_str_int(decoder, &tmpItem, TAG_ALGORITHM, &algorithmType);
        if (status != CBIPH_STATUS_FOUND) {
            return cbiph_map_cbor_error(status);
        }
        switch (algorithmType) {
            case COSE_ALG_ES256:
            case COSE_ALG_ES256K:
            case COSE_ALG_EDDSA:
                // Choose the first occurrence of an algorithm identifier supported by this
                // authenticator
                if (ctap2RegisterData->coseAlgorithm == 0) {
                    ctap2RegisterData->coseAlgorithm = algorithmType;
                }
                break;
            default:
                // Ignore unsupported algorithm
                break;
        }
    }

    PRINTF("Algorithm used %d\n", ctap2RegisterData->coseAlgorithm);
    switch (ctap2RegisterData->coseAlgorithm) {
        case COSE_ALG_ES256:
        case COSE_ALG_ES256K:
        case COSE_ALG_EDDSA:
            break;
        default:
            PRINTF("Unknown algorithm\n");
            return ERROR_UNSUPPORTED_ALGORITHM;
    }

    return 0;
}

static int process_makeCred_authnr_alg_step4(void) {
    /* Step 4: Create a new response structure and initialize both
     * its "uv" bit and "up" bit as false */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    ctap2RegisterData->responseUvBit = 0;
    // User presence is omitted as it is mandatory (see step 5)
    return 0;
}

static int process_makeCred_authnr_alg_step5(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    /* Step 5: Process all options */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t optionsItem;
    int status;
    bool boolValue;

    ctap2RegisterData->uvOption = 0;
    ctap2RegisterData->rkOption = 0;
    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_OPTIONS, optionsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        // Uv option
        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_VERIFICATION, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && boolValue) {
            ctap2RegisterData->uvOption = 1;
        }

        if (ctap2RegisterData->pinAuth != NULL) {
            // "Note: pinUvAuthParam and the "uv" option are processed as mutually
            // exclusive with pinUvAuthParam taking precedence."
            ctap2RegisterData->uvOption = 0;
        }

        // Rk option
        status = cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_RESIDENT_KEY, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && boolValue) {
#ifdef ENABLE_RK_CONFIG
            if (!config_get_rk_enabled()) {
                PRINTF("RK disabled\n");
                return ERROR_UNSUPPORTED_OPTION;
            }
#else
            ctap2RegisterData->rkOption = 1;
#endif
        }

        // Up option
        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_PRESENCE, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && !boolValue) {
            PRINTF("Forbidden user presence option\n");
            return ERROR_INVALID_OPTION;
        }
    }

    return 0;
}

static int process_makeCred_authnr_alg_step6(void) {
    /* Step 6: Handle alwaysUv option
     * => Do nothing as this option is not enabled */
    return 0;
}

static int process_makeCred_authnr_alg_step7(void) {
    /* Step 7: Handle makeCredUvNotRqd option */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    if ((ctap2RegisterData->uvOption == 0) && (ctap2RegisterData->pinAuth == NULL) &&
        (ctap2RegisterData->rkOption == 1)) {
        return ERROR_PIN_AUTH_INVALID;
    }
    return 0;
}

static int process_makeCred_authnr_alg_step8(void) {
    /* Step 8: Behavior for when makeCredUvNotRqd option is not enable
     * => Do nothing as this option is enabled */
    return 0;
}

static int process_makeCred_authnr_alg_step9(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    /* Step 9: Handle entrepriseAttestation */

    int status;
    cbipItem_t item;

    status = cbiph_get_map_item(decoder,
                                mapItem,
                                TAG_ENTREPRISE_ATTESTATION,
                                NULL,
                                &item,
                                CBIPH_TYPE_INT);
    if (status != CBIPH_STATUS_NOT_FOUND) {
        PRINTF("Error entreprise attestation not supported\n");
        return ERROR_INVALID_PAR;
    }
    return 0;
}

static int process_makeCred_authnr_alg_step10_and_step11(int protocol) {
    /* Step 10 in some condition allow to bypass step 11.
     * Therefore we process them in the same handler for commodity*/

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    int status;

    /* Step 10: Check if user verification can be skipped
     * Technically this step is useless as step 11 already do nothing if:
     * - uv option in not enabled
     * - pinUvAuthParam is not present
     * But we choose to skip to the spec steps for commodity. */

    if ((ctap2RegisterData->uvOption == 0) && (ctap2RegisterData->rkOption == 0) &&
        (ctap2RegisterData->pinAuth == NULL)) {
        // Skip step 11
        return 0;
    }

    /* Step 11: Check for user verification */

    if (ctap2RegisterData->pinAuth != NULL) {
        // Verify pinAuth, check permissions and userVerifiedFlagValue
        status = ctap2_client_pin_verify_auth_token(protocol,
                                                    AUTH_TOKEN_PERM_MAKE_CREDENTIAL,
                                                    ctap2RegisterData->rpIdHash,
                                                    ctap2RegisterData->clientDataHash,
                                                    CX_SHA256_SIZE,
                                                    ctap2RegisterData->pinAuth,
                                                    ctap2RegisterData->pinAuthLen,
                                                    true);
        if (status != ERROR_NONE) {
            return ERROR_PIN_AUTH_INVALID;
        }

        ctap2RegisterData->responseUvBit = 1;
        PRINTF("Client PIN authenticated\n");
    } else if (ctap2RegisterData->uvOption == 1) {
        // DEVIATION from spec: move BuiltInUV check in ctap2_make_credential_confirm() after step 14 (user consent)
    }

    return 0;
}

static int process_makeCred_authnr_alg_step12(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    /* Step 12: Process exclude list */

    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t tmpItem;
    int arrayLen;
    uint8_t *credId;
    uint32_t credIdLen;
    int status;

    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_EXCLUDE_LIST, tmpItem, cbipArray);
    arrayLen = tmpItem.value;
    if ((status == CBIPH_STATUS_FOUND) && (arrayLen > 0)) {
        for (int i = 0; i < arrayLen; i++) {
            if (i == 0) {
                cbip_next(decoder, &tmpItem);
            } else {
                cbiph_next_deep(decoder, &tmpItem);
            }

            // Check that credential 'type' exists and is 'public-key'
            status = cbiph_check_credential(decoder, &tmpItem);
            if (status == CBIPH_STATUS_NOT_FOUND) {
                continue;
            }
            if (status < 0) {
                PRINTF("Error fetching pubkeyCredParams entry\n");
                return cbiph_map_cbor_error(status);
            }

            status = cbiph_get_map_key_str_bytes(decoder,
                                                 &tmpItem,
                                                 CREDENTIAL_DESCRIPTOR_ID,
                                                 &credId,
                                                 &credIdLen);
            if (status != CBIPH_STATUS_FOUND) {
                return cbiph_map_cbor_error(status);
            }
            PRINTF("Trying credential %.*H\n", credIdLen, credId);
            if (credential_unwrap(ctap2RegisterData->rpIdHash,
                                  credId,
                                  credIdLen,
                                  NULL,
                                  NULL,
                                  NULL) < 0) {
                PRINTF("Skipping invalid credential candidate %d\n", i);
                continue;
            }

            // TODO: prompt user presence to exclude depending on credential credProtect value
            PRINTF("Valid candidate to exclude %d\n", i);
            return ERROR_CREDENTIAL_EXCLUDED;
        }
    }

    return 0;
}

static int process_makeCred_authnr_alg_step13(void) {
    /* Skip user presence (user consent) if performBuiltInUv() was called in step 11
     * => DEVIATION from spec: Do nothing as we don't want to skip user consent */
    return 0;
}

static void copy_register_info_on_buffers(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    ctap2_display_copy_rp(ctap2RegisterData->rpId, ctap2RegisterData->rpIdLen);

    if (ctap2RegisterData->userStr) {
        ctap2_display_copy_username(ctap2RegisterData->userStr, ctap2RegisterData->userStrLen);
    } else {
        uint8_t nameLength = MIN(ctap2RegisterData->userIdLen, (sizeof(g.buffer2_65) - 1) / 2);
        format_hex(ctap2RegisterData->userId, nameLength, g.buffer2_65, sizeof(g.buffer2_65));
    }
    PRINTF("After copy, buffer content:\n1 - '%s'\n2 - '%s'\n", g.buffer1_65, g.buffer2_65);
}

void ctap2_make_credential_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int protocol = 0;
    int status;
    bool silentExit;

    PRINTF("ctap2_make_credential_handle\n");

    memset(ctap2RegisterData, 0, sizeof(ctap2_register_data_t));
    ctap2RegisterData->buffer = buffer;

    // Init CBIP decoder
    cbip_decoder_init(&decoder, buffer, length);
    cbip_first(&decoder, &mapItem);
    if (mapItem.type != cbipMap) {
        PRINTF("Invalid top item\n");
        status = ERROR_INVALID_CBOR;
        goto exit;
    }

    /* Extract data from CBOR */
    status = parse_makeCred_authnr_clientDataHash(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_makeCred_authnr_rp(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_makeCred_authnr_user(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // RP & user decoded, we can store them into display buffer for future usage
    copy_register_info_on_buffers();

    status = parse_makeCred_authnr_pinAuth(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = parse_makeCred_authnr_extensions(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    /* Process each step of specification authenticatorMakeCredential Algorithm */
    status = process_makeCred_authnr_alg_step1(&silentExit);
    if (status != 0) {
        goto exit;
    }
    if (silentExit) {
        return;
    }

    status = process_makeCred_authnr_alg_step2(&decoder, &mapItem, &protocol);
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step3(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step4();
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step5(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step6();
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step7();
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step8();
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step9(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step10_and_step11(protocol);
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step12(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    status = process_makeCred_authnr_alg_step13();
    if (status != 0) {
        goto exit;
    }

    /* authenticatorMakeCredential Algorithm step 14:
     * - up option is mandatory true see step 5
     * - => DEVIATION from spec: Always require user consent
     */
    if (CMD_IS_OVER_U2F_NFC) {
        // No up nor uv requested, skip UX and reply immediately
        // TODO: is this what we want?
        ctap2_make_credential_confirm();
    } else {
        ctap2_make_credential_ux();
    }
    clearUserPresentFlag();
    clearUserVerifiedFlag();
    clearPinUvAuthTokenPermissionsExceptLbw();

    /* authenticatorMakeCredential Algorithm next steps:
     * - step 15: Extension output generation is done after user consent in
     *   - ctap2_make_credential_confirm()
     *     -> build_makeCred_authData()
     * - step 16-17-18: Credential creation is done after user consent in
     *   - ctap2_make_credential_confirm()
     *     -> build_makeCred_authData()
     *        -> ctap2_crypto_generate_wrapped_credential_and_pubkey()
     * - step 19: Generation of the attestation statement is done after user consent in
     *   - ctap2_make_credential_confirm()
     -     -> sign_and_build_makeCred_response()
     */

exit:
    if (status != 0) {
        PRINTF("Make_credential request parsing error %x\n", status);
        send_cbor_error(service, status);
    }
    return;
}

#ifdef HAVE_NFC
void nfc_idle_work2(void) {
    check_and_generate_new_pubkey();
}
#endif
