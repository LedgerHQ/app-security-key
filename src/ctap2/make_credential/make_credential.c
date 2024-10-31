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
#include "cbip_helper.h"
#include "ui_shared.h"
#include "config.h"
#include "globals.h"

#include "make_credential_ui.h"
#include "make_credential_utils.h"

#define TAG_CLIENT_DATA_HASH    0x01
#define TAG_RP                  0x02
#define TAG_USER                0x03
#define TAG_PUB_KEY_CRED_PARAMS 0x04
#define TAG_EXCLUDE_LIST        0x05
#define TAG_EXTENSIONS          0x06
#define TAG_OPTIONS             0x07
#define TAG_PIN_AUTH            0x08
#define TAG_PIN_PROTOCOL        0x09

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

static int process_makeCred_authnr_keyCredParams(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
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

static int process_makeCred_authnr_excludeList(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
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
            // DEVIATION from FIDO2.0 spec: Should prompt user to exclude
            // Impact is minor because user has manually unlocked its device.
            // Therefore user presence is somehow guarantee.
            PRINTF("Valid candidate to exclude %d\n", i);
            return ERROR_CREDENTIAL_EXCLUDED;
        }
    }

    return 0;
}

static int process_makeCred_authnr_extensions(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
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

static int process_makeCred_authnr_options(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipItem_t optionsItem;
    int status;
    bool boolValue;

    CHECK_MAP_KEY_ITEM_IS_VALID(decoder, mapItem, TAG_OPTIONS, optionsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        // Forbidden option
        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_PRESENCE, &boolValue);
        if ((status == CBIPH_STATUS_FOUND) && !boolValue) {
            PRINTF("Forbidden user presence option\n");
            return ERROR_INVALID_OPTION;
        }

        status =
            cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_USER_VERIFICATION, &boolValue);
        if (status == CBIPH_STATUS_FOUND) {
            ctap2RegisterData->pinRequired = boolValue;
        }

        status = cbiph_get_map_key_str_bool(decoder, &optionsItem, OPTION_RESIDENT_KEY, &boolValue);
        if (status == CBIPH_STATUS_FOUND) {
#ifdef ENABLE_RK_CONFIG
            if (boolValue && !config_get_rk_enabled()) {
                PRINTF("RK disabled\n");
                return ERROR_UNSUPPORTED_OPTION;
            }
#endif
            ctap2RegisterData->residentKey = boolValue;
        }
    }

    return 0;
}

static int process_makeCred_authnr_pin(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
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
    if (status == CBIPH_STATUS_FOUND) {
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
                                                    ctap2RegisterData->clientDataHash,
                                                    CX_SHA256_SIZE,
                                                    pinAuth,
                                                    pinAuthLen);
        if (status != ERROR_NONE) {
            return ERROR_PIN_AUTH_INVALID;
        }

        ctap2RegisterData->clientPinAuthenticated = 1;
        PRINTF("Client PIN authenticated\n");
    } else {
        if (N_u2f.pinSet) {
            PRINTF("PIN set and no PIN authentication provided\n");
            return ERROR_PIN_REQUIRED;
        }
    }

    return 0;
}

void ctap2_make_credential_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int status;

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

    // Handle clientDataHash
    status = parse_makeCred_authnr_clientDataHash(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Handle rp
    status = parse_makeCred_authnr_rp(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Handle user
    status = parse_makeCred_authnr_user(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // RP & user decoded, we can store them into display buffer for future usage
    ctap2_copy_info_on_buffers();

    // Handle cryptographic algorithms
    status = process_makeCred_authnr_keyCredParams(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check exclude list
    status = process_makeCred_authnr_excludeList(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check extensions
    status = process_makeCred_authnr_extensions(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    // Check options
    status = process_makeCred_authnr_options(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    PRINTF("uv %d rk %d extensions %d\n",
           ctap2RegisterData->pinRequired,
           ctap2RegisterData->residentKey,
           ctap2RegisterData->extensions);

    // Check PIN auth
    status = process_makeCred_authnr_pin(&decoder, &mapItem);
    if (status != 0) {
        goto exit;
    }

    if (CMD_IS_OVER_U2F_NFC) {
        // No up nor uv requested, skip UX and reply immediately
        // TODO: is this what we want?
        ctap2_make_credential_confirm();
    } else {
        ctap2_make_credential_ux();
    }

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
