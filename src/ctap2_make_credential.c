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
#include "cose_keys.h"
#include "crypto.h"
#include "crypto_data.h"
#include "ui_shared.h"
#include "config.h"
#include "rk_storage.h"
#include "globals.h"

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

#define TAG_RESP_FMT      0x01
#define TAG_RESP_AUTHDATA 0x02
#define TAG_RESP_ATTSTMT  0x03

#define KEY_RP_NAME "name"
#define KEY_RP_ICON "icon"

#define TAG_ALGORITHM        "alg"
#define TAG_SIGNATURE        "sig"
#define TAG_CERTIFICATE_X509 "x5c"

#define ATTESTATION_FORMAT_PACKED "packed"

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
    if (CMD_IS_OVER_U2F_CMD) {
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
            ctap2RegisterData->userStrLen = 64;
        }
        PRINTF("userStr %.*s\n", ctap2RegisterData->userStrLen, ctap2RegisterData->userStr);
    } else {
        PRINTF("userID %.*H\n", ctap2RegisterData->userIdLen, ctap2RegisterData->userId);
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
            ctap2RegisterData->rkOption = 1;
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
    ctap2_make_credential_ux();
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

static int encode_makeCred_public_key(const uint8_t *nonce,
                                      int coseAlgorithm,
                                      uint8_t *buffer,
                                      uint32_t bufferLength) {
    cbipEncoder_t encoder;
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;
    cx_curve_t bolosCurve;
    int status;

    bolosCurve = cose_alg_to_cx(coseAlgorithm);

    if (crypto_generate_private_key(nonce, &privateKey, bolosCurve) != 0) {
        return -1;
    }
    if (cx_ecfp_generate_pair_no_throw(bolosCurve, &publicKey, &privateKey, 1) != CX_OK) {
        return -1;
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
    if (ctap2RegisterData->responseUvBit) {
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
    ctap2CredentailData.residentKey = ctap2RegisterData->rkOption;
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

    ctap2UxState = CTAP2_UX_STATE_NONE;

    PRINTF("ctap2_make_credential_confirm\n");

    ctap2_send_keepalive_processing();

    ui_idle();

    // Perform User Verification if required
    if (ctap2RegisterData->uvOption) {
        performBuiltInUv();
        ctap2RegisterData->responseUvBit = 1;
    }

    ctap2_send_keepalive_processing();

    // Generate nonce
    cx_rng_no_throw(nonce, CREDENTIAL_NONCE_SIZE);

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
                                              G_io_apdu_buffer + 1,
                                              CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    if (status < 0) {
        status = ERROR_OTHER;
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

void ctap2_make_credential_user_cancel() {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
    ui_idle();
}
