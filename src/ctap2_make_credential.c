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

#define TAG_CLIENT_DATA_HASH    0x01
#define TAG_RP                  0x02
#define TAG_USER                0x03
#define TAG_PUB_KEY_CRED_PARAMS 0x04
#define TAG_EXCLUDE_LIST        0x05
#define TAG_EXTENSIONS          0x06
#define TAG_OPTIONS             0x07
#define TAG_PIN_AUTH            0x08
#define TAG_PIN_PROTOCOL        0x09

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
#ifdef HAVE_RK_SUPPORT_SETTING
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

void nfc_idle_work2(void) {
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
        send_cbor_response(&G_io_u2f, 1 + dataLen);
    } else {
        send_cbor_error(&G_io_u2f, status);
    }
}

void ctap2_make_credential_user_cancel() {
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
}
