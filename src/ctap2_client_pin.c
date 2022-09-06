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

#include "os.h"
#include "cx.h"
#include "../src/cx_hkdf.h"

#include "ctap2.h"
#include "config.h"
#include "cbip_helper.h"
#include "cose_keys.h"
#include "crypto.h"
#include "globals.h"
#include "ui_shared.h"

#define TAG_PIN_PROTOCOL  0x01
#define TAG_SUBCOMMAND    0x02
#define TAG_KEY_AGREEMENT 0x03
#define TAG_PIN_AUTH      0x04
#define TAG_NEW_PIN_ENC   0x05
#define TAG_PIN_HASH_ENC  0x06
#define TAG_PERMISSIONS   0x09
#define TAG_RP_ID         0x0A

#define TAG_RESP_KEY_AGREEMENT 0x01
#define TAG_RESP_PIN_TOKEN     0x02
#define TAG_RESP_PIN_RETRIES   0x03
#define TAG_RESP_UV_RETRIES    0x05

#define SUBCOMMAND_GET_PIN_RETRIES    0x01
#define SUBCOMMAND_GET_KEY_AGREEMENT  0x02
#define SUBCOMMAND_SET_PIN            0x03
#define SUBCOMMAND_CHANGE_PIN         0x04
#define SUBCOMMAND_GET_PIN_TOKEN      0x05
#define SUBCOMMAND_GET_AUTH_TOKEN_UV  0x06
#define SUBCOMMAND_GET_UV_RETRIES     0x07
#define SUBCOMMAND_GET_AUTH_TOKEN_PIN 0x09

#define MIN_PIN_LENGTH                  4
#define MAX_PIN_LENGTH                  64
#define MAX_TRANSIENT_PIN_AUTH_FAILURES 3

#define HKDF_INFO_HMAC      "CTAP2 HMAC key"
#define HKDF_INFO_HMAC_SIZE (sizeof(HKDF_INFO_HMAC) - 1)
#define HKDF_INFO_AES       "CTAP2 AES key"
#define HKDF_INFO_AES_SIZE  (sizeof(HKDF_INFO_AES) - 1)

// Choice:
// - consider const uint8_t maxUvRetries = 1, as after a try device is wiped
// - so no need for uvRetries counter
// - TODO: Should set get_info.preferredPlatformUvAttempts = 1

#define TOKEN_MAX_USAGE_LIMIT_MS     (10 * 60 * 1000)  // 10 minutes in msec
#define TOKEN_USER_PRESENT_LIMIT_MS  (30 * 1000)       // 30 seconds in msec
#define TOKEN_INITIAL_USAGE_LIMIT_MS (30 * 1000)       // 30 seconds in msec

static uint8_t authToken[AUTH_TOKEN_SIZE];
static uint8_t authTokenProtocol = 0;
static uint8_t authTokenPerms = 0;
static uint8_t authTokenRpIdHash[CX_SHA256_SIZE];
static uint32_t authTokenStartUptimeMs;
static bool authTokeninUse;
static bool authTokenFirstUsageDone;
static uint8_t authTokenUserVerifiedFlag;
static uint8_t authTokenUserPresentFlag;

static uint8_t ctap2TransientPinAuths;

static cx_ecfp_private_key_t ctap2KeyAgreement;

/******************************************/
/*        Context check helpers           */
/******************************************/
#define CHECK_PIN_SET()                                       \
    do {                                                      \
        if (!N_u2f.pinSet) {                                  \
            PRINTF("PIN not set\n");                          \
            send_cbor_error(service, ERROR_PIN_AUTH_INVALID); \
            return;                                           \
        }                                                     \
    } while (0)

#define CHECK_PIN_NOT_SET()                                   \
    do {                                                      \
        if (N_u2f.pinSet) {                                   \
            PRINTF("PIN already set\n");                      \
            send_cbor_error(service, ERROR_PIN_AUTH_INVALID); \
            return;                                           \
        }                                                     \
    } while (0)

#define CHECK_PIN_RETRIES()                              \
    do {                                                 \
        if (N_u2f.pinRetries == 0) {                     \
            PRINTF("PIN blocked\n");                     \
            send_cbor_error(service, ERROR_PIN_BLOCKED); \
            return;                                      \
        }                                                \
    } while (0)

#define CHECK_PIN_TRANSIENT_FAILURE()                                    \
    do {                                                                 \
        if (ctap2TransientPinAuths >= MAX_TRANSIENT_PIN_AUTH_FAILURES) { \
            PRINTF("PIN authentication blocked temporarily\n");          \
            send_cbor_error(service, ERROR_PIN_AUTH_BLOCKED);            \
            return;                                                      \
        }                                                                \
    } while (0)

/******************************************/
/*     PIN/UV Auth Protocol functions     */
/******************************************/
// Correspond to FIDO2.1 spec PIN/UV Auth Protocol regenerate() operation
int ctap2_client_pin_regenerate(void) {
    cx_ecfp_public_key_t publicKey;
    if (cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256R1, &publicKey, &ctap2KeyAgreement, 0) !=
        CX_OK) {
        PRINTF("regenerate key agreement failed\n");
        return -1;
    }
    return 0;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol decapsulate() operation
int ctap2_client_pin_decapsulate(int protocol,
                                 cbipDecoder_t *decoder,
                                 cbipItem_t *mapItem,
                                 int key,
                                 uint8_t *sharedSecret) {
    int status;
    cbipItem_t keyMapItem;
    cx_ecfp_public_key_t publicKey;
    uint8_t tmp[32];

    GET_MAP_KEY_ITEM(decoder, mapItem, key, keyMapItem, cbipMap);

    status = decode_cose_key(decoder, &keyMapItem, &publicKey, false);
    if (status < 0) {
        return ERROR_INVALID_CBOR;
    }

    status = cx_ecdh_no_throw(&ctap2KeyAgreement,
                              CX_ECDH_X,
                              publicKey.W,
                              sizeof(publicKey.W),
                              tmp,
                              sizeof(tmp));
    if (status != CX_OK) {
        PRINTF("ECDH failed\n");
        return ERROR_OTHER;
    }

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        cx_hash_sha256(tmp, sizeof(tmp), sharedSecret, SHARED_SECRET_V1_SIZE);
        PRINTF("Shared secret %.*H\n", SHARED_SECRET_V1_SIZE, sharedSecret);
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        uint8_t *hmacKey = sharedSecret;
        uint8_t *aesKey = sharedSecret + SECRET_HMAC_KEY_SIZE;

        cx_hkdf_extract(CX_SHA256, tmp, sizeof(tmp), NULL, 0, tmp);

        cx_hkdf_expand(CX_SHA256,
                       tmp,
                       sizeof(tmp),
                       (unsigned char *) HKDF_INFO_HMAC,
                       HKDF_INFO_HMAC_SIZE,
                       hmacKey,
                       SECRET_HMAC_KEY_SIZE);
        PRINTF("Shared hmac key %.*H\n", SECRET_HMAC_KEY_SIZE, hmacKey);

        cx_hkdf_expand(CX_SHA256,
                       tmp,
                       sizeof(tmp),
                       (unsigned char *) HKDF_INFO_AES,
                       HKDF_INFO_AES_SIZE,
                       aesKey,
                       SECRET_AES_KEY_SIZE);
        PRINTF("Shared aes key %.*H\n", SECRET_AES_KEY_SIZE, aesKey);
    } else {
        return ERROR_INVALID_PAR;
    }

    return ERROR_NONE;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol verify() operation
bool ctap2_client_pin_verify(int protocol,
                             const uint8_t *key,
                             uint32_t keyLen,
                             const uint8_t *msg,
                             uint32_t msgLength,
                             const uint8_t *msg2,
                             uint32_t msg2Len,
                             const uint8_t *signature,
                             uint32_t signatureLength) {
    uint8_t hmacValue[CX_SHA256_SIZE];

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        if (signatureLength != AUTH_PROT_V1_SIZE) {
            return ERROR_INVALID_CBOR;
        }
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        if (signatureLength != AUTH_PROT_V2_SIZE) {
            return ERROR_INVALID_CBOR;
        }
    } else {
        return ERROR_INVALID_PAR;
    }

    if (keyLen > CX_SHA256_SIZE) {
        // If key is longer than CX_SHA256_SIZE bytes, discard the excess.
        // This selects the HMAC-key portion of the shared secret.
        keyLen = CX_SHA256_SIZE;
    }

    if (msg2 == NULL) {
        cx_hmac_sha256(key, keyLen, msg, msgLength, hmacValue, CX_SHA256_SIZE);
    } else {
        cx_hmac_sha256_t hmac;

        cx_hmac_sha256_init(&hmac, key, keyLen);  // Can use
        cx_hmac((cx_hmac_t *) &hmac, 0, msg, msgLength, NULL, 0);
        cx_hmac((cx_hmac_t *) &hmac, CX_LAST, msg2, msg2Len, hmacValue, CX_SHA256_SIZE);
    }

    if (!crypto_compare(signature, hmacValue, signatureLength)) {
        PRINTF("signature %.*H\n", signatureLength, signature);
        PRINTF("computed sign %.*H\n", signatureLength, hmacValue);
        explicit_bzero(hmacValue, sizeof(hmacValue));
        return false;
    }

    explicit_bzero(hmacValue, sizeof(hmacValue));
    return true;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol decrypt() operation
int ctap2_client_pin_decrypt(int protocol,
                             const uint8_t *sharedSecret,
                             const uint8_t *dataIn,
                             uint32_t dataInLength,
                             uint8_t *dataOut,
                             uint32_t *dataOutLength) {
    const uint8_t *aesKey;
    const uint8_t *iv;
    uint8_t ivLength;
    const uint8_t *data;
    uint32_t dataLength;
    cx_aes_key_t key;

    if ((dataInLength % CX_AES_BLOCK_SIZE) != 0) {
        return -1;
    }
    *dataOutLength = dataInLength;

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        aesKey = sharedSecret;
        iv = NULL;
        ivLength = 0;
        data = dataIn;
        dataLength = dataInLength;
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        aesKey = sharedSecret + SECRET_HMAC_KEY_SIZE;
        iv = dataIn;
        ivLength = IV_PROT_V2_SIZE;
        data = dataIn + IV_PROT_V2_SIZE;
        dataLength = dataInLength - IV_PROT_V2_SIZE;
    } else {
        return -1;
    }

    if (cx_aes_init_key_no_throw(aesKey, SECRET_AES_KEY_SIZE, &key) != CX_OK) {
        return -1;
    }
    if (cx_aes_iv_no_throw(&key,
                           CX_LAST | CX_DECRYPT | CX_PAD_NONE | CX_CHAIN_CBC,
                           iv,
                           ivLength,
                           data,
                           dataLength,
                           dataOut,
                           dataOutLength) != CX_OK) {
        return -1;
    }

    return 0;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol encrypt() operation
int ctap2_client_pin_encrypt(int protocol,
                             const uint8_t *sharedSecret,
                             const uint8_t *dataIn,
                             uint32_t dataInLength,
                             uint8_t *dataOut,
                             uint32_t *dataOutLength) {
    const uint8_t *aesKey;
    uint8_t *iv;
    uint8_t ivLength;
    uint8_t *data;
    cx_aes_key_t key;
    *dataOutLength = dataInLength;

    if ((dataInLength % CX_AES_BLOCK_SIZE) != 0) {
        return -1;
    }

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        aesKey = sharedSecret;
        iv = NULL;
        ivLength = 0;
        data = dataOut;
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        aesKey = sharedSecret + SECRET_HMAC_KEY_SIZE;
        cx_rng(dataOut, IV_PROT_V2_SIZE);
        iv = dataOut;
        ivLength = IV_PROT_V2_SIZE;
        data = dataOut + IV_PROT_V2_SIZE;
    } else {
        return -1;
    }

    if (cx_aes_init_key_no_throw(aesKey, SECRET_AES_KEY_SIZE, &key) != CX_OK) {
        return -1;
    }
    if (cx_aes_iv_no_throw(&key,
                           CX_LAST | CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_CBC,
                           iv,
                           ivLength,
                           dataIn,
                           dataInLength,
                           data,
                           dataOutLength) != CX_OK) {
        return -1;
    }

    if (protocol == PIN_PROTOCOL_VERSION_V2) {
        *dataOutLength += IV_PROT_V2_SIZE;
    }

    return 0;
}

/******************************************/
/*   Pin Uv Auth Token Protocol helpers   */
/******************************************/
static uint32_t get_uptime_ms(void) {
    return uptime_ms;
}

static void beginUsingPinUvAuthToken(bool userIsPresent) {
    authTokenUserPresentFlag = userIsPresent;
    authTokenUserVerifiedFlag = true;
    authTokenStartUptimeMs = get_uptime_ms();
    authTokeninUse = true;
}

static void stopUsingPinUvAuthToken(void) {
    authTokeninUse = false;
}

// Equivalent to spec pinUvAuthTokenUsageTimerObserver()
static bool is_token_valid(void) {
    uint32_t currentUptimeMs = get_uptime_ms();

    if (!authTokeninUse) {
        return false;
    }

    if (currentUptimeMs > authTokenStartUptimeMs + TOKEN_MAX_USAGE_LIMIT_MS) {
        stopUsingPinUvAuthToken();
        return false;
    }

    if (authTokenUserPresentFlag) {
        if (currentUptimeMs > authTokenStartUptimeMs + TOKEN_USER_PRESENT_LIMIT_MS) {
            authTokenUserPresentFlag = false;
        }
    }

    if (!authTokenFirstUsageDone) {
        if (currentUptimeMs > authTokenStartUptimeMs + TOKEN_INITIAL_USAGE_LIMIT_MS) {
            stopUsingPinUvAuthToken();
            return false;
        } else {
            // consider that the token has been used
            authTokenFirstUsageDone = true;
        }
    }
    return true;
}

bool getUserPresentFlagValue(void) {
    if (authTokeninUse) {
        return authTokenUserPresentFlag;
    }
    return false;
}

bool getUserVerifiedFlagValue(void) {
    if (authTokeninUse) {
        return authTokenUserVerifiedFlag;
    }
    return false;
}

void clearUserPresentFlag(void) {
    authTokenUserPresentFlag = false;
}

void clearUserVerifiedFlag(void) {
    authTokenUserVerifiedFlag = false;
}

void clearPinUvAuthTokenPermissionsExceptLbw(void) {
    authTokenPerms &= (AUTH_TOKEN_PERM_RP_ID | AUTH_TOKEN_PERM_LARGE_BLOB_wRITE);
}

int ctap2_client_pin_verify_auth_token(int protocol,
                                       uint8_t neededPerm,
                                       uint8_t *rpIdHash,
                                       const uint8_t *msg,
                                       uint32_t msgLength,
                                       const uint8_t *signature,
                                       uint32_t signatureLength,
                                       bool needUserVerificated) {
    if (!is_token_valid()) {
        return ERROR_PIN_AUTH_INVALID;
    }

    if (protocol != authTokenProtocol) {
        return ERROR_INVALID_PAR;
    }

    if (!ctap2_client_pin_verify(protocol,
                                 authToken,
                                 AUTH_TOKEN_SIZE,
                                 msg,
                                 msgLength,
                                 NULL,
                                 0,
                                 signature,
                                 signatureLength)) {
        return ERROR_PIN_AUTH_INVALID;
    }

    if ((authTokenPerms & neededPerm) != neededPerm) {
        PRINTF("Missing perms\n");
        return ERROR_PIN_AUTH_INVALID;
    }

    if (authTokenPerms & AUTH_TOKEN_PERM_RP_ID) {
        if (memcmp(authTokenRpIdHash, rpIdHash, CX_SHA256_SIZE) != 0) {
            PRINTF("Bad rpIdHash\n");
            return ERROR_PIN_AUTH_INVALID;
        }
    }

    if (needUserVerificated) {
        if (!getUserVerifiedFlagValue()) {
            return ERROR_PIN_AUTH_INVALID;
        }
    }

    if ((authTokenPerms & AUTH_TOKEN_PERM_RP_ID) == 0) {
        authTokenPerms |= AUTH_TOKEN_PERM_RP_ID;
        memcpy(authTokenRpIdHash, rpIdHash, CX_SHA256_SIZE);
    }

    return ERROR_NONE;
}

/******************************************/
/*         Pin handling helpers           */
/******************************************/
static void handle_store_pin(u2f_service_t *service,
                             int protocol,
                             const uint8_t *sharedSecret,
                             uint8_t *pinEnc,
                             uint32_t pinEncLen) {
    uint32_t pinLenOut;

    // Decrypt pin in place
    if (ctap2_client_pin_decrypt(protocol, sharedSecret, pinEnc, pinEncLen, pinEnc, &pinLenOut) !=
        0) {
        PRINTF("PIN decryption failed\n");
        send_cbor_error(service, ERROR_PIN_POLICY_VIOLATION);
        return;
    }

    if (pinLenOut != MAX_PIN_LENGTH) {
        PRINTF("Invalid padded PIN length\n");
        send_cbor_error(service, ERROR_INVALID_PAR);
        return;
    }

    // Remove padding
    for (int i = pinLenOut - 1; i != 0; i--) {
        if (pinEnc[i] == 0) {
            pinLenOut -= 1;
        } else {
            break;
        }
    }
    PRINTF("Decrypted PIN %.*H\n", pinLenOut, pinEnc);

    if ((pinLenOut < MIN_PIN_LENGTH) || (pinLenOut >= MAX_PIN_LENGTH)) {
        PRINTF("Invalid PIN length\n");
        send_cbor_error(service, ERROR_PIN_POLICY_VIOLATION);
        return;
    }

    // Store LEFT(SHA-256(newPin), 16) as requested in
    // https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#settingNewPin
    cx_hash_sha256(pinEnc, pinLenOut, pinEnc, CX_SHA256_SIZE);
    PRINTF("PIN hash %.*H\n", PIN_HASH_SIZE, pinEnc);
    config_set_ctap2_pin(pinEnc);

    // Invalidate previous token and force the user to issue a GET_PIN_TOKEN command
    stopUsingPinUvAuthToken();

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1);
}

static int check_pin_hash(int protocol,
                          const uint8_t *sharedSecret,
                          uint8_t *pinHashEnc,
                          uint32_t pinHashEncLen) {
    uint32_t pinHashLen;

    config_decrease_ctap2_pin_retry_counter();

    // Decrypt in place
    if (ctap2_client_pin_decrypt(protocol,
                                 sharedSecret,
                                 pinHashEnc,
                                 pinHashEncLen,
                                 pinHashEnc,
                                 &pinHashLen) != 0) {
        PRINTF("PIN hash decryption failed\n");
        ctap2TransientPinAuths++;
        return ERROR_PIN_INVALID;
    }

    if (!crypto_compare(pinHashEnc, (uint8_t *) N_u2f.pin, PIN_HASH_SIZE)) {
        PRINTF("Computed PIN hash %.*H\n", PIN_HASH_SIZE, pinHashEnc);
        PRINTF("Stored PIN hash %.*H\n", PIN_HASH_SIZE, N_u2f.pin);
        if (ctap2_client_pin_regenerate() != 0) {
            return ERROR_OTHER;
        }
        ctap2TransientPinAuths++;
        if (N_u2f.pinRetries == 0) {
            return ERROR_PIN_BLOCKED;
        }
        if (ctap2TransientPinAuths == MAX_TRANSIENT_PIN_AUTH_FAILURES) {
            return ERROR_PIN_AUTH_BLOCKED;
        }
        return ERROR_PIN_INVALID;
    }

    config_reset_ctap2_pin_retry_counter();
    ctap2TransientPinAuths = 0;

    return ERROR_NONE;
}

/******************************************/
/*         Subcommands Handlers           */
/******************************************/
static void ctap2_handle_get_pin_retries(u2f_service_t *service,
                                         cbipDecoder_t *decoder,
                                         cbipItem_t *mapItem,
                                         int protocol) {
    UNUSED(decoder);
    UNUSED(mapItem);
    UNUSED(protocol);

    cbipEncoder_t encoder;

    PRINTF("ctap2_handle_get_pin_retries\n");
    CHECK_PIN_SET();

    cbip_encoder_init(&encoder, G_io_apdu_buffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_PIN_RETRIES);
    cbip_add_int(&encoder, N_u2f.pinRetries);

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset);
}

static void ctap2_handle_get_uv_retries(u2f_service_t *service,
                                        cbipDecoder_t *decoder,
                                        cbipItem_t *mapItem,
                                        int protocol) {
    UNUSED(decoder);
    UNUSED(mapItem);
    UNUSED(protocol);

    cbipEncoder_t encoder;

    PRINTF("ctap2_handle_get_uv_retries\n");
    CHECK_PIN_SET();

    cbip_encoder_init(&encoder, G_io_apdu_buffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_UV_RETRIES);
    cbip_add_int(&encoder, 1);

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset);
}

static void ctap2_handle_get_key_agreement(u2f_service_t *service,
                                           cbipDecoder_t *decoder,
                                           cbipItem_t *mapItem,
                                           int protocol) {
    UNUSED(service);
    UNUSED(decoder);
    UNUSED(mapItem);
    UNUSED(protocol);

    int status;
    cbipEncoder_t encoder;
    cx_ecfp_public_key_t publicKey;

    PRINTF("client_pin_get_key_agreement\n");
    if (cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256R1, &publicKey, &ctap2KeyAgreement, 1) !=
        CX_OK) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    cbip_encoder_init(&encoder, G_io_apdu_buffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_KEY_AGREEMENT);
    status = encode_cose_key(&encoder, &publicKey, true);
    if ((status < 0) || encoder.fault) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset);
}

static void ctap2_handle_set_pin(u2f_service_t *service,
                                 cbipDecoder_t *decoder,
                                 cbipItem_t *mapItem,
                                 int protocol) {
    uint8_t *pinAuth;
    uint32_t pinAuthLen;
    uint8_t *newPinEnc;
    uint32_t newPinEncLen;
    uint8_t sharedSecret[SHARED_SECRET_MAX_SIZE];
    int status;

    PRINTF("client_pin_set_pin\n");
    CHECK_PIN_NOT_SET();

    status =
        ctap2_client_pin_decapsulate(protocol, decoder, mapItem, TAG_KEY_AGREEMENT, sharedSecret);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        return;
    }

    if (cbiph_get_map_key_bytes(decoder, mapItem, TAG_PIN_AUTH, &pinAuth, &pinAuthLen) !=
        CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        return;
    }

    if (cbiph_get_map_key_bytes(decoder, mapItem, TAG_NEW_PIN_ENC, &newPinEnc, &newPinEncLen) !=
        CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        return;
    }

    // Check pinAuth
    if (!ctap2_client_pin_verify(protocol,
                                 sharedSecret,
                                 sizeof(sharedSecret),
                                 newPinEnc,
                                 newPinEncLen,
                                 NULL,
                                 0,
                                 pinAuth,
                                 pinAuthLen)) {
        ctap2_client_pin_regenerate();
        send_cbor_error(service, ERROR_PIN_AUTH_INVALID);
        return;
    }

    handle_store_pin(service, protocol, sharedSecret, newPinEnc, newPinEncLen);
}

static void ctap2_handle_change_pin(u2f_service_t *service,
                                    cbipDecoder_t *decoder,
                                    cbipItem_t *mapItem,
                                    int protocol) {
    uint8_t *pinAuth;
    uint32_t pinAuthLen;
    uint8_t *pinHashEnc;
    uint32_t pinHashEncLen;
    uint8_t *newPinEnc;
    uint32_t newPinEncLen;
    uint8_t sharedSecret[SHARED_SECRET_MAX_SIZE];
    int status;

    PRINTF("client_pin_change_pin\n");
    CHECK_PIN_SET();
    CHECK_PIN_RETRIES();
    CHECK_PIN_TRANSIENT_FAILURE();

    status =
        ctap2_client_pin_decapsulate(protocol, decoder, mapItem, TAG_KEY_AGREEMENT, sharedSecret);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        return;
    }

    if (cbiph_get_map_key_bytes(decoder, mapItem, TAG_PIN_AUTH, &pinAuth, &pinAuthLen) !=
        CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        return;
    }

    if (cbiph_get_map_key_bytes(decoder, mapItem, TAG_PIN_HASH_ENC, &pinHashEnc, &pinHashEncLen) !=
        CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        return;
    }

    if (cbiph_get_map_key_bytes(decoder, mapItem, TAG_NEW_PIN_ENC, &newPinEnc, &newPinEncLen) !=
        CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        return;
    }

    // Check pinAuth
    if (!ctap2_client_pin_verify(protocol,
                                 sharedSecret,
                                 sizeof(sharedSecret),
                                 newPinEnc,
                                 newPinEncLen,
                                 pinHashEnc,
                                 pinHashEncLen,
                                 pinAuth,
                                 pinAuthLen)) {
        ctap2_client_pin_regenerate();
        send_cbor_error(service, ERROR_PIN_AUTH_INVALID);
        return;
    }

    // Check pinHashEnc
    status = check_pin_hash(protocol, sharedSecret, pinHashEnc, pinHashEncLen);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        return;
    }

    // Process new PIN
    handle_store_pin(service, protocol, sharedSecret, newPinEnc, newPinEncLen);
}

static void handle_generic_get_auth_token(u2f_service_t *service,
                                          cbipDecoder_t *decoder,
                                          cbipItem_t *mapItem,
                                          int protocol,
                                          bool legacyMethod,
                                          bool usePin) {
    int perms;
    int status;
    ctap2_pin_data_t *ctap2PinData = globals_get_ctap2_pin_data();
    memset(ctap2PinData, 0, sizeof(ctap2_pin_data_t));

    ctap2PinData->protocol = protocol;

    // Check perms
    status = cbiph_get_map_key_int(decoder, mapItem, TAG_PERMISSIONS, &perms);
    if (!legacyMethod) {
        if (status != CBIPH_STATUS_FOUND) {
            send_cbor_error(service, ERROR_MISSING_PARAMETER);
            return;
        }

        if (perms <= 0) {
            send_cbor_error(service, ERROR_INVALID_PAR);
            return;
        }
        if ((perms & AUTH_TOKEN_PERM_MASK) != perms) {
            send_cbor_error(service, ERROR_INVALID_PAR);
            return;
        }
        if ((perms & AUTH_TOKEN_PERM_CREDENTIAL_MGMT) || (perms & AUTH_TOKEN_PERM_BIO_ENROLLMENT) ||
            (perms & AUTH_TOKEN_PERM_LARGE_BLOB_wRITE) || (perms & AUTH_TOKEN_PERM_AUTHEN_CONFIG)) {
            send_cbor_error(service, 0x40);  // CTAP2_ERR_UNAUTHORIZED_PERMISSION
            return;
        }
    } else {
        if (status != CBIPH_STATUS_NOT_FOUND) {
            send_cbor_error(service, ERROR_INVALID_PAR);
            return;
        }
        perms = AUTH_TOKEN_PERM_MAKE_CREDENTIAL | AUTH_TOKEN_PERM_GET_ASSERTION;
    }
    ctap2PinData->perms = perms;

    // Check RP ID
    status = cbiph_get_map_key_text(decoder,
                                    mapItem,
                                    TAG_RP_ID,
                                    &ctap2PinData->rpId,
                                    &ctap2PinData->rpIdLen);
    if (!legacyMethod) {
        if (status < CBIPH_STATUS_NOT_FOUND) {
            send_cbor_error(service, ERROR_INVALID_CBOR);
        }
        if (ctap2PinData->rpId != NULL) {
            cx_hash_sha256((uint8_t *) ctap2PinData->rpId,
                           ctap2PinData->rpIdLen,
                           ctap2PinData->rpIdHash,
                           CX_SHA256_SIZE);
        }
    } else {
        if (status != CBIPH_STATUS_NOT_FOUND) {
            send_cbor_error(service, ERROR_INVALID_PAR);
            return;
        }
    }

    if (usePin) {
        CHECK_PIN_SET();
        CHECK_PIN_RETRIES();
        CHECK_PIN_TRANSIENT_FAILURE();
    }

    status = ctap2_client_pin_decapsulate(protocol,
                                          decoder,
                                          mapItem,
                                          TAG_KEY_AGREEMENT,
                                          ctap2PinData->sharedSecret);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        return;
    }

    if (usePin) {
        uint8_t *pinHashEnc;
        uint32_t pinHashEncLen;

        // Check pinHashEnc
        if (cbiph_get_map_key_bytes(decoder,
                                    mapItem,
                                    TAG_PIN_HASH_ENC,
                                    &pinHashEnc,
                                    &pinHashEncLen) != CBIPH_STATUS_FOUND) {
            send_cbor_error(service, ERROR_MISSING_PARAMETER);
            return;
        }

        status = check_pin_hash(protocol, ctap2PinData->sharedSecret, pinHashEnc, pinHashEncLen);
        if (status != ERROR_NONE) {
            send_cbor_error(service, status);
            return;
        }
    } else {
        performBuiltInUv();
        // TODO, catch user verification error
    }

    ctap2_ux_client_pin_get_token();
}

static void ctap2_handle_get_pin_token(u2f_service_t *service,
                                       cbipDecoder_t *decoder,
                                       cbipItem_t *mapItem,
                                       int protocol) {
    PRINTF("client_pin_get_pin_token\n");
    handle_generic_get_auth_token(service, decoder, mapItem, protocol, true, true);
}

static void ctap2_handle_get_auth_token_using_pin(u2f_service_t *service,
                                                  cbipDecoder_t *decoder,
                                                  cbipItem_t *mapItem,
                                                  int protocol) {
    PRINTF("ctap2_handle_get_auth_token_using_pin\n");
    handle_generic_get_auth_token(service, decoder, mapItem, protocol, false, true);
}

static void ctap2_handle_get_auth_token_using_uv(u2f_service_t *service,
                                                 cbipDecoder_t *decoder,
                                                 cbipItem_t *mapItem,
                                                 int protocol) {
    PRINTF("ctap2_handle_get_auth_token_using_uv\n");
    handle_generic_get_auth_token(service, decoder, mapItem, protocol, false, false);
}

void ctap2_confirm_client_pin_get_token(void) {
    cbipEncoder_t encoder;
    uint8_t tokenEnc[AUTH_TOKEN_MAX_ENC_SIZE];
    uint32_t encryptedLength;
    ctap2_pin_data_t *ctap2PinData = globals_get_ctap2_pin_data();

    ctap2UxState = CTAP2_UX_STATE_NONE;

    PRINTF("ctap2_confirm_client_pin_get_token\n");

    // Prepare token
    authTokenProtocol = ctap2PinData->protocol;
    cx_rng_no_throw(authToken, AUTH_TOKEN_SIZE);
    PRINTF("Generated pin token %.*H\n", AUTH_TOKEN_SIZE, authToken);
    authTokenPerms = ctap2PinData->perms;
    if (ctap2PinData->rpId != NULL) {
        authTokenPerms |= AUTH_TOKEN_PERM_RP_ID;
        memcpy(authTokenRpIdHash, ctap2PinData->rpIdHash, CX_SHA256_SIZE);
    }
    beginUsingPinUvAuthToken(false);

    ctap2_client_pin_encrypt(ctap2PinData->protocol,
                             ctap2PinData->sharedSecret,
                             authToken,
                             AUTH_TOKEN_SIZE,
                             tokenEnc,
                             &encryptedLength);

    // Generate the response
    cbip_encoder_init(&encoder, G_io_apdu_buffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_PIN_TOKEN);
    cbip_add_byte_string(&encoder, tokenEnc, encryptedLength);

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset);
    ui_idle();
}

void ctap2_user_cancel_client_pin_get_token(void) {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
    ui_idle();
}

/******************************************/
/*           Command Handler              */
/******************************************/
void ctap2_client_pin_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int status;
    int protocol;
    int tmp;

    PRINTF("ctap2_client_pin_handle\n");

    cbip_decoder_init(&decoder, buffer, length);
    cbip_first(&decoder, &mapItem);
    if (mapItem.type != cbipMap) {
        PRINTF("Invalid top item\n");
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

    // Check PIN protocol version
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_PIN_PROTOCOL, &protocol);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Error fetching pin protocol\n");
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }

    if ((protocol != PIN_PROTOCOL_VERSION_V1) && (protocol != PIN_PROTOCOL_VERSION_V2)) {
        PRINTF("Unsupported pin protocol version\n");
        send_cbor_error(service, ERROR_INVALID_PAR);
        return;
    }

    // Check subcommand
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_SUBCOMMAND, &tmp);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Error fetching subcommand\n");
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }
    switch (tmp) {
        case SUBCOMMAND_GET_PIN_RETRIES:
            ctap2_handle_get_pin_retries(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_GET_KEY_AGREEMENT:
            ctap2_handle_get_key_agreement(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_SET_PIN:
            ctap2_handle_set_pin(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_CHANGE_PIN:
            ctap2_handle_change_pin(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_GET_PIN_TOKEN:
            ctap2_handle_get_pin_token(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_GET_AUTH_TOKEN_UV:
            ctap2_handle_get_auth_token_using_uv(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_GET_UV_RETRIES:
            ctap2_handle_get_uv_retries(service, &decoder, &mapItem, protocol);
            break;
        case SUBCOMMAND_GET_AUTH_TOKEN_PIN:
            ctap2_handle_get_auth_token_using_pin(service, &decoder, &mapItem, protocol);
            break;
        default:
            PRINTF("Unsupported subcommand %d\n", tmp);
            send_cbor_error(service, ERROR_UNSUPPORTED_OPTION);
            break;
    }
}

void ctap2_client_pin_reset_ctx(void) {
    ctap2_client_pin_regenerate();
    stopUsingPinUvAuthToken();

    ctap2TransientPinAuths = 0;
}
