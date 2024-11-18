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

#include <os.h>
#include <cx.h>
#include <ledger_assert.h>

#include "ctap2.h"
#include "ctap2_utils.h"
#include "config.h"
#include "cbip_helper.h"
#include "cose_keys.h"
#include "crypto.h"
#include "globals.h"

#define TAG_PIN_PROTOCOL  0x01
#define TAG_SUBCOMMAND    0x02
#define TAG_KEY_AGREEMENT 0x03
#define TAG_PIN_AUTH      0x04
#define TAG_NEW_PIN_ENC   0x05
#define TAG_PIN_HASH_ENC  0x06

#define TAG_RESP_KEY_AGREEMENT 0x01
#define TAG_RESP_PIN_TOKEN     0x02
#define TAG_RESP_RETRIES       0x03

#define SUBCOMMAND_GET_PIN_RETRIES   0x01
#define SUBCOMMAND_GET_KEY_AGREEMENT 0x02
#define SUBCOMMAND_SET_PIN           0x03
#define SUBCOMMAND_CHANGE_PIN        0x04
#define SUBCOMMAND_GET_PIN_TOKEN     0x05

#define MIN_PIN_LENGTH                  4
#define MAX_PIN_LENGTH                  64
#define MAX_TRANSIENT_PIN_AUTH_FAILURES 3

static uint8_t authToken[AUTH_TOKEN_SIZE];
static uint8_t authTokenProtocol = 0;
static bool authTokeninUse;

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
        cx_err_t cx_err;

        cx_err = cx_hmac_sha256_init_no_throw(&hmac, key, keyLen);
        LEDGER_ASSERT(cx_err == CX_OK, "cx_hmac_sha256_init_no_throw fail");
        cx_err = cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, msg, msgLength, NULL, 0);
        LEDGER_ASSERT(cx_err == CX_OK, "cx_hmac_no_throw fail");
        cx_err = cx_hmac_no_throw((cx_hmac_t *) &hmac,
                                  CX_LAST,
                                  msg2,
                                  msg2Len,
                                  hmacValue,
                                  CX_SHA256_SIZE);
        LEDGER_ASSERT(cx_err == CX_OK, "cx_hmac_no_throw fail");
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

    return 0;
}

/******************************************/
/*   Pin Uv Auth Token Protocol helpers   */
/******************************************/

static bool is_token_valid(void) {
    if (!authTokeninUse) {
        return false;
    }
    return true;
}

int ctap2_client_pin_verify_auth_token(int protocol,
                                       const uint8_t *msg,
                                       uint32_t msgLength,
                                       const uint8_t *signature,
                                       uint32_t signatureLength) {
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
    authTokeninUse = false;

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1, NULL);
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

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_RETRIES);
    cbip_add_int(&encoder, N_u2f.pinRetries);

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset, NULL);
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

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_KEY_AGREEMENT);
    status = encode_cose_key(&encoder, &publicKey, true);
    if ((status < 0) || encoder.fault) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset, NULL);
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

static void ctap2_handle_get_pin_token(u2f_service_t *service,
                                       cbipDecoder_t *decoder,
                                       cbipItem_t *mapItem,
                                       int protocol) {
    int status;
    uint8_t sharedSecret[SHARED_SECRET_MAX_SIZE];
    uint8_t *pinHashEnc;
    uint32_t pinHashEncLen;
    cbipEncoder_t encoder;
    uint8_t tokenEnc[AUTH_TOKEN_MAX_ENC_SIZE];
    uint32_t encryptedLength;

    PRINTF("client_pin_get_pin_token\n");

    CHECK_PIN_SET();
    CHECK_PIN_RETRIES();
    CHECK_PIN_TRANSIENT_FAILURE();

    status =
        ctap2_client_pin_decapsulate(protocol, decoder, mapItem, TAG_KEY_AGREEMENT, sharedSecret);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        return;
    }

    // Check pinHashEnc
    if (cbiph_get_map_key_bytes(decoder, mapItem, TAG_PIN_HASH_ENC, &pinHashEnc, &pinHashEncLen) !=
        CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        return;
    }

    status = check_pin_hash(protocol, sharedSecret, pinHashEnc, pinHashEncLen);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        return;
    }

    // Prepare token
    authTokenProtocol = protocol;
    cx_rng_no_throw(authToken, AUTH_TOKEN_SIZE);
    authTokeninUse = true;
    PRINTF("Generated pin token %.*H\n", AUTH_TOKEN_SIZE, authToken);

    ctap2_client_pin_encrypt(protocol,
                             sharedSecret,
                             authToken,
                             AUTH_TOKEN_SIZE,
                             tokenEnc,
                             &encryptedLength);

    // Generate the response
    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_PIN_TOKEN);
    cbip_add_byte_string(&encoder, tokenEnc, encryptedLength);

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset, NULL);
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
    if (protocol != PIN_PROTOCOL_VERSION_V1) {
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
        default:
            PRINTF("Unsupported subcommand %d\n", tmp);
            send_cbor_error(service, ERROR_UNSUPPORTED_OPTION);
            break;
    }
}

void ctap2_client_pin_reset_ctx(void) {
    ctap2_client_pin_regenerate();
    authTokeninUse = false;

    ctap2TransientPinAuths = 0;
}
