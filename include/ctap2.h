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

#ifndef __CTAP2_H__
#define __CTAP2_H__

#ifndef UNIT_TESTS
#include "cx.h"

#include "u2f_service.h"
#include "u2f_transport.h"
#else
#include "unit_test.h"
#endif

#include "cbip_decode.h"
#include "extension_hmac_secret.h"
#include "extension_txAuthSimple.h"

#define RP_ID_HASH_SIZE             CX_SHA256_SIZE
#define CRED_RANDOM_SIZE            32
#define HMAC_SECRET_SALT_SIZE       32
#define PIN_HASH_SIZE               16
#define AUTH_TOKEN_SIZE             16
#define AUTH_TOKEN_PROT_V1_ENC_SIZE AUTH_TOKEN_SIZE
#define AUTH_TOKEN_MAX_ENC_SIZE     AUTH_TOKEN_PROT_V1_ENC_SIZE
#define AUTH_PROT_V1_SIZE           16
#define SHARED_SECRET_V1_SIZE       32
#define SECRET_HMAC_KEY_SIZE        32
#define SECRET_AES_KEY_SIZE         32
#define SHARED_SECRET_MAX_SIZE      SHARED_SECRET_V1_SIZE

#define KEY_RP_ID "id"

#define OPTION_RESIDENT_KEY      "rk"
#define OPTION_USER_PRESENCE     "up"
#define OPTION_USER_VERIFICATION "uv"
#define OPTION_CLIENT_PIN        "clientPin"

#define CREDENTIAL_DESCRIPTOR_TYPE        "type"
#define CREDENTIAL_TYPE_PUBLIC_KEY        "public-key"
#define CREDENTIAL_TYPE_PUBLIC_KEY_LENGTH 10
#define CREDENTIAL_DESCRIPTOR_ID          "id"

#define KEY_USER_ID          "id"
#define KEY_USER_NAME        "name"
#define KEY_USER_DISPLAYNAME "displayName"
#define KEY_USER_ICON        "icon"

#define TAG_COSE_KTY   1
#define TAG_COSE_ALG   3
#define TAG_COSE_CRV   -1
#define TAG_COSE_X     -2
#define TAG_COSE_Y     -3
#define COSE_ALG_ES256 -7
// Assignment should be complete
// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-06
#define COSE_ALG_ES256K           -47
#define COSE_CURVE_P256K          8
#define COSE_ALG_EDDSA            -8
#define COSE_ALG_ECDH_ES_HKDF_256 -25
#define COSE_KEYTYPE_OKP          1
#define COSE_KEYTYPE_EC2          2
#define COSE_CURVE_P256           1
#define COSE_CURVE_ED25519        6

#define AUTHDATA_FLAG_USER_PRESENCE                    0x01
#define AUTHDATA_FLAG_USER_VERIFIED                    0x04
#define AUTHDATA_FLAG_ATTESTED_CREDENTIAL_DATA_PRESENT 0x40
#define AUTHDATA_FLAG_EXTENSION_DATA_PRESENT           0x80

#define PIN_PROTOCOL_VERSION_V1 1

#define FLAG_EXTENSION_HMAC_SECRET    0x01
#define FLAG_EXTENSION_TX_AUTH_SIMPLE 0x02

// Helper to detect if CTAP2_CBOR_CMD command is proxyied over U2F_CMD
// - CTAP2 calls that are CTAP2_CMD_CBOR commands:
//   There is a direct call from lib_stusb_impl/u2f_impl.c:u2f_message_complete()
//   to ctap2_handle_cmd_cbor(), hence G_io_app.apdu_state = APDU_IDLE
// - CTAP2 calls that are encapsulated on an APDU over U2F_CMD_MSG command
//   This calls goes through:
//   - lib_stusb_impl/u2f_impl.c:u2f_message_complete()
//   - lib_stusb_impl/u2f_impl.c:u2f_handle_cmd_msg()
//   - ....
//   - src/main.c:sample_main()
//   - src/u2f_processing.c:handleApdu()
//   In this case G_io_app.apdu_state is set to APDU_U2F in
//   lib_stusb_impl/u2f_impl.c:u2f_handle_cmd_msg()
#define CMD_IS_OVER_U2F_CMD        (G_io_app.apdu_state != APDU_IDLE)
#define CMD_IS_OVER_CTAP2_CBOR_CMD (G_io_app.apdu_state == APDU_IDLE)

extern const uint8_t AAGUID[16];

typedef struct ctap2_register_data_s {
    uint8_t rpIdHash[CX_SHA256_SIZE];
    uint8_t *buffer;  // pointer to the CBOR message in the APDU buffer
    char *rpId;
    uint32_t rpIdLen;
    uint8_t *clientDataHash;
    uint8_t *userId;
    uint32_t userIdLen;
    char *userStr;
    uint32_t userStrLen;
    int coseAlgorithm;     // algorithm chosen following the request message
    uint8_t pinRequired;   // set if uv is set
    uint8_t pinPresented;  // set if the PIN request was acknowledged by the user
    uint8_t
        clientPinAuthenticated;  // set if a standard FIDO client PIN authentication was performed
    uint8_t residentKey;         // set if the credential shall be created as a resident key
    uint8_t extensions;          // extensions flags as a bitmask
} ctap2_register_data_t;

typedef union ctap2_assert_multiple_flow_data_s {
    struct {
        cbipItem_t credentialItem;
        uint32_t credentialsNumber;
        uint32_t currentCredential;
    } allowList;
    struct {
        uint16_t minAge;
    } rk;
} ctap2_assert_multiple_flow_data_t;

typedef struct ctap2_assert_data_s {
    uint8_t rpIdHash[CX_SHA256_SIZE];
    uint8_t *buffer;  // pointer to the CBOR message in the APDU buffer
    char *rpId;
    uint32_t rpIdLen;
    uint8_t *clientDataHash;
    uint8_t *credId;
    uint32_t credIdLen;
    uint8_t *nonce;
    uint8_t *credential;
    uint32_t credentialLen;
    uint8_t pinRequired;   // set if uv is set
    uint8_t pinPresented;  // set if the PIN request was acknowledged by the user
    uint8_t
        clientPinAuthenticated;    // set if a standard FIDO client PIN authentication was performed
    uint8_t userPresenceRequired;  // set if up is set
    uint8_t singleCredential;      // set if a single credential was provided in the allow list
    uint8_t extensions;            // extensions flags as a bitmask

    uint8_t allowListPresent;
    uint16_t availableCredentials;

    // Multiple flow data
    uint16_t currentCredentialIndex;
    ctap2_assert_multiple_flow_data_t multipleFlowData;

    char *txAuthMessage;    // pointer to the TX Auth message or NULL
    uint32_t txAuthLength;  // length of the TX Auth message
    char
        txAuthLast;  // last character of the txAuth CBOR field overwritten by a '\0' when displayed
} ctap2_assert_data_t;

typedef enum ctap2_ux_state_e {
    CTAP2_UX_STATE_NONE = 0,
    CTAP2_UX_STATE_MAKE_CRED,
    CTAP2_UX_STATE_GET_ASSERTION,
    CTAP2_UX_STATE_MULTIPLE_ASSERTION,
    CTAP2_UX_STATE_NO_ASSERTION,
    CTAP2_UX_STATE_RESET,
    CTAP2_UX_STATE_CANCELLED = 0xff
} ctap2_ux_state_t;

typedef struct ctap2_proxy_s {
    bool uiStarted;
    uint32_t length;
} ctap2_proxy_t;

bool ctap2_check_rpid_filter(const char *rpId, uint32_t rpIdLen);
void ctap2_ux_get_rpid(const char *rpId, uint32_t rpIdLen, uint8_t *rpIdHash);
void send_cbor_error(u2f_service_t *service, uint8_t error);
void send_cbor_response(u2f_service_t *service, uint32_t length);
void ctap2_send_keepalive_processing(void);

// Correspond to FIDO2.1 spec performBuiltInUv() operation
void performBuiltInUv(void);

void ctap2_make_credential_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_get_assertion_handle(u2f_service_t *service,
                                uint8_t *buffer,
                                uint16_t length,
                                bool *immediateReply);
void ctap2_get_next_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_get_info_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_client_pin_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_reset_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);

void ctap2_make_credential_ux(void);
void ctap2_make_credential_confirm(void);
void ctap2_make_credential_user_cancel(void);

void ctap2_get_assertion_ux(ctap2_ux_state_t state);
void ctap2_get_assertion_next_credential_ux_helper(void);
void ctap2_get_assertion_confirm(void);
void ctap2_get_assertion_user_cancel(void);

void ctap2_reset_ux(void);
void ctap2_reset_confirm(void);
void ctap2_reset_cancel(void);

void ctap2_client_pin_reset_ctx(void);

/******************************************/
/*       PIN Auth Protocol functions      */
/******************************************/

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol regenerate() operation
int ctap2_client_pin_regenerate(void);

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol decapsulate() operation
int ctap2_client_pin_decapsulate(int protocol,
                                 cbipDecoder_t *decoder,
                                 cbipItem_t *mapItem,
                                 int key,
                                 uint8_t *sharedSecret);

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol verify() operation
bool ctap2_client_pin_verify(int protocol,
                             const uint8_t *key,
                             uint32_t keyLen,
                             const uint8_t *msg,
                             uint32_t msgLength,
                             const uint8_t *msg2,
                             uint32_t msg2Len,
                             const uint8_t *signature,
                             uint32_t signatureLength);

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol decrypt() operation
int ctap2_client_pin_decrypt(int protocol,
                             const uint8_t *sharedSecret,
                             const uint8_t *dataIn,
                             uint32_t dataInLength,
                             uint8_t *dataOut,
                             uint32_t *dataOutLength);

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol encrypt() operation
int ctap2_client_pin_encrypt(int protocol,
                             const uint8_t *sharedSecret,
                             const uint8_t *dataIn,
                             uint32_t dataInLength,
                             uint8_t *dataOut,
                             uint32_t *dataOutLength);

/******************************************/
/*        Pin Auth Token helpers          */
/******************************************/

int ctap2_client_pin_verify_auth_token(int protocol,
                                       const uint8_t *msg,
                                       uint32_t msgLength,
                                       const uint8_t *signature,
                                       uint32_t signatureLength);

#endif
