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
#include <cx.h>
#include <os_io_seproxyhal.h>

#include <u2f_service.h>
#include <u2f_transport.h>
#else
#include "unit_test.h"
#endif

#include "cbip_decode.h"
#include "extension_hmac_secret.h"
#include "ctap2_utils.h"

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

#define CREDENTIAL_DESCRIPTOR_ALG         "alg"
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

#define FLAG_EXTENSION_HMAC_SECRET 0x01

extern const uint8_t AAGUID[16];

// Correspond to FIDO2.1 spec performBuiltInUv() operation
void performBuiltInUv(void);

void ctap2_make_credential_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_get_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_get_next_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_get_info_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_client_pin_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);
void ctap2_reset_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length);

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
