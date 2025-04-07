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

#include "ctap2.h"
#include "ctap2_utils.h"
#include "cbip_encode.h"
#include "config.h"
#include "globals.h"

#define CTAP_HEADER_SIZE 7

#define TAG_VERSIONS                     0x01
#define TAG_EXTENSIONS                   0x02
#define TAG_AAGUID                       0x03
#define TAG_OPTIONS                      0x04
#define TAG_MAX_MSG_SIZE                 0x05
#define TAG_PIN_PROTOCOLS                0x06
#define TAG_MAX_CREDENTIAL_COUNT_IN_LIST 0x07
#define TAG_MAX_CREDENTIAL_ID_LENGTH     0x08
#define TAG_TRANSPORTS                   0x09
#define TAG_ALGORITHMS                   0x0A

#define OPTION_PLAT                 "plat"
#define OPTION_ALWAYS_UV            "alwaysUv"
#define OPTION_CRED_MGMT            "credMgmt"
#define OPTION_AUTHN_CFG            "authnrCfg"
#define OPTION_CLIENT_PIN           "clientPin"
#define OPTION_LARGE_BLOBS          "largeBlobs"
#define OPTION_PIN_UV_AUTH_TOKEN    "pinUvAuthToken"
#define OPTION_SET_MIN_PIN_LENGTH   "setMinPINLength"
#define OPTION_MAKE_CRED_WITHOUT_UV "makeCredUvNotRqd"
#define OPTION_CRED_MGMT_PREVIEW    "credentialMgmtPreview"

#define VERSION_U2F        "U2F_V2"
#define VERSION_FIDO2      "FIDO_2_0"
#define VERSION_FIDO21_PRE "FIDO_2_1_PRE"
#define VERSION_FIDO21     "FIDO_2_1"

#define TRANSPORT_USB "usb"
#define TRANSPORT_NFC "nfc"

static void cbip_add_option(cbipEncoder_t *encoder,
                            const char *option_desc,
                            size_t option_desc_size,
                            bool value) {
    cbip_add_string(encoder, option_desc, option_desc_size);
    cbip_add_boolean(encoder, value);
}

static void cbip_add_alg_pkey(cbipEncoder_t *encoder,
                              const char *alg_desc,
                              size_t alg_desc_size,
                              int alg) {
    cbip_add_map_header(encoder, 2);
    cbip_add_string(encoder, alg_desc, alg_desc_size);
    cbip_add_int(encoder, alg);
    cbip_add_string(encoder, CREDENTIAL_DESCRIPTOR_TYPE, sizeof(CREDENTIAL_DESCRIPTOR_TYPE) - 1);
    cbip_add_string(encoder, CREDENTIAL_TYPE_PUBLIC_KEY, sizeof(CREDENTIAL_TYPE_PUBLIC_KEY) - 1);
}

void ctap2_get_info_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(buffer);
    UNUSED(length);

    cbipEncoder_t encoder;

    PRINTF("ctap2_get_info_handle\n");

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);

    cbip_add_map_header(&encoder, 8);

    // versions (0x01)

    cbip_add_int(&encoder, TAG_VERSIONS);
    cbip_add_array_header(&encoder, 2);
    cbip_add_string(&encoder, VERSION_U2F, sizeof(VERSION_U2F) - 1);
    cbip_add_string(&encoder, VERSION_FIDO2, sizeof(VERSION_FIDO2) - 1);
    /* cbip_add_string(&encoder, VERSION_FIDO21_PRE, sizeof(VERSION_FIDO21_PRE) - 1); */
    /* cbip_add_string(&encoder, VERSION_FIDO21, sizeof(VERSION_FIDO21) - 1); */

    // extensions (0x02)

    cbip_add_int(&encoder, TAG_EXTENSIONS);
    cbip_add_array_header(&encoder, 1);
    cbip_add_string(&encoder, EXTENSION_HMAC_SECRET, sizeof(EXTENSION_HMAC_SECRET) - 1);

    // AAGUID (0x03)

    cbip_add_int(&encoder, TAG_AAGUID);
    cbip_add_byte_string(&encoder, AAGUID, sizeof(AAGUID));

    // options (0x04)
    // Ordered correctly - see here:
    // https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html#message-encoding
    cbip_add_int(&encoder, TAG_OPTIONS);
    cbip_add_map_header(&encoder, 5);
#ifdef ENABLE_RK_CONFIG
    cbip_add_option(&encoder,
                    OPTION_RESIDENT_KEY,
                    sizeof(OPTION_RESIDENT_KEY) - 1,
                    config_get_rk_enabled());
#else
    cbip_add_option(&encoder, OPTION_RESIDENT_KEY, sizeof(OPTION_RESIDENT_KEY) - 1, true);
#endif
    cbip_add_option(&encoder, OPTION_USER_PRESENCE, sizeof(OPTION_USER_PRESENCE) - 1, true);
    cbip_add_option(&encoder, OPTION_USER_VERIFICATION, sizeof(OPTION_USER_VERIFICATION) - 1, true);
    cbip_add_option(&encoder, OPTION_PLAT, sizeof(OPTION_PLAT) - 1, false);
    /*
    cbip_add_option(&encoder, OPTION_ALWAYS_UV, sizeof(OPTION_ALWAYS_UV) - 1, false);
    cbip_add_option(&encoder, OPTION_CRED_MGMT, sizeof(OPTION_CRED_MGMT) - 1, true);
    cbip_add_option(&encoder, OPTION_AUTHN_CFG, sizeof(OPTION_AUTHN_CFG) - 1, true);
    */
    cbip_add_option(&encoder, OPTION_CLIENT_PIN, sizeof(OPTION_CLIENT_PIN) - 1, N_u2f.pinSet);
    /*
    cbip_add_option(&encoder,
                    OPTION_LARGE_BLOBS, sizeof(OPTION_LARGE_BLOBS) - 1, true);
    cbip_add_option(&encoder,
                    OPTION_PIN_UV_AUTH_TOKEN,
                    sizeof(OPTION_PIN_UV_AUTH_TOKEN) - 1,
                    true);
    cbip_add_option(&encoder,
                    OPTION_SET_MIN_PIN_LENGTH,
                    sizeof(OPTION_SET_MIN_PIN_LENGTH) - 1, true);
    cbip_add_option(&encoder,
                    OPTION_MAKE_CRED_WITHOUT_UV,
                    sizeof(OPTION_MAKE_CRED_WITHOUT_UV) - 1,
                    true);
    cbip_add_option(&encoder,
                    OPTION_CRED_MGMT_PREVIEW,
                    sizeof(OPTION_CRED_MGMT_PREVIEW) - 1,
                    true);
    */

    // maxMsgSize (0x05)

    cbip_add_int(&encoder, TAG_MAX_MSG_SIZE);
    cbip_add_int(&encoder, CUSTOM_IO_APDU_BUFFER_SIZE - CTAP_HEADER_SIZE);

    // pinProtocols (0x06)

    cbip_add_int(&encoder, TAG_PIN_PROTOCOLS);
    cbip_add_array_header(&encoder, 1);
    cbip_add_int(&encoder, PIN_PROTOCOL_VERSION_V1);

    // transports (0x09)

    cbip_add_int(&encoder, TAG_TRANSPORTS);
    cbip_add_array_header(&encoder, 2);
    cbip_add_string(&encoder, TRANSPORT_USB, sizeof(TRANSPORT_USB) - 1);
    cbip_add_string(&encoder, TRANSPORT_NFC, sizeof(TRANSPORT_NFC) - 1);

    // algorithms (0x10)
    // List of 3, in this order of preference: ES256, EDDSA, ES256K
    cbip_add_int(&encoder, TAG_ALGORITHMS);
    cbip_add_array_header(&encoder, 3);
    cbip_add_alg_pkey(&encoder,
                      CREDENTIAL_DESCRIPTOR_ALG,
                      sizeof(CREDENTIAL_DESCRIPTOR_ALG) - 1,
                      COSE_ALG_ES256);
    cbip_add_alg_pkey(&encoder,
                      CREDENTIAL_DESCRIPTOR_ALG,
                      sizeof(CREDENTIAL_DESCRIPTOR_ALG) - 1,
                      COSE_ALG_EDDSA);
    cbip_add_alg_pkey(&encoder,
                      CREDENTIAL_DESCRIPTOR_ALG,
                      sizeof(CREDENTIAL_DESCRIPTOR_ALG) - 1,
                      COSE_ALG_ES256K);

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}
