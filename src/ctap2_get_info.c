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

#include "ctap2.h"
#include "cbip_encode.h"
#include "config.h"

#define CTAP_HEADER_SIZE 7

#define TAG_VERSIONS                     0x01
#define TAG_EXTENSIONS                   0x02
#define TAG_AAGUID                       0x03
#define TAG_OPTIONS                      0x04
#define TAG_MAX_MSG_SIZE                 0x05
#define TAG_PIN_PROTOCOLS                0x06
#define TAG_MAX_CREDENTIAL_COUNT_IN_LIST 0x07
#define TAG_MAX_CREDENTIAL_ID_LENGTH     0x08

#define VERSION_U2F   "U2F_V2"
#define VERSION_FIDO2 "FIDO_2_0"

void ctap2_get_info_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(buffer);
    UNUSED(length);

    cbipEncoder_t encoder;

    PRINTF("ctap2_get_info_handle\n");

    cbip_encoder_init(&encoder, G_io_apdu_buffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);

    cbip_add_map_header(&encoder, 6);

    // versions (0x01)

    cbip_add_int(&encoder, TAG_VERSIONS);
    cbip_add_array_header(&encoder, 2);
    cbip_add_string(&encoder, VERSION_U2F, sizeof(VERSION_U2F) - 1);
    cbip_add_string(&encoder, VERSION_FIDO2, sizeof(VERSION_FIDO2) - 1);

    // extensions (0x02)

    cbip_add_int(&encoder, TAG_EXTENSIONS);
    cbip_add_array_header(&encoder, 2);
    cbip_add_string(&encoder, EXTENSION_HMAC_SECRET, sizeof(EXTENSION_HMAC_SECRET) - 1);
    cbip_add_string(&encoder, EXTENSION_TX_AUTH_SIMPLE, sizeof(EXTENSION_TX_AUTH_SIMPLE) - 1);

    // AAGUID (0x03)

    cbip_add_int(&encoder, TAG_AAGUID);
    cbip_add_byte_string(&encoder, AAGUID, sizeof(AAGUID));

    // options (0x04)

    cbip_add_int(&encoder, TAG_OPTIONS);
    cbip_add_map_header(&encoder, 4);
    cbip_add_string(&encoder, OPTION_RESIDENT_KEY, sizeof(OPTION_RESIDENT_KEY) - 1);
    cbip_add_boolean(&encoder, true);
    cbip_add_string(&encoder, OPTION_USER_PRESENCE, sizeof(OPTION_USER_PRESENCE) - 1);
    cbip_add_boolean(&encoder, true);
    cbip_add_string(&encoder, OPTION_USER_VERIFICATION, sizeof(OPTION_USER_VERIFICATION) - 1);
    cbip_add_boolean(&encoder, true);
    cbip_add_string(&encoder, OPTION_CLIENT_PIN, sizeof(OPTION_CLIENT_PIN) - 1);
    cbip_add_boolean(&encoder, N_u2f.pinSet);

    // maxMsgSize (0x05)

    cbip_add_int(&encoder, TAG_MAX_MSG_SIZE);
    cbip_add_int(&encoder, CUSTOM_IO_APDU_BUFFER_SIZE - CTAP_HEADER_SIZE);

    // pinProtocols (0x06)

    cbip_add_int(&encoder, TAG_PIN_PROTOCOLS);
    cbip_add_array_header(&encoder, 1);
    cbip_add_int(&encoder, PIN_PROTOCOL_VERSION_V1);

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset);
}
