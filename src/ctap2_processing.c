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
#include "os_io_seproxyhal.h"
#include "u2f_processing.h"
#include "io.h"

#include "ctap2.h"
#include "cbip_helper.h"
#include "globals.h"
#include "fido_known_apps.h"
#include "ui_shared.h"

#define SW_NO_ERROR 0x9000

#define RPID_FILTER      "webctap."
#define RPID_FILTER_SIZE (sizeof(RPID_FILTER) - 1)

bool ctap2_check_rpid_filter(const char *rpId, uint32_t rpIdLen) {
    if ((rpIdLen < RPID_FILTER_SIZE) || (memcmp(rpId, RPID_FILTER, RPID_FILTER_SIZE) != 0)) {
        return true;
    } else {
        return false;
    }
}

void send_cbor_error(u2f_service_t *service, uint8_t error) {
    if (CMD_IS_OVER_U2F_CMD) {
        io_send_response_pointer((uint8_t *) &error, 1, SW_NO_ERROR);
    } else {
        u2f_message_reply(service, CTAP2_CMD_CBOR, (uint8_t *) &error, 1);
    }
}

void send_cbor_response(u2f_service_t *service, uint32_t length) {
    if (CMD_IS_OVER_U2F_CMD) {
        io_send_response_pointer(G_io_apdu_buffer, length, SW_NO_ERROR);
    } else {
        u2f_message_reply(service, CTAP2_CMD_CBOR, G_io_apdu_buffer, length);
    }
}

void ctap2_send_keepalive_processing() {
    if (CMD_IS_OVER_CTAP2_CBOR_CMD) {
        u2f_transport_ctap2_send_keepalive(&G_io_u2f, KEEPALIVE_REASON_PROCESSING);
        io_seproxyhal_io_heartbeat();
    }
}

void performBuiltInUv(void) {
    PRINTF("performBuiltInUv\n");
    // No-op as the user is verified through the session PIN.
}

#define CBOR_MAKE_CREDENTIAL    0x01
#define CBOR_GET_ASSERTION      0x02
#define CBOR_GET_NEXT_ASSERTION 0x08
#define CBOR_GET_INFO           0x04
#define CBOR_CLIENT_PIN         0x06
#define CBOR_RESET              0x07

void ctap2_handle_cmd_cbor(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    int status;
    // PRINTF("cmd_cbor %d %.*H\n", length, length, buffer);

    if (length < 1) {
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

#ifdef HAVE_CBOR_DEBUG
    PRINTF("CBOR %.*H\n", length, buffer);
    cbiph_dump(buffer + 1, length - 1);
#endif

    status = cbiph_validate(buffer + 1, length - 1);
    if (status < 0) {
        PRINTF("Failed to validate cbor\n");
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

    switch (buffer[0]) {
        case CBOR_MAKE_CREDENTIAL:
            ctap2_make_credential_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_GET_ASSERTION: {
            bool immediateReply;
            ctap2_get_assertion_handle(service, buffer + 1, length - 1, &immediateReply);
            if (immediateReply) {
                ctap2_get_assertion_confirm(1);
            }
        } break;
        case CBOR_GET_NEXT_ASSERTION:
            ctap2_get_next_assertion_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_GET_INFO:
            ctap2_get_info_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_CLIENT_PIN:
            ctap2_client_pin_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_RESET:
            ctap2_reset_handle(service, buffer + 1, length - 1);
            break;
        default:
            send_cbor_error(service, ERROR_INVALID_CBOR);
            break;
    }
}

void ctap2_handle_cmd_cancel(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(buffer);
    UNUSED(length);

    PRINTF("ctap2_cmd_cancel %d\n", ctap2UxState);
    if ((ctap2UxState != CTAP2_UX_STATE_NONE) && (ctap2UxState != CTAP2_UX_STATE_CANCELLED)) {
        PRINTF("Cancel pending UI\n");

        ctap2UxState = CTAP2_UX_STATE_CANCELLED;
        ui_idle();
        send_cbor_error(service, ERROR_KEEPALIVE_CANCEL);
    }
}
