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

#include "cbip_helper.h"
#include "globals.h"
#include "fido_known_apps.h"
#include "ui_shared.h"
#include "sw_code.h"
#include "nfc_io.h"
#include "ctap2_utils.h"
#include "ctap2.h"

#define CBOR_MAKE_CREDENTIAL    0x01
#define CBOR_GET_ASSERTION      0x02
#define CBOR_GET_NEXT_ASSERTION 0x08
#define CBOR_GET_INFO           0x04
#define CBOR_CLIENT_PIN         0x06
#define CBOR_RESET              0x07
#define CBOR_SELECTION          0x0B

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
        case CBOR_GET_ASSERTION:
            ctap2_get_assertion_handle(service, buffer + 1, length - 1);
            break;
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
        case CBOR_SELECTION:
            ctap2_selection_handle(service, buffer + 1, length - 1);
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
    if (ctap2UxState != CTAP2_UX_STATE_NONE) {
        PRINTF("Cancel pending UI\n");

        ctap2UxState = CTAP2_UX_STATE_NONE;

        // Answer as fast as possible as Chrome expect a fast answer and in case
        // it didn't comes fast enough, it won't be sent back if the user
        // eventually choose again this authenticator.
        send_cbor_error(service, ERROR_KEEPALIVE_CANCEL);

#ifdef HAVE_BAGL
        ux_stack_pop();
        ux_stack_push();
#endif
        ui_idle();
    }
}
