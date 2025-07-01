/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2024 Ledger
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

#include <lib_standard_app/io.h>
#include "u2f_processing.h"

#include "ctap2.h"
#include "ctap2_utils.h"
#include "globals.h"
#include "nfc_io.h"
#include "sw_code.h"

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

void send_cbor_response(u2f_service_t *service, uint32_t length, const char *status) {
    if (CMD_IS_OVER_U2F_NFC) {
        nfc_io_set_response_ready(SW_NO_ERROR, length, status);
        nfc_io_send_prepared_response();
    } else if (CMD_IS_OVER_U2F_CMD) {
        io_send_response_pointer(responseBuffer, length, SW_NO_ERROR);
    } else {
        u2f_message_reply(service, CTAP2_CMD_CBOR, responseBuffer, length);
    }
}

void ctap2_send_keepalive_processing() {
    if (CMD_IS_OVER_CTAP2_CBOR_CMD) {
        u2f_transport_ctap2_send_keepalive(&G_io_u2f, KEEPALIVE_REASON_PROCESSING);
#ifndef REVAMPED_IO
        io_seproxyhal_io_heartbeat();
#endif  // !REVAMPED_IO
    }
}

void performBuiltInUv(void) {
    PRINTF("performBuiltInUv\n");
    // No-op as the user is verified through the session PIN.
}
