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

#include "ctap2.h"
#include "config.h"
#include "ui_shared.h"
#include "globals.h"

void ctap2_reset_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(service);
    UNUSED(buffer);
    UNUSED(length);

    PRINTF("ctap2_reset_handle\n");
    ctap2_reset_ux();
}

void ctap2_reset_confirm() {
    ctap2UxState = CTAP2_UX_STATE_NONE;

    config_process_ctap2_reset();

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1);
    ui_idle();
}

void ctap2_reset_cancel() {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
    ui_idle();
}
