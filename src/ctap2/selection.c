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
#include "ux.h"

#include "ctap2.h"
#include "globals.h"
#include "ui_shared.h"

static void selection_confirm(uint8_t code) {
    ctap2UxState = CTAP2_UX_STATE_NONE;

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, code, NULL);
    ui_idle();
}

static void selection_cancel(void) {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
    ui_idle();
}


#if defined(HAVE_BAGL)

static uint8_t selectionConfirmedCode;

// First step selects as fast as possible

UX_STEP_CB(ux_ctap2_selection_flow_0_step,
           pbb,
           selection_confirm(selectionConfirmedCode),
           {
               &C_icon_validate_14,
               "Device selection",
               "Confirm",
           });

UX_STEP_CB(ux_ctap2_selection_flow_1_step,
           pbb,
           selection_cancel(),
           {
               &C_icon_crossmark,
               "Device selection",
               "Abort",
           });

UX_FLOW(ux_ctap2_selection_flow,
        &ux_ctap2_selection_flow_0_step,
        &ux_ctap2_selection_flow_1_step,
        FLOW_LOOP);

void ctap2_selection_ux(uint8_t code) {
    // Save code for response value if user confirm
    selectionConfirmedCode = code;

    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2UxState = CTAP2_UX_STATE_SELECTION;

    G_ux.externalText = NULL;
    ux_flow_init(0, ux_ctap2_selection_flow, NULL);
}

#elif defined(HAVE_NBGL)

void ctap2_selection_ux(uint8_t code) {
    UNUSED(code);
}

#endif


void ctap2_selection_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(service);
    UNUSED(buffer);
    UNUSED(length);

    PRINTF("ctap2_selection_handle\n");
    ctap2_selection_ux(ERROR_NONE);
}
