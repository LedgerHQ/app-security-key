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

#ifdef HAVE_FIDO2

#include "os.h"
#include "ux.h"

#include "ctap2.h"
#include "globals.h"

// First step selects as fast as possible

UX_STEP_CB(ux_ctap2_selection_flow_0_step,
           pbb,
           ctap2_selection_confirm(),
           {
               &C_icon_validate_14,
               "Device selection",
               "Confirm",
           });

UX_STEP_CB(ux_ctap2_selection_flow_1_step,
           pbb,
           ctap2_selection_cancel(),
           {
               &C_icon_crossmark,
               "Device selection",
               "Abort",
           });

UX_FLOW(ux_ctap2_selection_flow,
        &ux_ctap2_selection_flow_0_step,
        &ux_ctap2_selection_flow_1_step,
        FLOW_LOOP);

void ctap2_selection_ux(void) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2UxState = CTAP2_UX_STATE_SELECTION;
    ctap2Proxy.uiStarted = true;

    G_ux.externalText = NULL;
    ux_flow_init(0, ux_ctap2_selection_flow, NULL);
}

#endif
