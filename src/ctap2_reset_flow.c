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

// First step resets as fast as possible to please Windows

UX_STEP_CB(ux_ctap2_reset_flow_0_step,
           pb,
           ctap2_reset_confirm(),
           {&C_icon_eye, "Reset credentials"});

UX_STEP_NOCB(ux_ctap2_reset_flow_1_step,
             bnnn_paging,
             {
                 .title = "Warning",
                 .text = "All credentials will be invalidated",
             });

UX_STEP_CB(ux_ctap2_reset_flow_2_step,
           pbb,
           ctap2_reset_confirm(),
           {
               &C_icon_validate_14,
               "Confirm",
               "reset",
           });

UX_STEP_CB(ux_ctap2_reset_flow_3_step,
           pbb,
           ctap2_reset_cancel(),
           {
               &C_icon_crossmark,
               "Abort",
               "reset",
           });

UX_FLOW(ux_ctap2_reset_flow,
        &ux_ctap2_reset_flow_0_step,
        &ux_ctap2_reset_flow_1_step,
        &ux_ctap2_reset_flow_2_step,
        &ux_ctap2_reset_flow_3_step);

void ctap2_reset_ux(void) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2UxState = CTAP2_UX_STATE_RESET;

    G_ux.externalText = NULL;
    ux_flow_init(0, ux_ctap2_reset_flow, NULL);
}
