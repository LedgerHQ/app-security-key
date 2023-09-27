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

#if defined(HAVE_BAGL)

UX_STEP_NOCB(ux_ctap2_reset_flow_0_step,
             pnn,
             {
                 &C_icon_warning,
                 "Delete login details",
                 "for all websites?",
             });

UX_STEP_CB(ux_ctap2_reset_flow_1_step,
           pb,
           ctap2_reset_confirm(),
           {&C_icon_validate_14, "Yes, delete"});

UX_STEP_CB(ux_ctap2_reset_flow_2_step,
           pb,
           ctap2_reset_cancel(),
           {
               &C_icon_crossmark,
               "No, don't delete",
           });

UX_FLOW(ux_ctap2_reset_flow,
        &ux_ctap2_reset_flow_0_step,
        &ux_ctap2_reset_flow_1_step,
        &ux_ctap2_reset_flow_2_step);

void ctap2_reset_ux(void) {
    ctap2UxState = CTAP2_UX_STATE_RESET;

    G_ux.externalText = NULL;
    ux_flow_init(0, ux_ctap2_reset_flow, NULL);
}

#endif