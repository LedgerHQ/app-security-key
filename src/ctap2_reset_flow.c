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

static void ctap_ux_on_user_action(bool confirm) {
    ctap2UxState = CTAP2_UX_STATE_NONE;

    if (confirm) {
        ctap2_reset_confirm();
        ui_idle();
    } else {
        ctap2_reset_cancel();
        ui_idle();
    }
}

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
           ctap_ux_on_user_action(true),
           {&C_icon_validate_14, "Yes, delete"});

UX_STEP_CB(ux_ctap2_reset_flow_2_step,
           pb,
           ctap_ux_on_user_action(false),
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

    UX_WAKE_UP();

    ux_flow_init(0, ux_ctap2_reset_flow, NULL);
}

#elif defined(HAVE_NBGL)
#include "nbgl_use_case.h"

void ctap2_reset_ux(void) {
    ctap2UxState = CTAP2_UX_STATE_RESET;

    UX_WAKE_UP();

    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);

    nbgl_useCaseChoice(&C_warning64px,
                       "Delete saved login\n"
                       "details for all\n"
                       "websites?\n",
                       NULL,
                       "Yes, delete",
                       "No, don't delete",
                       ctap_ux_on_user_action);
}

#endif