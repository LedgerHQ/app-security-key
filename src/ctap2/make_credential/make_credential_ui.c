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
#include "ux.h"

#include "globals.h"
#include "ui_messages.h"
#include "ui_shared.h"

#include "make_credential_ui.h"
#include "make_credential_utils.h"

static void ctap_ux_on_user_choice(bool confirm) {
    ctap2UxState = CTAP2_UX_STATE_NONE;

    if (confirm) {
        ctap2_make_credential_confirm();
#ifdef HAVE_NBGL
        app_nbgl_status(CTAP2_REGISTRATION, true, ui_idle);
#else
        ui_idle();
#endif
    } else {
        ctap2_make_credential_user_cancel();
#ifdef HAVE_NBGL
        app_nbgl_status(CTAP2_REGISTRATION_CANCELLED, false, ui_idle);
#else
        ui_idle();
#endif
    }
}

#if defined(HAVE_BAGL)

UX_STEP_NOCB(ux_ctap2_make_cred_flow_first_step,
             pnn,
             {
                 &C_icon_security_key,
                 "Register new",
                 "account",
             });

UX_STEP_NOCB(ux_ctap2_make_cred_flow_domain_step,
             bnnn_paging,
             {
                 .title = "Website",
                 .text = g.rp_buffer,
             });

UX_STEP_NOCB(ux_ctap2_make_cred_flow_user_step,
             bnnn_paging,
             {
                 .title = "User ID",
                 .text = g.username_buffer,
             });

UX_STEP_CB(ux_ctap2_make_cred_flow_accept_step,
           pb,
           ctap_ux_on_user_choice(true),
           {
               &C_icon_validate_14,
               "Register",
           });

UX_STEP_CB(ux_ctap2_make_cred_flow_refuse_step,
           pb,
           ctap_ux_on_user_choice(false),
           {
               &C_icon_crossmark,
               "Don't register",
           });

UX_STEP_CB(ux_ctap2_make_cred_resident_flow_accept_step,
           pbb,
           ctap_ux_on_user_choice(true),
           {
               &C_icon_validate_14,
               "Register",
               "resident key",
           });

UX_FLOW(ux_ctap2_make_cred_flow,
        &ux_ctap2_make_cred_flow_first_step,
        &ux_ctap2_make_cred_flow_domain_step,
        &ux_ctap2_make_cred_flow_user_step,
        &ux_ctap2_make_cred_flow_accept_step,
        &ux_ctap2_make_cred_flow_refuse_step);

UX_FLOW(ux_ctap2_make_cred_resident_flow,
        &ux_ctap2_make_cred_flow_first_step,
        &ux_ctap2_make_cred_flow_domain_step,
        &ux_ctap2_make_cred_flow_user_step,
        &ux_ctap2_make_cred_resident_flow_accept_step,
        &ux_ctap2_make_cred_flow_refuse_step);

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"
#include "nbgl_layout.h"

#define NB_OF_PAIRS 2
static const nbgl_layoutTagValue_t pairs[NB_OF_PAIRS] = {{
                                                             .item = "Website",
                                                             .value = g.rp_buffer,
                                                         },
                                                         {
                                                             .item = "User ID",
                                                             .value = g.username_buffer,
                                                         }};

#endif

void ctap2_make_credential_ux(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();
    ctap2UxState = CTAP2_UX_STATE_MAKE_CRED;

    UX_WAKE_UP();

#if defined(HAVE_BAGL)
    ux_flow_init(0,
                 (ctap2RegisterData->residentKey ? ux_ctap2_make_cred_resident_flow
                                                 : ux_ctap2_make_cred_flow),
                 NULL);
#elif defined(HAVE_NBGL)
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);

    if (ctap2RegisterData->residentKey) {
        app_nbgl_start_review(NB_OF_PAIRS,
                              pairs,
                              "Register resident key",
                              ctap_ux_on_user_choice,
                              NULL);
    } else {
        app_nbgl_start_review(NB_OF_PAIRS, pairs, "Register", ctap_ux_on_user_choice, NULL);
    }
#endif
}
