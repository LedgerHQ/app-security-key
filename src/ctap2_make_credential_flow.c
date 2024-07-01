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
#include "format.h"

#include "ctap2.h"
#include "globals.h"
#include "ui_shared.h"

static void ctap2_ux_get_display_user(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    // TODO show that user.id is truncated if necessary
    if (ctap2RegisterData->userStr) {
        uint8_t nameLength = MIN(ctap2RegisterData->userStrLen, sizeof(verifyHash) - 1);

        memcpy(verifyHash, ctap2RegisterData->userStr, nameLength);
        verifyHash[nameLength] = '\0';
    } else {
        uint8_t nameLength = MIN(ctap2RegisterData->userIdLen, (sizeof(verifyHash) - 1) / 2);

        format_hex(ctap2RegisterData->userId, nameLength, verifyHash, sizeof(verifyHash));
    }
}

static void ctap_ux_on_user_choice(bool confirm) {
    ctap2UxState = CTAP2_UX_STATE_NONE;

    if (confirm) {
        ctap2_make_credential_confirm();
#ifdef HAVE_NBGL
        app_nbgl_status("Registration details\nsent", true, ui_idle, TUNE_SUCCESS);
#else
        ui_idle();
#endif
    } else {
        ctap2_make_credential_user_cancel();
#ifdef HAVE_NBGL
        app_nbgl_status("Registration cancelled", false, ui_idle, NBGL_NO_TUNE);
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
                 .text = rpID,
             });

UX_STEP_NOCB(ux_ctap2_make_cred_flow_user_step,
             bnnn_paging,
             {
                 .title = "User ID",
                 .text = verifyHash,
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
                                                             .value = rpID,
                                                         },
                                                         {
                                                             .item = "User ID",
                                                             .value = verifyHash,
                                                         }};

#endif

void ctap2_make_credential_ux(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    ctap2UxState = CTAP2_UX_STATE_MAKE_CRED;

    // TODO show that rp.id is truncated if necessary
    uint8_t len = MIN(sizeof(g.rpID) - 1, ctap2RegisterData->rpIdLen);
    memcpy(g.rpID, ctap2RegisterData->rpId, len);

    rpID[len] = '\0';
    ctap2_ux_get_display_user();

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
