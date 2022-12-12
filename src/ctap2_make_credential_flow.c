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

#include "ctap2.h"
#include "globals.h"

static void ctap2_ux_display_rp(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    PRINTF("ctap2_ux_display_rp\n");
    ctap2_ux_get_rpid(ctap2RegisterData->rpId,
                      ctap2RegisterData->rpIdLen,
                      ctap2RegisterData->rpIdHash);
}

static void ctap2_ux_display_user(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    PRINTF("ctap2_ux_display_user\n");
    if (ctap2RegisterData->userStr) {
        uint8_t nameLength = MIN(ctap2RegisterData->userStrLen, sizeof(verifyHash) - 1);

        memcpy(verifyHash, ctap2RegisterData->userStr, nameLength);
        verifyHash[nameLength] = '\0';
    } else {
        snprintf(verifyHash,
                 sizeof(verifyHash),
                 "%.*H",
                 ctap2RegisterData->userIdLen,
                 ctap2RegisterData->userId);
        verifyHash[sizeof(verifyHash) - 1] = '\0';
    }
}

UX_STEP_CB(ux_ctap2_make_cred_flow_0_step,
           pbb,
           ctap2_make_credential_confirm(),
           {
               &C_icon_validate_14,
               "Register",
               "FIDO 2",
           });

UX_STEP_CB(ux_ctap2_make_cred_resident_flow_0_step,
           pbb,
           ctap2_make_credential_confirm(),
           {
               &C_icon_validate_14,
               "Register local",
               "FIDO 2",
           });

UX_STEP_NOCB(ux_ctap2_make_cred_resident_flow_0b_step,
             bnnn_paging,
             {
                 .title = "Warning",
                 .text = "This credential will be lost on application reset",
             });

UX_STEP_NOCB_INIT(ux_ctap2_make_cred_flow_1_step,
                  bnnn_paging,
                  ctap2_ux_display_rp(),
                  {
                      .title = "Domain",
                      .text = (char *) verifyHash,
                  });

UX_STEP_NOCB_INIT(ux_ctap2_make_cred_flow_2_step,
                  bnnn_paging,
                  ctap2_ux_display_user(),
                  {
                      .title = "User",
                      .text = (char *) verifyHash,
                  });
UX_STEP_CB(ux_ctap2_make_cred_flow_3_step,
           pbb,
           ctap2_make_credential_user_cancel(),
           {
               &C_icon_crossmark,
               "Abort",
               "register",
           });

UX_FLOW(ux_ctap2_make_cred_flow,
        &ux_ctap2_make_cred_flow_0_step,
        &ux_ctap2_make_cred_flow_1_step,
        &ux_ctap2_make_cred_flow_2_step,
        &ux_ctap2_make_cred_flow_3_step,
        FLOW_LOOP);

UX_FLOW(ux_ctap2_make_cred_resident_flow,
        &ux_ctap2_make_cred_resident_flow_0_step,
        &ux_ctap2_make_cred_resident_flow_0b_step,
        &ux_ctap2_make_cred_flow_1_step,
        &ux_ctap2_make_cred_flow_2_step,
        &ux_ctap2_make_cred_flow_3_step,
        FLOW_LOOP);

void ctap2_make_credential_ux(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2UxState = CTAP2_UX_STATE_MAKE_CRED;
    ctap2Proxy.uiStarted = true;

    G_ux.externalText = NULL;
    ux_flow_init(0,
                 (ctap2RegisterData->residentKey ? ux_ctap2_make_cred_resident_flow
                                                 : ux_ctap2_make_cred_flow),
                 NULL);
}
