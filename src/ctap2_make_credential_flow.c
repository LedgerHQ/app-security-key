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

static void ctap2_ux_get_display_user(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

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
           ctap2_make_credential_confirm(),
           {
               &C_icon_validate_14,
               "Register",
           });

UX_STEP_CB(ux_ctap2_make_cred_flow_refuse_step,
           pb,
           ctap2_make_credential_user_cancel(),
           {
               &C_icon_crossmark,
               "Don't register",
           });

UX_STEP_CB(ux_ctap2_make_cred_resident_flow_accept_step,
           pbb,
           ctap2_make_credential_confirm(),
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

#endif

void ctap2_make_credential_ux(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    ctap2UxState = CTAP2_UX_STATE_MAKE_CRED;

    // TODO show that rp.id is truncated if necessary
    uint8_t len = MIN(sizeof(rpID) - 1, ctap2RegisterData->rpIdLen);
    memcpy(rpID, ctap2RegisterData->rpId, len);
    rpID[len] = '\0';
    PRINTF("rpId %s\n", rpID);

    ctap2_ux_get_display_user();

#if defined(HAVE_BAGL)
    G_ux.externalText = NULL;
    ux_flow_init(0,
                 (ctap2RegisterData->residentKey ? ux_ctap2_make_cred_resident_flow
                                                 : ux_ctap2_make_cred_flow),
                 NULL);
#endif
}
