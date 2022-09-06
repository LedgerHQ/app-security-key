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
#include "credential.h"
#include "globals.h"

static void ctap2_ux_multiple_next(void);
static void ctap2_ux_display_rp_assertion(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    ctap2_ux_get_rpid(ctap2AssertData->rpId, ctap2AssertData->rpIdLen, ctap2AssertData->rpIdHash);
}

static void ctap2_ux_display_user_assertion(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    credential_data_t credData;

    // TODO show that user.id is truncated if necessary
    if (credential_decode(&credData,
                          ctap2AssertData->credential,
                          ctap2AssertData->credentialLen,
                          true) != 0) {
        // This should never happen, but keep a consistent state if it ever does
        verifyHash[0] = '\0';
    } else if (credData.userStr != NULL) {
        uint8_t nameLength = MIN(credData.userStrLen, sizeof(verifyHash) - 1);
        memcpy(verifyHash, credData.userStr, nameLength);
        verifyHash[nameLength] = '\0';
    } else {
        snprintf(verifyHash, sizeof(verifyHash), "%.*H", credData.userIdLen, credData.userId);
        verifyHash[sizeof(verifyHash) - 1] = '\0';
    }

    PRINTF("name %s\n", verifyName);
    PRINTF("hash %s\n", verifyHash);
}

UX_STEP_CB(ux_ctap2_get_assertion_flow_0_step,
           pbb,
           ctap2_get_assertion_confirm(),
           {
               &C_icon_validate_14,
               "Login",
               "FIDO 2",
           });

UX_STEP_NOCB_INIT(ux_ctap2_get_assertion_flow_1_step,
                  bnnn_paging,
                  ctap2_ux_display_rp_assertion(),
                  {
                      .title = "Domain",
                      .text = (char *) verifyHash,
                  });

UX_STEP_NOCB_INIT(ux_ctap2_get_assertion_flow_2_step,
                  bnnn_paging,
                  ctap2_ux_display_user_assertion(),
                  {
                      .title = "User",
                      .text = (char *) verifyHash,
                  });
UX_STEP_CB(ux_ctap2_get_assertion_flow_3_step,
           pbb,
           ctap2_get_assertion_user_cancel(),
           {
               &C_icon_crossmark,
               "Abort",
               "login",
           });

UX_FLOW(ux_ctap2_get_assertion_flow,
        &ux_ctap2_get_assertion_flow_0_step,
        &ux_ctap2_get_assertion_flow_1_step,
        &ux_ctap2_get_assertion_flow_2_step,
        &ux_ctap2_get_assertion_flow_3_step,
        FLOW_LOOP);

// Extra steps and flow if there are multiple credentials
UX_STEP_NOCB(ux_ctap2_get_assertion_multiple_flow_0_step,
             pbb,
             {
                 &C_icon_people,
                 "Login multi",
                 "FIDO 2",
             });

UX_STEP_NOCB_INIT(ux_ctap2_get_assertion_multiple_flow_2_step,
                  bnnn_paging,
                  ctap2_ux_display_user_assertion(),
                  {
                      .title = (char *) verifyName,
                      .text = (char *) verifyHash,
                  });

UX_STEP_CB(ux_ctap2_get_assertion_multiple_flow_3_step,
           pbb,
           ctap2_ux_multiple_next(),
           {
               &C_icon_people,
               "Next",
               "User",
           });

UX_STEP_CB(ux_ctap2_get_assertion_multiple_flow_4_step,
           pbb,
           ctap2_get_assertion_confirm(),
           {
               &C_icon_validate_14,
               "Confirm",
               "login",
           });

UX_FLOW(ux_ctap2_get_assertion_multiple_flow,
        &ux_ctap2_get_assertion_multiple_flow_0_step,
        &ux_ctap2_get_assertion_flow_1_step,
        &ux_ctap2_get_assertion_multiple_flow_2_step,
        &ux_ctap2_get_assertion_multiple_flow_3_step,
        &ux_ctap2_get_assertion_multiple_flow_4_step,
        &ux_ctap2_get_assertion_flow_3_step,
        FLOW_LOOP);

// Extra steps if a text is associated to the TX for single assertion
UX_STEP_NOCB(ux_ctap2_get_assertion_text_flow_0_step,
             pbb,
             {
                 &C_icon_certificate,
                 "Login",
                 "FIDO 2",
             });

UX_STEP_NOCB(ux_ctap2_get_assertion_text_flow_1_step,
             bnnn_paging,
             {.title = "Message", .text = NULL});

UX_STEP_CB(ux_ctap2_get_assertion_text_flow_3_step,
           pbb,
           ctap2_get_assertion_confirm(),
           {
               &C_icon_validate_14,
               "Confirm",
               "login",
           });

UX_FLOW(ux_ctap2_get_assertion_text_flow,
        &ux_ctap2_get_assertion_text_flow_0_step,
        &ux_ctap2_get_assertion_text_flow_1_step,
        &ux_ctap2_get_assertion_flow_1_step,
        &ux_ctap2_get_assertion_flow_2_step,
        &ux_ctap2_get_assertion_text_flow_3_step,
        &ux_ctap2_get_assertion_flow_3_step,
        FLOW_LOOP);

// Extra steps if a text is associated to the TX for multiple assertion
UX_STEP_NOCB(ux_ctap2_get_assertion_multiple_text_flow_0_step,
             pbb,
             {
                 &C_icon_certificate,
                 "Login multi",
                 "FIDO 2",
             });

UX_FLOW(ux_ctap2_get_assertion_multiple_text_flow,
        &ux_ctap2_get_assertion_multiple_text_flow_0_step,
        &ux_ctap2_get_assertion_text_flow_1_step,
        &ux_ctap2_get_assertion_flow_1_step,
        &ux_ctap2_get_assertion_multiple_flow_2_step,
        &ux_ctap2_get_assertion_multiple_flow_3_step,
        &ux_ctap2_get_assertion_multiple_flow_4_step,
        &ux_ctap2_get_assertion_flow_3_step,
        FLOW_LOOP);

// Dedicated flow to get user presence confirmation if no account is registered
UX_STEP_CB(ux_ctap2_no_assertion_flow_0_step,
           pbb,
           ctap2_get_assertion_no_assertion_confirm(),
           {
               &C_icon_validate_14,
               "No account",
               "registered",
           });

UX_STEP_NOCB_INIT(ux_ctap2_no_assertion_flow_1_step,
                  bnnn_paging,
                  ctap2_ux_display_rp_assertion(),
                  {
                      .title = "Domain",
                      .text = (char *) verifyHash,
                  });

UX_FLOW(ux_ctap2_no_assertion_flow,
        &ux_ctap2_no_assertion_flow_0_step,
        &ux_ctap2_no_assertion_flow_1_step,
        FLOW_LOOP);

static void get_next_multiple_flow_state(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    ctap2_get_assertion_next_credential_ux_helper();

    snprintf((char *) verifyName,
             sizeof(verifyName),
             "User %d / %d",
             ctap2AssertData->currentCredentialIndex,
             ctap2AssertData->numberOfCredentials);
}

static void ctap2_ux_multiple_next(void) {
    PRINTF("ctap2_ux_multiple_next\n");
    get_next_multiple_flow_state();
    ux_flow_init(0,
                 ux_ctap2_get_assertion_multiple_flow,
                 &ux_ctap2_get_assertion_multiple_flow_2_step);
}

void ctap2_get_assertion_ux(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2Proxy.uiStarted = true;

    if (ctap2AssertData->txAuthMessage != NULL) {
        ctap2AssertData->txAuthLast = ctap2AssertData->txAuthMessage[ctap2AssertData->txAuthLength];
        ctap2AssertData->txAuthMessage[ctap2AssertData->txAuthLength] = '\0';
        G_ux.externalText = ctap2AssertData->txAuthMessage;
    } else {
        G_ux.externalText = NULL;
    }

    if (ctap2AssertData->numberOfCredentials == 1) {
        ctap2UxState = CTAP2_UX_STATE_GET_ASSERTION;
        if (ctap2AssertData->txAuthMessage != NULL) {
            ux_flow_init(0, ux_ctap2_get_assertion_text_flow, NULL);
        } else {
            ux_flow_init(0, ux_ctap2_get_assertion_flow, NULL);
        }
    } else {
        ctap2UxState = CTAP2_UX_STATE_MULTIPLE_ASSERTION;
        get_next_multiple_flow_state();
        if (ctap2AssertData->txAuthMessage != NULL) {
            ux_flow_init(0, ux_ctap2_get_assertion_multiple_text_flow, NULL);
        } else {
            ux_flow_init(0, ux_ctap2_get_assertion_multiple_flow, NULL);
        }
    }
}
