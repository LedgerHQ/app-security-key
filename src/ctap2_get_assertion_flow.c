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

UX_STEP_CB(ux_ctap2_get_assertion_flow_accept_step,
           pbb,
           ctap2_get_assertion_confirm(),
           {
               &C_icon_validate_14,
               "Approve",
               "login request",
           });

UX_STEP_NOCB_INIT(ux_ctap2_get_assertion_flow_domain_step,
                  bnnn_paging,
                  ctap2_ux_display_rp_assertion(),
                  {
                      .title = "Domain",
                      .text = (char *) verifyHash,
                  });

UX_STEP_NOCB_INIT(ux_ctap2_get_assertion_flow_user_step,
                  bnnn_paging,
                  ctap2_ux_display_user_assertion(),
                  {
                      .title = "User",
                      .text = (char *) verifyHash,
                  });

UX_STEP_CB(ux_ctap2_get_assertion_flow_refuse_step,
           pbb,
           ctap2_get_assertion_user_cancel(),
           {&C_icon_crossmark, "Reject", "login request"});

UX_FLOW(ux_ctap2_get_assertion_flow,
        &ux_ctap2_get_assertion_flow_accept_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_get_assertion_flow_user_step,
        &ux_ctap2_get_assertion_flow_accept_step,
        &ux_ctap2_get_assertion_flow_refuse_step);

// Extra steps and flow if there are multiple credentials
UX_STEP_NOCB(ux_ctap2_get_assertion_multiple_flow_first_step,
             pbb,
             {
                 &C_icon_people,
                 "Log in with",
                 "chosen credential",
             });

UX_STEP_NOCB_INIT(ux_ctap2_get_assertion_multiple_flow_user_step,
                  bnnn_paging,
                  ctap2_ux_display_user_assertion(),
                  {
                      .title = (char *) verifyName,
                      .text = (char *) verifyHash,
                  });

UX_STEP_CB(ux_ctap2_get_assertion_multiple_flow_next_user_step,
           pbb,
           ctap2_ux_multiple_next(),
           {&C_icon_people, "Show next", "credential"});

UX_FLOW(ux_ctap2_get_assertion_multiple_flow,
        &ux_ctap2_get_assertion_multiple_flow_first_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_get_assertion_multiple_flow_user_step,
        &ux_ctap2_get_assertion_multiple_flow_next_user_step,
        &ux_ctap2_get_assertion_flow_accept_step,
        &ux_ctap2_get_assertion_flow_refuse_step);

// Extra steps if a text is associated to the TX for single assertion

UX_STEP_NOCB(ux_ctap2_get_assertion_text_flow_first_step,
             pbn,
             {
                 &C_icon_certificate,
                 "Log in",
                 "with text",
             });

UX_STEP_NOCB(ux_ctap2_get_assertion_text_flow_text_step,
             bnnn_paging,
             {.title = "Message", .text = NULL});

UX_FLOW(ux_ctap2_get_assertion_text_flow,
        &ux_ctap2_get_assertion_text_flow_first_step,
        &ux_ctap2_get_assertion_text_flow_text_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_get_assertion_flow_user_step,
        &ux_ctap2_get_assertion_flow_refuse_step,
        &ux_ctap2_get_assertion_flow_accept_step);

// Extra steps if a text is associated to the TX for multiple assertion
UX_STEP_NOCB(ux_ctap2_get_assertion_multiple_text_flow_first_step,
             pnn,
             {
                 &C_icon_certificate,
                 "Log in with text",
                 "and chosen credential",
             });

UX_FLOW(ux_ctap2_get_assertion_multiple_text_flow,
        &ux_ctap2_get_assertion_multiple_text_flow_first_step,
        &ux_ctap2_get_assertion_text_flow_text_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_get_assertion_multiple_flow_user_step,
        &ux_ctap2_get_assertion_multiple_flow_next_user_step,
        &ux_ctap2_get_assertion_flow_refuse_step,
        &ux_ctap2_get_assertion_flow_accept_step);

// Dedicated flow to get user presence confirmation if no account is registered
UX_STEP_NOCB(ux_ctap2_no_assertion_flow_0_step,
             pnn,
             {
                 &C_icon_warning,
                 "No credential found",
                 "for this domain",
             });

UX_STEP_NOCB_INIT(ux_ctap2_no_assertion_flow_1_step,
                  bnnn_paging,
                  ctap2_ux_display_rp_assertion(),
                  {
                      .title = "Domain",
                      .text = (char *) verifyHash,
                  });

UX_STEP_CB(ux_ctap2_no_assertion_flow_2_step,
           pb,
           ctap2_get_assertion_no_assertion_confirm(),
           {&C_icon_back_x, "Close"});

UX_FLOW(ux_ctap2_no_assertion_flow,
        &ux_ctap2_no_assertion_flow_0_step,
        &ux_ctap2_no_assertion_flow_1_step,
        &ux_ctap2_no_assertion_flow_2_step);

static void get_next_multiple_flow_state(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    ctap2_get_assertion_next_credential_ux_helper();

    snprintf((char *) verifyName,
             sizeof(verifyName),
             "User %d / %d",
             ctap2AssertData->currentCredentialIndex,
             ctap2AssertData->availableCredentials);
}

static void ctap2_ux_multiple_next(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    PRINTF("ctap2_ux_multiple_next\n");
    get_next_multiple_flow_state();
    if (ctap2AssertData->txAuthMessage != NULL) {
        ux_flow_init(0,
                     ux_ctap2_get_assertion_multiple_text_flow,
                     &ux_ctap2_get_assertion_multiple_flow_user_step);
    } else {
        ux_flow_init(0,
                     ux_ctap2_get_assertion_multiple_flow,
                     &ux_ctap2_get_assertion_multiple_flow_user_step);
    }
}

void ctap2_get_assertion_ux(ctap2_ux_state_t state) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    if (state == CTAP2_UX_STATE_MULTIPLE_ASSERTION) {
        get_next_multiple_flow_state();
    }

    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2Proxy.uiStarted = true;

    ctap2UxState = state;

    if (ctap2AssertData->txAuthMessage != NULL) {
        ctap2AssertData->txAuthLast = ctap2AssertData->txAuthMessage[ctap2AssertData->txAuthLength];
        ctap2AssertData->txAuthMessage[ctap2AssertData->txAuthLength] = '\0';
        G_ux.externalText = ctap2AssertData->txAuthMessage;
    } else {
        G_ux.externalText = NULL;
    }

    switch (state) {
        case CTAP2_UX_STATE_GET_ASSERTION: {
            if (ctap2AssertData->txAuthMessage != NULL) {
                ux_flow_init(0, ux_ctap2_get_assertion_text_flow, NULL);
            } else {
                ux_flow_init(0, ux_ctap2_get_assertion_flow, NULL);
            }
            break;
        }
        case CTAP2_UX_STATE_MULTIPLE_ASSERTION: {
            if (ctap2AssertData->txAuthMessage != NULL) {
                ux_flow_init(0, ux_ctap2_get_assertion_multiple_text_flow, NULL);
            } else {
                ux_flow_init(0, ux_ctap2_get_assertion_multiple_flow, NULL);
            }
            break;
        }
        default: {
            ux_flow_init(0, ux_ctap2_no_assertion_flow, NULL);
            break;
        }
    }
}
