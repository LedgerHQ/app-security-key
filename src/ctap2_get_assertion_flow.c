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

static void ctap2_ux_display_user_assertion(void) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    credential_data_t credData;

    uint8_t nameLength = 0;

    // TODO show that user.id is truncated if necessary
    if (credential_decode(&credData,
                          ctap2AssertData->credential,
                          ctap2AssertData->credentialLen,
                          true) != 0) {
        // This should never happen, but keep a consistent state if it ever does
        verifyHash[0] = '\0';
    } else if (credData.userStr != NULL) {
        nameLength = MIN(credData.userStrLen, sizeof(verifyHash) - 1);
        memcpy(verifyHash, credData.userStr, nameLength);
        verifyHash[nameLength] = '\0';
    } else {
        snprintf(verifyHash, sizeof(verifyHash), "%.*H", credData.userIdLen, credData.userId);
        verifyHash[sizeof(verifyHash) - 1] = '\0';
        nameLength = MIN(credData.userIdLen * 2, sizeof(verifyHash) - 1);
    }

    if (nameLength > 32) {
        memcpy(verifyHash + 32, "...", sizeof("..."));
    }

    PRINTF("name %s\n", verifyHash);
}

#if defined(HAVE_BAGL)

UX_STEP_NOCB(ux_ctap2_get_assertion_flow_first_step,
             pnn,
             {
                 &C_icon_security_key,
                 "Review login",
                 "request",
             });

UX_STEP_NOCB(ux_ctap2_get_assertion_flow_domain_step,
             bnnn_paging,
             {
                 .title = "Website",
                 .text = (char *) rpID,
             });

UX_STEP_NOCB(ux_ctap2_get_assertion_flow_user_step,
             bnnn_paging,
             {
                 .title = "User ID",
                 .text = (char *) verifyHash,
             });

UX_STEP_CB(ux_ctap2_get_assertion_flow_accept_step,
           pb,
           ctap2_get_assertion_confirm(1),
           {&C_icon_validate_14, "Log in"});

UX_STEP_CB(ux_ctap2_get_assertion_flow_refuse_step,
           pbb,
           ctap2_get_assertion_user_cancel(),
           {&C_icon_crossmark, "Reject", "login request"});

UX_FLOW(ux_ctap2_get_assertion_flow,
        &ux_ctap2_get_assertion_flow_first_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_get_assertion_flow_user_step,
        &ux_ctap2_get_assertion_flow_accept_step,
        &ux_ctap2_get_assertion_flow_refuse_step);

// Extra steps and flow if there are multiple credentials
UX_STEP_NOCB(ux_ctap2_get_assertion_multiple_flow_first_step,
             pnn,
             {
                 &C_icon_security_key,
                 "Select user ID",
                 "to log in",
             });

// display stepped screens
static unsigned int ux_step;
static unsigned int ux_step_count;

#define STATE_LEFT_BORDER  0
#define STATE_VARIABLE     1
#define STATE_RIGHT_BORDER 2

static void display_next_multiple_flow_state(uint16_t idx) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();
    ctap2_get_assertion_credential_idx(idx);

    snprintf((char *) verifyName,
             sizeof(verifyName),
             "Log in user %d/%d",
             ctap2AssertData->currentCredentialIndex,
             ctap2AssertData->availableCredentials);
    ctap2_ux_display_user_assertion();
}

static void display_next_state(uint8_t state) {
    if (state == STATE_LEFT_BORDER) {
        if (ux_step == 0) {
            ux_step = 1;
            ux_flow_next();
        } else if (ux_step == 1) {
            --ux_step;
            ux_flow_prev();
        } else if (ux_step > 1) {
            --ux_step;
            ux_flow_next();
        }
    } else if (state == STATE_VARIABLE) {
        display_next_multiple_flow_state(ux_step);
    } else if (state == STATE_RIGHT_BORDER) {
        if (ux_step < ux_step_count) {
            ++ux_step;
            ux_flow_prev();
        } else if (ux_step == ux_step_count) {
            ++ux_step;
            ux_flow_next();
        } else if (ux_step > ux_step_count) {
            ux_step = ux_step_count;
            ux_flow_prev();
        }
    }
}

UX_STEP_INIT(ux_ctap2_get_assertion_multiple_left_border, NULL, NULL, {
    display_next_state(STATE_LEFT_BORDER);
});

UX_STEP_CB_INIT(ux_ctap2_get_assertion_multiple_user_border,
                bnnn_paging,
                { display_next_state(STATE_VARIABLE); },
                ctap2_get_assertion_confirm(ux_step),
                {
                    .title = verifyName,
                    .text = verifyHash,
                });

UX_STEP_INIT(ux_ctap2_get_assertion_multiple_right_border, NULL, NULL, {
    display_next_state(STATE_RIGHT_BORDER);
});

UX_FLOW(ux_ctap2_get_assertion_multiple_flow,
        &ux_ctap2_get_assertion_multiple_flow_first_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_get_assertion_multiple_left_border,
        &ux_ctap2_get_assertion_multiple_user_border,
        &ux_ctap2_get_assertion_multiple_right_border,
        &ux_ctap2_get_assertion_flow_refuse_step);

// Dedicated flow to get user presence confirmation if no account is registered
UX_STEP_NOCB(ux_ctap2_no_assertion_flow_0_step,
             pnn,
             {
                 &C_icon_warning,
                 "Login details not",
                 "found",
             });

UX_STEP_NOCB(ux_ctap2_no_assertion_flow_1_step,
             nnn,
             {
                 "Log in using the",
                 "same Ledger you",
                 "register with.",
             });

UX_STEP_CB(ux_ctap2_no_assertion_flow_3_step,
           pb,
           ctap2_get_assertion_confirm(0),
           {&C_icon_back_x, "Close"});

UX_FLOW(ux_ctap2_no_assertion_flow,
        &ux_ctap2_no_assertion_flow_0_step,
        &ux_ctap2_no_assertion_flow_1_step,
        &ux_ctap2_get_assertion_flow_domain_step,
        &ux_ctap2_no_assertion_flow_3_step);

#endif

void ctap2_get_assertion_ux(ctap2_ux_state_t state) {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    // TODO show that rp.id is truncated if necessary
    uint8_t len = MIN(sizeof(rpID) - 1, ctap2AssertData->rpIdLen);
    memcpy(rpID, ctap2AssertData->rpId, len);
    rpID[len] = '\0';
    PRINTF("rpId %s\n", rpID);

    ctap2_ux_display_user_assertion();

    ctap2UxState = state;

#if defined(HAVE_BAGL)

    ux_step = 0;
    ux_step_count = ctap2AssertData->availableCredentials;

    switch (state) {
        case CTAP2_UX_STATE_GET_ASSERTION: {
            ux_flow_init(0, ux_ctap2_get_assertion_flow, NULL);
            break;
        }
        case CTAP2_UX_STATE_MULTIPLE_ASSERTION: {
            ux_flow_init(0, ux_ctap2_get_assertion_multiple_flow, NULL);
            break;
        }
        default: {
            ux_flow_init(0, ux_ctap2_no_assertion_flow, NULL);
            break;
        }
    }
#endif
}
