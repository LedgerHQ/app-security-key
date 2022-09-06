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

#include "client_pin_ui.h"
#include "client_pin_utils.h"



static void ux_display_perms(void) {
    ctap2_pin_data_t *ctap2PinData = get_ctap2_pin_data();
    int offset = 0;

    PRINTF("ctap2_ux_display_perms\n");

    if (ctap2PinData->perms & AUTH_TOKEN_PERM_MAKE_CREDENTIAL) {
        offset += snprintf(g.buffer1_65 + offset, sizeof(g.buffer1_65) - offset, "%s", "register, ");
    }
    if (ctap2PinData->perms & AUTH_TOKEN_PERM_GET_ASSERTION) {
        offset += snprintf(g.buffer1_65 + offset, sizeof(g.buffer1_65) - offset, "%s", "login, ");
    }
    if (ctap2PinData->perms & AUTH_TOKEN_PERM_CREDENTIAL_MGMT) {
        offset +=
            snprintf(g.buffer1_65 + offset, sizeof(g.buffer1_65) - offset, "%s", "manage creds, ");
    }
    if (ctap2PinData->perms & AUTH_TOKEN_PERM_LARGE_BLOB_wRITE) {
        offset += snprintf(g.buffer1_65 + offset, sizeof(g.buffer1_65) - offset, "%s", "write blobs, ");
    }

    if (offset > 2) {
        // Remove the last ','
        g.buffer1_65[offset - 2] = '\0';
    }
    PRINTF("PERMS: %s\n", g.buffer1_65);
}

static void ctap2_ux_display_rp(void) {
    ctap2_pin_data_t *ctap2PinData = get_ctap2_pin_data();

    PRINTF("ctap2_ux_display_rp\n");

    if (ctap2PinData->rpId != NULL) {
        ctap2_display_copy_rp(ctap2PinData->rpId, ctap2PinData->rpIdLen);
    } else {
        strcpy(g.buffer1_65, "All");
    }
}

#if defined(HAVE_BAGL)

UX_STEP_CB(ux_ctap2_get_token_flow_0_step,
           pbb,
           confirm_client_pin_get_token(),
           {
               &C_icon_validate_14,
               "Grant permissions",
               "FIDO 2",
           });

UX_STEP_NOCB_INIT(ux_ctap2_get_token_flow_1_step,
                  bnnn_paging,
                  ux_display_perms(),
                  {
                      .title = "Permissions",
                      .text = (char *) g.buffer1_65,
                  });

UX_STEP_NOCB_INIT(ux_ctap2_get_token_flow_2_step,
                  bnnn_paging,
                  ctap2_ux_display_rp(),
                  {
                      .title = "Domain",
                      .text = (char *) g.buffer1_65,
                  });

UX_STEP_CB(ux_ctap2_get_token_flow_3_step,
           pbb,
           user_cancel_client_pin_get_token(),
           {
               &C_icon_crossmark,
               "Refuse",
               "permissions",
           });

UX_FLOW(ux_ctap2_get_token_flow,
        &ux_ctap2_get_token_flow_0_step,
        &ux_ctap2_get_token_flow_1_step,
        &ux_ctap2_get_token_flow_2_step,
        &ux_ctap2_get_token_flow_3_step,
        FLOW_LOOP);

void ux_client_pin_get_token(void) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ctap2UxState = CTAP2_UX_STATE_CLIENT_PIN;

    G_ux.externalText = NULL;
    ux_flow_init(0, ux_ctap2_get_token_flow, NULL);
}

#elif defined(HAVE_NBGL)

void ux_client_pin_get_token(void) {}

#endif
