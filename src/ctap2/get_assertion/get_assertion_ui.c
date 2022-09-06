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

#include "credential.h"
#include "globals.h"
#include "ui_shared.h"

#include "get_assertion_ui.h"
#include "get_assertion_utils.h"

#define SELECT_ID_BUFFER_SIZE 36

static void ux_display_user_assertion(char buffer[static SELECT_ID_BUFFER_SIZE]) {
    uint8_t nameLength = load_user_in_buffer(buffer, SELECT_ID_BUFFER_SIZE);

#if defined(HAVE_BAGL)
    if (nameLength > 32) {
        memcpy(buffer + 32, "...", sizeof("..."));
    }
#else
    UNUSED(nameLength);
#endif  // HAVE_BAGL
}

static void ctap_ux_on_user_choice(bool confirm, uint16_t idx) {
    ctap2UxState = CTAP2_UX_STATE_NONE;

    if (confirm) {
        // As the choice is made authenticator-side, according to the spec SK should not let the
        // client being aware of additional credentials. This will prevent the client to call
        // getNextAssertion to discover more credentials.
        globals_get_ctap2_assert_data()->numberOfCredentials =
            MIN(globals_get_ctap2_assert_data()->numberOfCredentials, 1);
        get_assertion_confirm(idx);
#ifdef HAVE_NBGL
        app_nbgl_status("Login request signed", true, ui_idle);
#else
        ui_idle();
#endif
    } else {
        get_assertion_user_cancel();
#ifdef HAVE_NBGL
        app_nbgl_status("Login cancelled", false, ui_idle);
#else
        ui_idle();
#endif
    }
}

#if defined(HAVE_BAGL)

UX_STEP_NOCB(ux_get_assertion_flow_first_step,
             pnn,
             {
                 &C_icon_security_key,
                 "Review login",
                 "request",
             });

UX_STEP_NOCB(ux_get_assertion_flow_domain_step,
             bnnn_paging,
             {
                 .title = "Website",
                 .text = (char *) g.buffer1_65,
             });

UX_STEP_NOCB(ux_get_assertion_flow_user_step,
             bnnn_paging,
             {
                 .title = "User ID",
                 .text = (char *) g.buffer2_65,
             });

UX_STEP_CB(ux_get_assertion_flow_accept_step,
           pb,
           ctap_ux_on_user_choice(true, 1),
           {&C_icon_validate_14, "Log in"});

UX_STEP_CB(ux_get_assertion_flow_refuse_step,
           pbb,
           ctap_ux_on_user_choice(false, 0),
           {&C_icon_crossmark, "Reject", "login request"});

UX_FLOW(ux_get_assertion_flow,
        &ux_get_assertion_flow_first_step,
        &ux_get_assertion_flow_domain_step,
        &ux_get_assertion_flow_user_step,
        &ux_get_assertion_flow_accept_step,
        &ux_get_assertion_flow_refuse_step);

// Extra steps and flow if there are multiple credentials
UX_STEP_NOCB(ux_get_assertion_multiple_flow_first_step,
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
    get_assertion_credential_idx(idx);

    snprintf((char *) g.buffer_20,
             sizeof(g.buffer_20),
             // Max number will be 999: 'Log in user 999/999\n' -> 20 char.
             // As the parameters are uint16_t, this could overflow, but it is very unlikely
             "Log in user %d/%d",
             ctap2AssertData->currentCredentialIndex,
             ctap2AssertData->numberOfCredentials);
    ux_display_user_assertion(g.buffer2_65);
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

UX_STEP_INIT(ux_get_assertion_multiple_left_border, NULL, NULL, {
    display_next_state(STATE_LEFT_BORDER);
});

#ifndef TARGET_NANOS
UX_STEP_CB_INIT(ux_get_assertion_multiple_user_border,
                bnnn_paging,
                { display_next_state(STATE_VARIABLE); },
                ctap_ux_on_user_choice(true, ux_step),
                {
                    .title = g.buffer_20,
                    .text = g.buffer2_65,
                });
#else
UX_STEP_CB_INIT(ux_get_assertion_multiple_user_border,
                bn,
                { display_next_state(STATE_VARIABLE); },
                ctap_ux_on_user_choice(true, ux_step),
                {
                    g.buffer_20,
                    g.buffer2_65,
                });
#endif

UX_STEP_INIT(ux_get_assertion_multiple_right_border, NULL, NULL, {
    display_next_state(STATE_RIGHT_BORDER);
});

UX_FLOW(ux_get_assertion_multiple_flow,
        &ux_get_assertion_multiple_flow_first_step,
        &ux_get_assertion_flow_domain_step,
        &ux_get_assertion_multiple_left_border,
        &ux_get_assertion_multiple_user_border,
        &ux_get_assertion_multiple_right_border,
        &ux_get_assertion_flow_refuse_step);

// Dedicated flow to get user presence confirmation if no account is registered

#ifndef TARGET_NANOS
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
#else
UX_STEP_NOCB(ux_ctap2_no_assertion_flow_0_step,
             pnn,
             {
                 &C_icon_warning,
                 "Login details",
                 "not found",
             });

UX_STEP_NOCB(ux_ctap2_no_assertion_flow_1_step,
             nn,
             {
                 "Use the same Ledger",
                 "you register with.",
             });
#endif

UX_STEP_CB(ux_ctap2_no_assertion_flow_3_step,
           pb,
           ctap_ux_on_user_choice(true, 0),
           {&C_icon_back_x, "Close"});

UX_FLOW(ux_ctap2_no_assertion_flow,
        &ux_ctap2_no_assertion_flow_0_step,
        &ux_ctap2_no_assertion_flow_1_step,
        &ux_get_assertion_flow_domain_step,
        &ux_ctap2_no_assertion_flow_3_step);

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"
#include "nbgl_layout.h"

static nbgl_page_t *pageContext;
#define NB_OF_PAIRS 2
static const nbgl_layoutTagValue_t pairs[NB_OF_PAIRS] = {
    {.item = "Website", .value = g.buffer1_65},
    {.item = "User ID", .value = g.buffer2_65}};

#if defined(TARGET_STAX)
#define SELECT_MAX_ID_NB 5
#elif defined(TARGET_FLEX)
#define SELECT_MAX_ID_NB 4
#endif

static char user_id_list[SELECT_MAX_ID_NB][SELECT_ID_BUFFER_SIZE];
static const char *const bar_texts[SELECT_MAX_ID_NB] = {
    user_id_list[0],
    user_id_list[1],
    user_id_list[2],
    user_id_list[3],
#if defined(TARGET_STAX)
    user_id_list[4],
#endif  // TARGET_STAX
};
static uint8_t token_list[SELECT_MAX_ID_NB];
uint16_t available_credentials;
uint16_t selected_credential;

static void on_user_choice(bool confirm) {
    ctap_ux_on_user_choice(confirm, selected_credential);
}

static void on_user_select(void);

static void on_user_select_exit() {
    // Relauch without changing previously shown user id
    get_assertion_credential_idx(selected_credential);
    app_nbgl_start_review(NB_OF_PAIRS, pairs, "Log in", on_user_choice, on_user_select);
}

static bool on_user_select_navigation_callback(uint8_t page, nbgl_pageContent_t *content) {
    if (page > available_credentials / SELECT_MAX_ID_NB) {
        return false;
    }
    int first_page_index = page * SELECT_MAX_ID_NB + 1;
    int i = 0;
    while ((i < SELECT_MAX_ID_NB) && ((i + first_page_index) <= available_credentials)) {
        get_assertion_credential_idx(first_page_index + i);
        ux_display_user_assertion(user_id_list[i]);
        token_list[i] = FIRST_USER_TOKEN + first_page_index + i;
        i++;
    }
    content->tuneId = NBGL_NO_TUNE;
    content->type = BARS_LIST;
    content->barsList.barTexts = bar_texts;
    content->barsList.tokens = token_list;
    content->barsList.nbBars = i;
    content->barsList.tuneId = TUNE_TAP_CASUAL;
    return true;
}

static void on_user_select_callback(int token, uint8_t index) {
    UNUSED(index);

    if (token <= FIRST_USER_TOKEN) {
        PRINTF("Should not happen!");
        return;
    }

    int idx = token - FIRST_USER_TOKEN;
    if (idx > available_credentials) {
        PRINTF("Should not happen!");
        return;
    }

    PRINTF("User selected %d\n", idx);

    // change the current credential idx and relaunch the review
    selected_credential = idx;
    get_assertion_credential_idx(selected_credential);
    ux_display_user_assertion(g.buffer2_65);
    app_nbgl_start_review(NB_OF_PAIRS, pairs, "Log in", on_user_choice, on_user_select);
}

static void on_user_select(void) {
    // Reuse useCaseSettings which fit our needs
    nbgl_useCaseNavigableContent("User IDs",
                                 0,
                                 (available_credentials - 1) / SELECT_MAX_ID_NB + 1,
                                 on_user_select_exit,
                                 on_user_select_navigation_callback,
                                 on_user_select_callback);
}

static void on_no_assertion_user_choice(int token, uint8_t index) {
    UNUSED(token);
    UNUSED(index);

    nbgl_pageRelease(pageContext);

    ctap2UxState = CTAP2_UX_STATE_NONE;

    get_assertion_confirm(0);
    ui_idle();
}

static void app_nbgl_no_assertion(void) {
    snprintf(g.buffer2_65, sizeof(g.buffer2_65), "Login details not found\nfor %s", g.buffer1_65);
    nbgl_pageInfoDescription_t info = {
        .bottomButtonStyle = NO_BUTTON_STYLE,
        .footerText = NULL,
        .centeredInfo.icon = &C_icon_security_key_64px,
        .centeredInfo.offsetY = 0,
        .centeredInfo.onTop = false,
        .centeredInfo.style = LARGE_CASE_INFO,
        .centeredInfo.text1 = g.buffer2_65,
        .centeredInfo.text2 = "Make sure to log in\nusing the same Ledger\nyou registered with.",
        .centeredInfo.text3 = NULL,
        .tapActionText = "Tap to dismiss",
        .tapActionToken = FIRST_USER_TOKEN,
        .topRightStyle = NO_BUTTON_STYLE,
        .actionButtonText = NULL,
        .tuneId = TUNE_TAP_CASUAL};

    pageContext = nbgl_pageDrawInfo(&on_no_assertion_user_choice, NULL, &info);
    nbgl_refresh();
}

#endif

void get_assertion_ux() {
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    // TODO show that rp.id is truncated if necessary
    uint8_t len = MIN(sizeof(g.buffer1_65) - 1, ctap2AssertData->rpIdLen);
    memcpy(g.buffer1_65, ctap2AssertData->rpId, len);
    g.buffer1_65[len] = '\0';
    PRINTF("GET_ASSERTION: rpId %s\n", g.buffer1_65);

    UX_WAKE_UP();

#if defined(HAVE_BAGL)
    ux_step = 0;
#elif defined(HAVE_NBGL)
    selected_credential = 1;
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif
    if (ctap2AssertData->numberOfCredentials == 0) {
        // No credential possible
#if defined(HAVE_BAGL)
        ux_flow_init(0, ux_ctap2_no_assertion_flow, NULL);
#elif defined(HAVE_NBGL)
        app_nbgl_no_assertion();
#endif
    } else if (ctap2AssertData->numberOfCredentials == 1) {
        ctap2UxState = CTAP2_UX_STATE_GET_ASSERTION;
        ux_display_user_assertion(g.buffer2_65);
        PRINTF("GET_ASSERTION: buffer2_65 %s\n", g.buffer2_65);
#if defined(HAVE_BAGL)
        ux_flow_init(0, ux_get_assertion_flow, NULL);
#elif defined(HAVE_NBGL)
        app_nbgl_start_review(NB_OF_PAIRS, pairs, "Log in", on_user_choice, NULL);
#endif
    } else {
        // Multiple credentials possible
        ctap2UxState = CTAP2_UX_STATE_MULTIPLE_ASSERTION;
#if defined(HAVE_BAGL)
        ux_step_count = ctap2AssertData->numberOfCredentials;
        ux_flow_init(0, ux_get_assertion_multiple_flow, NULL);
#elif defined(HAVE_NBGL)
        available_credentials = ctap2AssertData->numberOfCredentials;
        // Pre-filling the first selected credential
        // If the user wants to use another one, it will be changed in `on_user_select_callback`
        get_assertion_credential_idx(selected_credential);
        ux_display_user_assertion(g.buffer2_65);
        PRINTF("GET_ASSERTION: buffer2_65 %s\n", g.buffer2_65);
        app_nbgl_start_review(NB_OF_PAIRS, pairs, "Log in", on_user_choice, on_user_select);
#endif
    }
}
