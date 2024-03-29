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

#include "ux.h"

static void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

#include "config.h"
#include "ui_shared.h"

#if defined(HAVE_BAGL)
#ifdef HAVE_RK_SUPPORT_SETTING

static void display_warning();
static void display_settings();
static void toggle_settings();

UX_STEP_NOCB(ux_settings_enabling_flow_warning_step,
             bn_paging,
             {.title = "Warning",
              .text = "Enabling resident\n"
                      "keys will store login\n"
                      "details on this device.\n"
                      "An OS or app update\n"
                      "will delete those\n"
                      "login details.\n"
                      "This will cause login\n"
                      "issues for your\n"
                      "connected accounts.\n"
                      "Are you sure you\n"
                      "want to enable\n"
                      "resident keys?"});

UX_STEP_CB(ux_settings_warning_flow_cancel_step,
           pb,
           display_settings(),
           {
               &C_icon_crossmark,
               "Cancel",
           });

UX_STEP_CB(ux_settings_enabling_flow_confirm_step,
           pbb,
           toggle_settings(),
           {
               &C_icon_validate_14,
               "Enable",
               "resident keys",
           });

UX_FLOW(ux_settings_enabling_flow,
        &ux_settings_enabling_flow_warning_step,
        &ux_settings_warning_flow_cancel_step,
        &ux_settings_enabling_flow_confirm_step);

static void display_warning() {
    ux_flow_init(0, ux_settings_enabling_flow, NULL);
}

static void toggle_settings() {
    if (config_get_rk_enabled()) {
        config_set_rk_enabled(false);
    } else {
        config_set_rk_enabled(true);
    }
    display_settings();
}

UX_STEP_CB(ux_settings_flow_1_enabled_step, bn, toggle_settings(), {"Resident keys", "Enabled"});

UX_STEP_CB(ux_settings_flow_1_disabled_step, bn, display_warning(), {"Resident keys", "Disabled"});

UX_STEP_CB(ux_settings_flow_2_step,
           pb,
           ui_idle(),
           {
               &C_icon_back_x,
               "Back",
           });

UX_DEF(ux_settings_enabled_flow, &ux_settings_flow_1_enabled_step, &ux_settings_flow_2_step);

UX_DEF(ux_settings_disabled_flow, &ux_settings_flow_1_disabled_step, &ux_settings_flow_2_step);

static void display_settings() {
    if (config_get_rk_enabled()) {
        ux_flow_init(0, ux_settings_enabled_flow, NULL);
    } else {
        ux_flow_init(0, ux_settings_disabled_flow, NULL);
    }
}
#endif  // HAVE_RK_SUPPORT_SETTING

UX_STEP_NOCB(ux_idle_flow_1_step, pn, {&C_icon_security_key, "Security Key"});

#ifndef TARGET_NANOS
UX_STEP_NOCB(ux_idle_flow_2_step,
             nnnn,
             {"Use for two-factor", "authentication and", "password-less", "log ins."});
#else
UX_STEP_NOCB(ux_idle_flow_2_step,
             nn,
             {
                 "Use for 2FA and",
                 "password-less log ins.",
             });
#endif

UX_STEP_NOCB(ux_idle_flow_3_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });

#ifdef HAVE_RK_SUPPORT_SETTING
UX_STEP_VALID(ux_idle_flow_4_step,
              pb,
              display_settings(),
              {
                  &C_icon_coggle,
                  "Settings",
              });
#endif  // HAVE_RK_SUPPORT_SETTING

UX_STEP_CB(ux_idle_flow_5_step,
           pb,
           app_quit(),
           {
               &C_icon_dashboard_x,
               "Quit app",
           });
UX_FLOW(ux_idle_flow,
        &ux_idle_flow_1_step,
        &ux_idle_flow_2_step,
        &ux_idle_flow_3_step,
#ifdef HAVE_RK_SUPPORT_SETTING
        &ux_idle_flow_4_step,
#endif  // HAVE_RK_SUPPORT_SETTING
        &ux_idle_flow_5_step);

void ui_idle(void) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
}

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"
#include "nbgl_page.h"
#include "nbgl_layout.h"

// 'About' menu

static const char *const INFO_TYPES[] = {"Version", "Developer", "Copyright"};
static const char *const INFO_CONTENTS[] = {APPVERSION, "Ledger", "(c) 2023 Ledger"};

#ifdef HAVE_RK_SUPPORT_SETTING

static nbgl_layoutSwitch_t toggle;
static void ui_menu_settings_page(void);

static void warning_choice(bool accept) {
    if (accept) {
        config_set_rk_enabled(true);
        app_nbgl_status("Resident keys enabled", true, ui_menu_settings_page, NBGL_NO_TUNE);
    } else {
        ui_menu_settings_page();
    }
}

static void settings_callback(int token, uint8_t index) {
    UNUSED(index);
    switch (token) {
        case FIRST_USER_TOKEN:
            if (config_get_rk_enabled()) {
                config_set_rk_enabled(false);
            } else {
                nbgl_useCaseChoice(&C_warning64px,
                                   "Enable resident keys?",
                                   "Updating the OS or this app\n"
                                   "will delete login info stored on\n"
                                   "this device, causing login\n"
                                   "issues.",
                                   "Enable",
                                   "Cancel",
                                   warning_choice);
            }
            break;
        default:
            PRINTF("Should not happen!");
            break;
    }
}
#endif  // HAVE_RK_SUPPORT_SETTING

static bool nav_callback(uint8_t page, nbgl_pageContent_t *content) {
    if (page == 0) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = 3;
        content->infosList.infoTypes = INFO_TYPES;
        content->infosList.infoContents = INFO_CONTENTS;
    }
#ifdef HAVE_RK_SUPPORT_SETTING
    else if (page == 1) {
        toggle.text = "Resident keys";
        toggle.subText =
            "Stores login info on this\n"
            "device's memory and lets you\n"
            "login without username.\n\n"
            "Caution: Updating the OS or\n"
            "this app will delete the stored\n"
            "login info, causing login issues\n"
            "for connected accounts";
        toggle.token = FIRST_USER_TOKEN;
        toggle.tuneId = TUNE_TAP_CASUAL;
        toggle.initState = config_get_rk_enabled();
        content->type = SWITCHES_LIST;
        content->switchesList.nbSwitches = 1;
        content->switchesList.switches = &toggle;
    } else {
#endif  // HAVE_RK_SUPPORT_SETTING
        return false;
    }
    return true;
}

static void ui_menu_settings(uint8_t init_page) {
    nbgl_useCaseSettings(APPNAME,
                         init_page,
#ifdef HAVE_RK_SUPPORT_SETTING
                         2,
#else
                         1,
#endif
                         false,
                         ui_idle,
                         nav_callback,
                         settings_callback);
}

static void ui_menu_settings_home(void) {
    ui_menu_settings(0);
}

static void ui_menu_settings_page(void) {
    ui_menu_settings(1);
}

void ui_idle(void) {
    nbgl_useCaseHome(APPNAME,
                     &C_icon_security_key_64px,
                     "Use this app for two-factor\nauthentication and\npassword-less log ins.",
#ifdef HAVE_RK_SUPPORT_SETTING
                     true,
#else
                     false,
#endif
                     ui_menu_settings_home,
                     app_quit);
}

static nbgl_layout_t *layout;
static nbgl_page_t *pageContext;
static nbgl_choiceCallback_t onChoice;
static nbgl_callback_t onSelect;
static nbgl_callback_t onQuit;

enum { TITLE_TOKEN = FIRST_USER_TOKEN, CHOICE_TOKEN, SELECT_TOKEN, QUIT_TOKEN };

static void onActionCallback(int token, uint8_t index) {
    if (token == CHOICE_TOKEN && onChoice != NULL) {
        // Release the review layout.
        nbgl_layoutRelease(layout);

        onChoice(index == 0);
    } else if (token == SELECT_TOKEN && onSelect != NULL) {
        // Release the review layout.
        nbgl_layoutRelease(layout);

        onSelect();
    } else if (token == QUIT_TOKEN && onQuit != NULL) {
        // Release the review layout.
        nbgl_layoutRelease(layout);

        onQuit();
    }
}

void app_nbgl_start_review(uint8_t nb_pairs,
                           const nbgl_layoutTagValue_t *pairs,
                           const char *confirm_text,
                           nbgl_choiceCallback_t on_choice,
                           nbgl_callback_t on_select) {
    nbgl_layoutDescription_t layoutDescription;
    onChoice = on_choice;
    onSelect = on_select;

    layoutDescription.modal = false;
    layoutDescription.withLeftBorder = true;
    layoutDescription.onActionCallback = onActionCallback;
    layoutDescription.tapActionText = NULL;
    layoutDescription.ticker.tickerCallback = NULL;

    layout = nbgl_layoutGet(&layoutDescription);

    nbgl_layoutBar_t bar;
    bar.text = APPNAME;
    bar.subText = NULL;
    bar.iconRight = NULL;
    bar.iconLeft = NULL;
    bar.token = TITLE_TOKEN;
    bar.centered = true;
    bar.inactive = false;
    bar.tuneId = NBGL_NO_TUNE;
    nbgl_layoutAddTouchableBar(layout, &bar);
    nbgl_layoutAddSeparationLine(layout);

    const nbgl_layoutTagValueList_t tagValueList = {.nbPairs = nb_pairs,
                                                    .pairs = pairs,
                                                    .smallCaseForValue = false,
                                                    .nbMaxLinesForValue = 0,
                                                    .wrapping = false};

    nbgl_layoutAddTagValueList(layout, &tagValueList);

    if (onSelect) {
        nbgl_layoutButton_t select_button_info = {.text = "Select another ID",
                                                  .icon = NULL,
                                                  .token = SELECT_TOKEN,
                                                  .style = WHITE_BACKGROUND,
                                                  .fittingContent = true,
                                                  .onBottom = false,
                                                  .tuneId = TUNE_TAP_CASUAL};

        nbgl_layoutAddButton(layout, &select_button_info);
    }

    nbgl_layoutChoiceButtons_t choice_buttons_info = {.bottomText = "Cancel",
                                                      .token = CHOICE_TOKEN,
                                                      .topText = confirm_text,
                                                      .style = ROUNDED_AND_FOOTER_STYLE,
                                                      .tuneId = TUNE_TAP_CASUAL};
    nbgl_layoutAddChoiceButtons(layout, &choice_buttons_info);

    nbgl_layoutDraw(layout);

    nbgl_refresh();
}

static void tickerCallback(void) {
    nbgl_pageRelease(pageContext);
    if (onQuit != NULL) {
        onQuit();
    }
}

void app_nbgl_status(const char *message,
                     bool is_success,
                     nbgl_callback_t on_quit,
                     tune_index_e tune) {
    if (tune != NBGL_NO_TUNE) {
        io_seproxyhal_play_tune(tune);
    }

    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &tickerCallback,
        .tickerIntervale = 0,  // not periodic
        .tickerValue = 3000    // 3 seconds
    };
    onQuit = on_quit;

    nbgl_pageInfoDescription_t info = {.bottomButtonStyle = NO_BUTTON_STYLE,
                                       .footerText = NULL,
                                       .centeredInfo.icon = &C_round_cross_64px,
                                       .centeredInfo.offsetY = 0,
                                       .centeredInfo.onTop = false,
                                       .centeredInfo.style = LARGE_CASE_INFO,
                                       .centeredInfo.text1 = message,
                                       .centeredInfo.text2 = NULL,
                                       .centeredInfo.text3 = NULL,
                                       .tapActionText = "",
                                       .tapActionToken = QUIT_TOKEN,
                                       .topRightStyle = NO_BUTTON_STYLE,
                                       .actionButtonText = NULL,
                                       .tuneId = TUNE_TAP_CASUAL};

    if (is_success) {
        info.centeredInfo.icon = &C_round_check_64px;
    } else {
        info.centeredInfo.icon = &C_round_warning_64px;
    }

    pageContext = nbgl_pageDrawInfo(&onActionCallback, &ticker, &info);

    nbgl_refresh();
}

#endif
