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

#if defined(HAVE_NBGL)

#include <main_std_app.h>

#include "ux.h"

static void app_quit(void) {
    // exit app here using standard app functionality
    app_exit();
}

#include "config.h"
#include "globals.h"
#include "ui_shared.h"

#include "nbgl_use_case.h"
#include "nbgl_page.h"
#include "nbgl_layout.h"

/*
 * 'Info' / 'Settings' menu
 */

#ifdef ENABLE_RK_CONFIG_UI_SETTING
static uint8_t initSettingPage;
static nbgl_layoutSwitch_t switches[1] = {0};
#endif  // ENABLE_RK_CONFIG_UI_SETTING
static const char *const INFO_TYPES[] = {"Version", "Developer", "Copyright"};
static const char *const INFO_CONTENTS[] = {APPVERSION, "Ledger", "(c) 2022-2025 Ledger"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = 3,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

#ifdef ENABLE_RK_CONFIG_UI_SETTING

static void controls_callback(int token, uint8_t index, int page);

static const nbgl_content_t contents[1] = {{.type = SWITCHES_LIST,
                                            .content.switchesList.nbSwitches = 1,
                                            .content.switchesList.switches = switches,
                                            .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = 1};

static void ui_back_from_menu_choice(void) {
    switches[0].initState = config_get_rk_enabled();
    nbgl_useCaseHomeAndSettings(
        APPNAME,
        &C_icon_security_key_64px,
        "Use this app for two-factor\nauthentication and\npassword-less log ins.",
        initSettingPage,
        &settingContents,
        &infoList,
        NULL,
        app_quit);
}

static void warning_choice(bool accept) {
    if (accept) {
        config_set_rk_enabled(true);
        app_nbgl_status("Resident keys enabled", true, ui_back_from_menu_choice);
    } else {
        ui_back_from_menu_choice();
    }
}

static void controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    initSettingPage = page;
    if (token == FIRST_USER_TOKEN) {
        if (config_get_rk_enabled()) {
            config_set_rk_enabled(false);
        } else {
            nbgl_useCaseChoice(&C_Warning_64px,
                               "Enable resident keys?",
                               "Updating the OS or this app\n"
                               "will delete login info stored on\n"
                               "this device, causing login\n"
                               "issues.",
                               "Enable",
                               "Cancel",
                               warning_choice);
        }
    }
    switches[0].initState = config_get_rk_enabled();
}
#endif  // ENABLE_RK_CONFIG_UI_SETTING

/*
 * When no NFC, warning status page
 */

#if defined(TARGET_STAX) && (API_LEVEL <= 15 && API_LEVEL != 0)
#define C_Info_32px C_info_i_32px
#endif  // defined(TARGET_STAX) && API_LEVEL <= 15

static const nbgl_pageInfoDescription_t nfc_info = {
    .centeredInfo.icon = &INFO_I_ICON,
    .centeredInfo.text1 = "Use NFC to log in with a single tap",
    .centeredInfo.text3 =
        "Quit this app and go to device settings, then enable NFC.\n"
        "Make sure your mobile phone also has NFC enabled.",
    .tapActionText = "Tap to dismiss",
};

static void no_NFC_callback(int token __attribute__((unused)),
                            uint8_t index __attribute__((unused))) {
    ui_idle();
}

static void no_NFC_info_page(void) {
    nbgl_pageDrawInfo(no_NFC_callback, NULL, &nfc_info);
    nbgl_refreshSpecial(FULL_COLOR_CLEAN_REFRESH);
}

static nbgl_homeAction_t homeNoNFCWarning = {};

/*
 * Home page
 */

void ui_idle(void) {
    nbgl_homeAction_t *home_button = NULL;

#ifdef HAVE_NFC
    bool nfc_enabled;
    nfc_enabled = os_setting_get(OS_SETTING_FEATURES, NULL, 0) & OS_SETTING_FEATURES_NFC_ENABLED;
    if (!nfc_enabled) {
        homeNoNFCWarning.text = "NFC is disabled";
        // TODO: currently the .icon is ignored in the SDK
        homeNoNFCWarning.icon = &INFO_I_ICON;
        homeNoNFCWarning.callback = no_NFC_info_page;
        home_button = &homeNoNFCWarning;
    }
#endif  // ENABLE_NFC

#ifdef ENABLE_RK_CONFIG_UI_SETTING
    switches[0].text = "Resident keys";
    switches[0].subText =
        "Stores login info on this\n"
        "device's memory and lets you\n"
        "login without username.\n"
        "\n"
        "Caution: Updating the OS or\n"
        "this app will delete the stored\n"
        "login info, causing login issues\n"
        "for connected accounts.";
    switches[0].token = FIRST_USER_TOKEN;
    switches[0].tuneId = TUNE_TAP_CASUAL;
    switches[0].initState = config_get_rk_enabled();
#endif  //  ENABLE_RK_CONFIG_UI_SETTING
    nbgl_useCaseHomeAndSettings(
        APPNAME,
        &C_icon_security_key_64px,
        "Use this app for two-factor\nauthentication and\npassword-less log ins.",
        INIT_HOME_PAGE,
#ifdef ENABLE_RK_CONFIG_UI_SETTING
        &settingContents,
#else
        NULL,
#endif  // ENABLE_RK_CONFIG_UI_SETTING
        &infoList,
        home_button,
        app_quit);
}

/*
 * Generic reviews (register, authenticate)
 */

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
    // only NBGL screens has such needs
    globals_truncate_pairs_for_display(true);

    nbgl_layoutDescription_t layoutDescription;
    onChoice = on_choice;
    onSelect = on_select;

    layoutDescription.modal = false;
    layoutDescription.withLeftBorder = true;
    layoutDescription.onActionCallback = onActionCallback;
    layoutDescription.tapActionText = NULL;
    layoutDescription.ticker.tickerCallback = NULL;

    layout = nbgl_layoutGet(&layoutDescription);

    nbgl_layoutHeader_t bar;
    bar.type = HEADER_TITLE;
    bar.separationLine = true;
    bar.title.text = APPNAME;
    nbgl_layoutAddHeader(layout, &bar);

    const nbgl_contentTagValueList_t tagValueList = {.nbPairs = nb_pairs,
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

void app_nbgl_status(const char *message, bool is_success, nbgl_callback_t on_quit) {
    if (g.is_nfc && is_success) {
        // Truncate display buffers for small police (hence `false`) then format them into the
        // display buffer (which is then used in `centeredInfo.text3`)
        globals_truncate_pairs_for_display(false);
        globals_prepare_displayed_message(false);
    } else {
        globals_prepare_displayed_message(true);
    }

    if (is_success == true) {
        io_seproxyhal_play_tune(TUNE_SUCCESS);
    }

    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &tickerCallback,
        .tickerIntervale = 0,  // not periodic
        .tickerValue = 3000    // 3 seconds
    };
    onQuit = on_quit;
    PRINTF("Will be displayed: '%s'\n", g.displayed_message);
    nbgl_pageInfoDescription_t info = {
        .bottomButtonStyle = NO_BUTTON_STYLE,
        .footerText = NULL,
        .centeredInfo.icon = &C_Denied_Circle_64px,
        .centeredInfo.offsetY = 0,
        .centeredInfo.onTop = false,
        .centeredInfo.style = LARGE_CASE_INFO,
        .centeredInfo.text1 = message,
        .centeredInfo.text2 = NULL,
        /* .centeredInfo.text3 = NULL, */
        .centeredInfo.text3 = g.displayed_message[0] == 0 ? NULL : &g.displayed_message[0],
        .tapActionText = NULL,
        .tapActionToken = QUIT_TOKEN,
        .topRightStyle = NO_BUTTON_STYLE,
        .actionButtonText = NULL,
        .tuneId = TUNE_TAP_CASUAL,
    };

    if (is_success) {
        info.centeredInfo.icon = &C_Check_Circle_64px;
    } else {
        info.centeredInfo.icon = &C_Important_Circle_64px;
    }

    pageContext = nbgl_pageDrawInfo(&onActionCallback, &ticker, &info);

    nbgl_refresh();
}

#endif
