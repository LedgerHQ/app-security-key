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

#ifdef HAVE_RK_SUPPORT_SETTING
#include "config.h"
#include "ui_shared.h"

static void display_warning();
static void display_settings();
static void toogle_settings();

UX_STEP_NOCB(ux_settings_enabling_flow_warning_step,
             bn_paging,
             {.title = "Warning",
              .text = "Read carefully\n"
                      "before enabling\n"
                      "resident keys.\n"
                      "If you register\n"
                      "resident keys, they\n"
                      "will be lost whenever\n"
                      "you update this app\n"
                      "or the OS. You are\n"
                      "responsible for\n"
                      "maintaining access\n"
                      "to the services you\n"
                      "register with."});

UX_STEP_NOCB(ux_settings_disabling_flow_warning_step,
             bn_paging,
             {.title = "Warning",
              .text = "Read before\n"
                      "disabling\n"
                      "resident keys."});

UX_STEP_NOCB(ux_settings_disabling_flow_text_1_step,
             nnnn,
             {.line1 = "This app will tell",
              .line2 = "websites that",
              .line3 = "resident keys are not",
              .line4 = "available to use."});

UX_STEP_NOCB(ux_settings_disabling_flow_text_2_step,
             nnn,
             {
                 .line1 = "If they are required,",
                 .line2 = "the Security Key app",
                 .line3 = "won't be compatible.",
             });

UX_STEP_CB(ux_settings_warning_flow_cancel_step,
           pb,
           display_settings(),
           {
               &C_icon_crossmark,
               "Cancel",
           });

UX_STEP_CB(ux_settings_enabling_flow_confirm_step,
           pbb,
           toogle_settings(),
           {
               &C_icon_warning,
               "Enable",
               "resident keys",
           });

UX_STEP_CB(ux_settings_disabling_flow_confirm_step,
           pbb,
           toogle_settings(),
           {
               &C_icon_validate_14,
               "Disable",
               "resident keys",
           });

UX_FLOW(ux_settings_enabling_flow,
        &ux_settings_enabling_flow_warning_step,
        &ux_settings_warning_flow_cancel_step,
        &ux_settings_enabling_flow_confirm_step);

UX_FLOW(ux_settings_disabling_flow,
        &ux_settings_disabling_flow_warning_step,
        &ux_settings_disabling_flow_text_1_step,
        &ux_settings_disabling_flow_text_2_step,
        &ux_settings_disabling_flow_confirm_step,
        &ux_settings_warning_flow_cancel_step);

static void display_warning() {
    if (config_get_rk_enabled()) {
        ux_flow_init(0, ux_settings_disabling_flow, NULL);
    } else {
        ux_flow_init(0, ux_settings_enabling_flow, NULL);
    }
}

static void toogle_settings() {
    if (config_get_rk_enabled()) {
        config_set_rk_enabled(false);
    } else {
        config_set_rk_enabled(true);
    }
    display_settings();
}

UX_STEP_CB(ux_settings_flow_1_enabled_step, bn, display_warning(), {"Resident keys", "Enabled"});

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

UX_STEP_NOCB(ux_idle_flow_1_step,
             nnn,
             {
                 "Security Key",
                 "is ready to",
                 "authenticate",
             });
UX_STEP_NOCB(ux_idle_flow_2_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });

#ifdef HAVE_RK_SUPPORT_SETTING
UX_STEP_VALID(ux_idle_flow_3_step,
              pb,
              display_settings(),
              {
                  &C_icon_coggle,
                  "Settings",
              });
#endif  // HAVE_RK_SUPPORT_SETTING

UX_STEP_CB(ux_idle_flow_4_step,
           pb,
           os_sched_exit(-1),
           {
               &C_icon_dashboard_x,
               "Quit app",
           });
UX_FLOW(ux_idle_flow,
        &ux_idle_flow_1_step,
        &ux_idle_flow_2_step,
#ifdef HAVE_RK_SUPPORT_SETTING
        &ux_idle_flow_3_step,
#endif  // HAVE_RK_SUPPORT_SETTING
        &ux_idle_flow_4_step);

void ui_idle(void) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    G_ux.externalText = NULL;
    ux_flow_init(0, ux_idle_flow, NULL);
}
