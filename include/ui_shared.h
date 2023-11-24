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

#ifndef __UI_SHARED_H__
#define __UI_SHARED_H__

void ui_idle();

#ifdef HAVE_NBGL

#include "nbgl_use_case.h"
#include "nbgl_layout.h"

void app_nbgl_start_review(uint8_t nb_pairs,
                           const nbgl_layoutTagValue_t *pairs,
                           const char *confirm_text,
                           nbgl_choiceCallback_t on_choice,
                           nbgl_callback_t on_select);

void app_nbgl_status(const char *message,
                     bool is_success,
                     nbgl_callback_t on_quit,
                     tune_index_e tune);
#endif

#endif
