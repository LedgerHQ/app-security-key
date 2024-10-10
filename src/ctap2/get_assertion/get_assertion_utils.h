/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2024 Ledger
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

#pragma once

#include "cbip_helper.h"

#define TAG_RP_ID            0x01
#define TAG_CLIENT_DATA_HASH 0x02
#define TAG_ALLOWLIST        0x03
#define TAG_EXTENSIONS       0x04
#define TAG_OPTIONS          0x05
#define TAG_PIN_AUTH         0x06
#define TAG_PIN_PROTOCOL     0x07

void get_assertion_confirm(uint16_t idx);
void get_assertion_credential_idx(uint16_t idx);
void get_assertion_user_cancel();

int handle_getAssert_allowList_item(cbipDecoder_t *decoder, cbipItem_t *item, bool unwrap);
