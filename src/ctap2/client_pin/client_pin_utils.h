/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2023 Ledger
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

#include "globals.h"

#define TAG_RESP_KEY_AGREEMENT 0x01
#define TAG_RESP_PIN_TOKEN     0x02
#define TAG_RESP_PIN_RETRIES   0x03
#define TAG_RESP_UV_RETRIES    0x05

typedef struct auth_token_s {
    uint8_t value[AUTH_TOKEN_SIZE];
    uint8_t protocol;
    uint8_t perms;
    uint8_t rpIdHash[CX_SHA256_SIZE];
} auth_token_t;

extern auth_token_t authToken;

bool is_token_valid(void);
void stopUsingPinUvAuthToken(void);
void user_cancel_client_pin_get_token(void);
void confirm_client_pin_get_token(void);

static inline ctap2_pin_data_t *get_ctap2_pin_data(void) {
    return &shared_ctx.u.ctap2Data.u.ctap2PinData;
}
