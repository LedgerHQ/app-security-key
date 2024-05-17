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

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include "u2f_service.h"

#include "credential.h"
#include "u2f_process.h"
#include "ctap2.h"

extern char verifyHash[65];
extern char verifyName[20];
extern char rpID[65];

extern u2f_service_t G_io_u2f;

#ifdef TARGET_NANOS
// Spare RAM on Nanos
#define responseBuffer G_io_apdu_buffer
#else
extern uint8_t responseBuffer[IO_APDU_BUFFER_SIZE];
#endif

typedef struct ctap2_data_t {
    union ctap2_data_u {
        ctap2_register_data_t ctap2RegisterData;
        ctap2_assert_data_t ctap2AssertData;
    } u;
} ctap2_data_t;

typedef struct shared_ctx_s {
    union shared_ctx_u {
        u2f_data_t u2fData;
        ctap2_data_t ctap2Data;
    } u;
    uint8_t sharedBuffer[500];
} shared_ctx_t;

extern shared_ctx_t shared_ctx;
extern ctap2_ux_state_t ctap2UxState;

static inline u2f_data_t *globals_get_u2f_data(void) {
    return &shared_ctx.u.u2fData;
}

static inline ctap2_data_t *globals_get_ctap2_data(void) {
    return &shared_ctx.u.ctap2Data;
}

static inline ctap2_register_data_t *globals_get_ctap2_register_data(void) {
    return &shared_ctx.u.ctap2Data.u.ctap2RegisterData;
}

static inline ctap2_assert_data_t *globals_get_ctap2_assert_data(void) {
    return &shared_ctx.u.ctap2Data.u.ctap2AssertData;
}

#endif
