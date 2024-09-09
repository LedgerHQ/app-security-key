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

#pragma once

#include "u2f_service.h"

#include "credential.h"
#include "u2f_process.h"
#include "ctap2.h"

#define U2F_VERSION      "U2F_V2"
#define U2F_VERSION_SIZE (sizeof(U2F_VERSION) - 1)

#define FIDO2_VERSION      "FIDO_2_0"
#define FIDO2_VERSION_SIZE (sizeof(FIDO2_VERSION) - 1)

#define FIDO_AID_SIZE 8
static const uint8_t FIDO_AID[FIDO_AID_SIZE] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1  2
#define OFFSET_P2  3

#define FIDO_CLA               0x00
#define FIDO_INS_ENROLL        0x01
#define FIDO_INS_SIGN          0x02
#define FIDO_INS_GET_VERSION   0x03
#define FIDO_INS_CTAP2_PROXY   0x10
#define FIDO_INS_APPLET_SELECT 0xA4

#define FIDO2_NFC_CLA                 0x80
#define FIDO2_NFC_CHAINING_CLA        0x90
#define FIDO2_NFC_INS_CTAP2_PROXY     0x10
#define FIDO2_NFC_INS_APPLET_DESELECT 0x12

#define P1_U2F_CHECK_IS_REGISTERED    0x07
#define P1_U2F_REQUEST_USER_PRESENCE  0x03
#define P1_U2F_OPTIONAL_USER_PRESENCE 0x08

#define APDU_MIN_HEADER       4
#define LC_FIRST_BYTE_OFFSET  4
#define SHORT_ENC_LC_SIZE     1
#define SHORT_ENC_LE_SIZE     1
#define EXT_ENC_LC_SIZE       3
#define EXT_ENC_LE_SIZE       2  // considering only scenarios where Lc is present
#define SHORT_ENC_DATA_OFFSET 5
#define EXT_ENC_DATA_OFFSET   7

#define SHORT_ENC_DEFAULT_LE \
    253  // Should be 256, stax-rc4 MCU only support 255, so use 253 + 2 for now here
#define EXT_ENC_DEFAULT_LE 65536

typedef struct global_s {
    char verifyHash[65];
    char buffer_20[20];
    char rpID[65];
    char display_status[131];
    bool is_nfc;
} global_t;

extern global_t g;

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

void truncate_pairs_for_display(void);
void prepare_display_status(void);
