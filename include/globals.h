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

#include <u2f_service.h>

#include "credential.h"
#include "u2f_process.h"
#include "ctap2/make_credential/make_credential_struct.h"
#include "ctap2/get_assertion/get_assertion_struct.h"

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
#define FIDO_INS_REGISTER      0x01
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

#define NAME_BUFFER_SIZE 65

// Helper to detect if CTAP2_CBOR_CMD command is proxyied over U2F_CMD
// - CTAP2 calls that are CTAP2_CMD_CBOR commands:
//   There is a direct call from lib_stusb_impl/u2f_impl.c:u2f_message_complete()
//   to ctap2_handle_cmd_cbor(), hence G_io_app.apdu_state = APDU_IDLE
// - CTAP2 calls that are encapsulated on an APDU over U2F_CMD_MSG command
//   This calls goes through:
//   - lib_stusb_impl/u2f_impl.c:u2f_message_complete()
//   - lib_stusb_impl/u2f_impl.c:u2f_handle_cmd_msg()
//   - ....
//   - src/main.c:sample_main()
//   - src/u2f_processing.c:handleApdu()
//   In this case G_io_app.apdu_state is set to APDU_U2F in
//   lib_stusb_impl/u2f_impl.c:u2f_handle_cmd_msg()
#define CMD_IS_OVER_U2F_CMD        (G_io_app.apdu_state != APDU_IDLE)
#define CMD_IS_OVER_CTAP2_CBOR_CMD (G_io_app.apdu_state == APDU_IDLE)

#define CMD_IS_OVER_U2F_USB (G_io_u2f.media == U2F_MEDIA_USB)

#ifdef HAVE_NFC
#define CMD_IS_OVER_U2F_NFC (G_io_app.apdu_media == IO_APDU_MEDIA_NFC)
void nfc_idle_work2(void);
#else
#define CMD_IS_OVER_U2F_NFC false
#endif

typedef struct global_s {
    char buffer_20[20];
    char buffer1_65[NAME_BUFFER_SIZE];
    char buffer2_65[NAME_BUFFER_SIZE];
    char display_status[131];
    bool is_nfc;
    bool is_getNextAssertion;
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

/*
 * Truncate strings stored in global buffers to fit screen width. Truncation depends on police size:
 * - on classic review screens, the police is larger, argument `large` should be `true` .
 * - on status screens (buffer display when NFC transport is used), the police is smaller, argument
 *   `large` should be `false`.
 */
void truncate_pairs_for_display(bool large);

/*
 * Formats strings stored in global buffers into a single global buffer
 *
 * This functions copies the global buffers `g.buffer1_65` and `g.buffer2_65` into
 * `g.display_status`. This `g.display_status` is used by `app_nbgl_status` to display
 * additional informations (RP name, username, ...).
 * These information are copied only if:
 * - the current transport is NFC
 * - AND `clean_buffer` is `false`.
 * In this case, the formatting is the following: `<g.buffer1_65>\n<g.buffer2_65>`.
 * Else, '\0' is inserted at the beginning of the buffer.
 * The input buffers should have been previously truncated to fit the NBGL page width.
 *
 * @param clean_buffer: always insert a '\0' character at the beginning of the buffer
 */
void prepare_display_status(bool clean_buffer);

void ctap2_display_copy_username(const char *name, uint8_t nameLength);
void ctap2_display_copy_rp(const char *name, uint8_t nameLength);

void ctap2_copy_info_on_buffers(void);
