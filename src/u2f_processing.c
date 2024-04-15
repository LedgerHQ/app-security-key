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
#include "os_io_seproxyhal.h"
#include "cx.h"
#include "ux.h"
#include "io.h"
#include "format.h"

#include "u2f_processing.h"
#include "u2f_service.h"
#include "u2f_transport.h"
#include "u2f_impl.h"

#include "config.h"
#include "crypto.h"
#include "crypto_data.h"
#include "credential.h"
#include "ui_shared.h"
#include "globals.h"
#include "fido_known_apps.h"
#include "ctap2.h"

#define U2F_VERSION      "U2F_V2"
#define U2F_VERSION_SIZE (sizeof(U2F_VERSION) - 1)

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1  2
#define OFFSET_P2  3

#define FIDO_CLA             0x00
#define FIDO_INS_ENROLL      0x01
#define FIDO_INS_SIGN        0x02
#define FIDO_INS_GET_VERSION 0x03
#define FIDO_INS_CTAP2_PROXY 0x10

#define P1_U2F_CHECK_IS_REGISTERED    0x07
#define P1_U2F_REQUEST_USER_PRESENCE  0x03
#define P1_U2F_OPTIONAL_USER_PRESENCE 0x08

#define SW_NO_ERROR                 0x9000
#define SW_WRONG_LENGTH             0x6700
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA               0x6A80
#define SW_INCORRECT_P1P2           0x6A86
#define SW_INS_NOT_SUPPORTED        0x6D00
#define SW_CLA_NOT_SUPPORTED        0x6E00
#define SW_PROPRIETARY_INTERNAL     0x6FFF

#define U2F_ENROLL_RESERVED 0x05
static const uint8_t DUMMY_ZERO[] = {0x00};
#define SIGN_USER_PRESENCE_MASK 0x01
static const uint8_t DUMMY_USER_PRESENCE[] = {SIGN_USER_PRESENCE_MASK};

#define U2F_ENROLL_USER_KEY_SIZE 65

#define APDU_MIN_HEADER       4
#define LC_FIRST_BYTE_OFFSET  4
#define SHORT_ENC_LC_SIZE     1
#define SHORT_ENC_LE_SIZE     1
#define EXT_ENC_LC_SIZE       3
#define EXT_ENC_LE_SIZE       2  // considering only scenarios where Lc is present
#define SHORT_ENC_DATA_OFFSET 5
#define EXT_ENC_DATA_OFFSET   7

int u2f_get_cmd_msg_data(uint8_t *rx, uint16_t rx_length, uint8_t **data, uint16_t *le) {
    uint32_t data_length;
    /* Parse buffer to retrieve the data length.
       Both Short and Extended encodings are supported */

    // By default, if absent, le == 0
    *le = 0;

    if (rx_length < APDU_MIN_HEADER) {
        return -1;
    }

    if (rx_length == APDU_MIN_HEADER) {
        // Either short or extended encoding with Lc and Le omitted
        return 0;
    }

    if (rx_length == APDU_MIN_HEADER + 1) {
        // Short encoding, with next byte either Le or Lc with the other one omitted
        // There is no way to tell so no way to check the value
        // but anyway the data length is 0

        // Support this particular short encoding APDU as Fido Conformance Tool v1.7.0
        // is using it even though spec requires that short encoding should not be used
        // over HID.
        if (rx[APDU_MIN_HEADER] != 0) {
            *le = rx[APDU_MIN_HEADER];
        }

        return 0;
    }

    if (rx_length == APDU_MIN_HEADER + 2) {
        // Short encoding
        data_length = rx[LC_FIRST_BYTE_OFFSET];
        if (data_length == 0) {
            // next byte is LE
            *le = rx[LC_FIRST_BYTE_OFFSET + 1];
        } else if (data_length == 1) {
            *data = rx + SHORT_ENC_DATA_OFFSET;
        } else {
            return -1;
        }
    }

    if (rx_length == APDU_MIN_HEADER + 3) {
        if (rx[4] != 0) {
            // Short encoding, Lc (1B) and data present, with two next bytes either:
            // - Lc = 0x01, data = 0xyy and Le = 0xzz
            // - Lc = 0x02, data = 0xyyzz and Le is omitted
            data_length = rx[LC_FIRST_BYTE_OFFSET];
            *data = rx + SHORT_ENC_DATA_OFFSET;

            // Ensure that Lc value is consistent and retrieve Le
            if (SHORT_ENC_DATA_OFFSET + data_length == rx_length) {
                /* Lc = 0x02, data = 0xyyzz and Le is omitted*/
            } else if (SHORT_ENC_DATA_OFFSET + data_length + SHORT_ENC_LE_SIZE == rx_length) {
                /* Lc = 0x01, data = 0xyy and Le = 0xzz */
                *le = rx[SHORT_ENC_DATA_OFFSET + data_length];
            } else {
                return -1;
            }
            return data_length;
        } else {
            // Can't be short encoding as Lc = 0x00 would lead to invalid length
            // so extended encoding and either:
            // - Lc = 0x00 0x00 0x00 and Le is omitted
            // - Lc omitted and Le = 0x00 0xyy 0xzz
            // so no way to check the value
            // but anyway the data length is 0
            return 0;
        }
    }

    if (rx[LC_FIRST_BYTE_OFFSET] != 0) {
        // Short encoding, Lc and data present, optionally Le (1B) is present too
        data_length = rx[LC_FIRST_BYTE_OFFSET];
        *data = rx + SHORT_ENC_DATA_OFFSET;

        // Ensure that Lc value is consistent and retrieve Le
        if (SHORT_ENC_DATA_OFFSET + data_length == rx_length) {
            /* Le is omitted*/
        } else if (SHORT_ENC_DATA_OFFSET + data_length + SHORT_ENC_LE_SIZE == rx_length) {
            /* Le is present*/
            *le = rx[SHORT_ENC_DATA_OFFSET + data_length];
        } else {
            return -1;
        }
        return data_length;
    } else {
        // Can't be short encoding as Lc = 0 would lead to invalid length
        // so extended encoding with Lc field present, optionally Le (2B) is present too
        data_length = (rx[LC_FIRST_BYTE_OFFSET + 1] << 8) | (rx[LC_FIRST_BYTE_OFFSET + 2]);
        *data = rx + EXT_ENC_DATA_OFFSET;

        // Ensure that Lc value is consistent and retrieve Le
        if (APDU_MIN_HEADER + EXT_ENC_LC_SIZE + data_length == rx_length) {
            /* Le is omitted*/
        } else if (APDU_MIN_HEADER + EXT_ENC_LC_SIZE + data_length + EXT_ENC_LE_SIZE == rx_length) {
            /* Le is present*/
            *le = (rx[EXT_ENC_DATA_OFFSET + data_length] << 8) +
                  rx[EXT_ENC_DATA_OFFSET + data_length];
        } else {
            return -1;
        }
        return data_length;
    }
}

/******************************************/
/*     U2F message payload structures     */
/******************************************/

/* Registration Request Message
 *
 * +-------------------------+
 * | Challenge | Application |
 * +-------------------------+
 * | 32 bytes  |  32 bytes   |
 * +-------------------------+
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_reg_req_t {
    uint8_t challenge_param[32];
    uint8_t application_param[32];
} u2f_reg_req_t;

/* Registration Response Message: Success
 *
 * +----------+----------+----------------+------------+-------------+-----------*
 * | Reserved | User key | Key handle len | Key handle | Attestation | Signature |
 * +----------+----------+----------------+------------+-------------+-----------*
 * |  1 byte  | 65 bytes |    1 byte      |  L bytes   |             |           |
 * +----------+----------+----------------+------------+-------------+-----------*
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_reg_resp_base_t {
    uint8_t reserved_byte;
    uint8_t user_key[U2F_ENROLL_USER_KEY_SIZE];
    uint8_t key_handle_length;
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];  // We generate fix size key handles
    // attestation certificate: not in this base struct due to not const length
    // signature: not in this base struct due to not const offset nor length
} u2f_reg_resp_base_t;

/* Authentication Request Message
 *
 * +-------------------------+----------------+------------+
 * | Challenge | Application | Key handle len | Key handle |
 * +-------------------------+----------------+------------+
 * | 32 bytes  |  32 bytes   |    1 byte      |  L bytes   |
 * +-------------------------+----------------+------------+
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_auth_req_base_t {
    uint8_t challenge_param[32];
    uint8_t application_param[32];
    uint8_t key_handle_length;
    // key handle: not in this base struct due to not const length
} u2f_auth_req_base_t;

/* Authentication Response Message: Success
 *
 * +---------------+---------+-----------*
 * | User presence | Counter | Signature |
 * +---------------+---------+-----------*
 * |  1 byte       | 4 bytes |           |
 * +---------------+---------+-----------*
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_auth_resp_base_t {
    uint8_t user_presence;
    uint8_t counter[4];
    // signature: not in this base struct due to not const length
} u2f_auth_resp_base_t;

/******************************************/
/*         U2F response helpers           */
/******************************************/

static void u2f_compute_enroll_response_hash(u2f_reg_resp_base_t *reg_resp_base,
                                             uint16_t key_handle_length,
                                             uint8_t *data_hash) {
    cx_sha256_t hash;

    cx_sha256_init(&hash);
    crypto_hash(&hash.header, 0, DUMMY_ZERO, 1, NULL, 0);
    crypto_hash(&hash.header,
                0,
                globals_get_u2f_data()->application_param,
                sizeof(globals_get_u2f_data()->application_param),
                NULL,
                0);
    crypto_hash(&hash.header,
                0,
                globals_get_u2f_data()->challenge_param,
                sizeof(globals_get_u2f_data()->challenge_param),
                NULL,
                0);
    crypto_hash(&hash.header, 0, reg_resp_base->key_handle, key_handle_length, NULL, 0);
    crypto_hash(&hash.header,
                CX_LAST,
                reg_resp_base->user_key,
                sizeof(reg_resp_base->user_key),
                data_hash,
                CX_SHA256_SIZE);
}

static int u2f_generate_pubkey(const uint8_t *nonce,
                               uint8_t user_key[static U2F_ENROLL_USER_KEY_SIZE]) {
    cx_ecfp_private_key_t private_key;

    if (crypto_generate_private_key(nonce, &private_key, CX_CURVE_SECP256R1) != 0) {
        return -1;
    }
    if (crypto_generate_public_key(&private_key, user_key, CX_CURVE_SECP256R1) <= 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return -1;
    }
    explicit_bzero(&private_key, sizeof(private_key));
    return 0;
}

static uint16_t u2f_prepare_enroll_response(uint8_t *buffer, uint16_t *length) {
    int offset = 0;
    int result;
    int key_handle_length;

    *length = 0;

    u2f_reg_resp_base_t *reg_resp_base = (u2f_reg_resp_base_t *) buffer;
    offset += sizeof(u2f_reg_resp_base_t);

    // Fill reserved byte
    reg_resp_base->reserved_byte = U2F_ENROLL_RESERVED;

    {
        // Generate nonce
        cx_rng_no_throw(globals_get_u2f_data()->nonce, CREDENTIAL_NONCE_SIZE);

        // Generate and fill public key
        if (u2f_generate_pubkey(globals_get_u2f_data()->nonce, reg_resp_base->user_key) != 0) {
            return SW_PROPRIETARY_INTERNAL;
        }
    }

    // Generate key handle
    // This also generate nonce needed for public key generation
    key_handle_length = credential_wrap(globals_get_u2f_data()->application_param,
                                        globals_get_u2f_data()->nonce,
                                        NULL,
                                        reg_resp_base->key_handle,
                                        sizeof(reg_resp_base->key_handle),
                                        false,
                                        false);

    // We only support generating key_handle with fixed length
    if (key_handle_length != sizeof(reg_resp_base->key_handle)) {
        return SW_PROPRIETARY_INTERNAL;
    }

    // Fill key handle length
    reg_resp_base->key_handle_length = key_handle_length;

    // Fill attestation certificate
    memmove(buffer + offset, ATTESTATION_CERT, sizeof(ATTESTATION_CERT));
    offset += sizeof(ATTESTATION_CERT);

    // Prepare signature
    uint8_t data_hash[CX_SHA256_SIZE];
    u2f_compute_enroll_response_hash(reg_resp_base, key_handle_length, data_hash);

    // Fill signature
    uint8_t *signature = (buffer + offset);
    result = crypto_sign_attestation(data_hash, signature, false);

    if (result > 0) {
        *length = offset + result;
        return SW_NO_ERROR;
    } else {
        return SW_PROPRIETARY_INTERNAL;
    }
}

static void u2f_compute_sign_response_hash(u2f_auth_resp_base_t *auth_resp_base,
                                           uint8_t *data_hash) {
    cx_sha256_t hash;

    cx_sha256_init(&hash);
    crypto_hash(&hash.header,
                0,
                globals_get_u2f_data()->application_param,
                sizeof(globals_get_u2f_data()->application_param),
                NULL,
                0);
    crypto_hash(&hash.header, 0, DUMMY_USER_PRESENCE, 1, NULL, 0);
    crypto_hash(&hash.header, 0, auth_resp_base->counter, sizeof(auth_resp_base->counter), NULL, 0);
    crypto_hash(&hash.header,
                CX_LAST,
                globals_get_u2f_data()->challenge_param,
                sizeof(globals_get_u2f_data()->challenge_param),
                data_hash,
                CX_SHA256_SIZE);
}

static uint16_t u2f_prepare_sign_response(uint8_t *buffer, uint16_t *length) {
    int offset = 0;
    int result;

    *length = 0;

    u2f_auth_resp_base_t *auth_resp_base = (u2f_auth_resp_base_t *) buffer;
    offset += sizeof(u2f_auth_resp_base_t);

    // Fill user presence byte
    auth_resp_base->user_presence = SIGN_USER_PRESENCE_MASK;

    // Fill counter
    config_increase_and_get_authentification_counter(auth_resp_base->counter);

    // Prepare signature
    uint8_t data_hash[CX_SHA256_SIZE];
    u2f_compute_sign_response_hash(auth_resp_base, data_hash);

    // Generate private key and fill signature
    cx_ecfp_private_key_t private_key;
    uint8_t *signature = (buffer + offset);

    if (crypto_generate_private_key(globals_get_u2f_data()->nonce,
                                    &private_key,
                                    CX_CURVE_SECP256R1) != 0) {
        return SW_PROPRIETARY_INTERNAL;
    }

    result = crypto_sign_application(data_hash, &private_key, signature);

    explicit_bzero(&private_key, sizeof(private_key));

    if (result > 0) {
        offset += result;
        *length = offset;
        return SW_NO_ERROR;
    } else {
        return SW_PROPRIETARY_INTERNAL;
    }
}

static int u2f_process_user_presence_confirmed(void) {
    uint16_t sw = SW_PROPRIETARY_INTERNAL;
    uint16_t length = 0;

    switch (G_io_apdu_buffer[OFFSET_INS]) {
        case FIDO_INS_ENROLL:
            sw = u2f_prepare_enroll_response(G_io_apdu_buffer, &length);
            break;

        case FIDO_INS_SIGN:
            sw = u2f_prepare_sign_response(G_io_apdu_buffer, &length);
            break;

        default:
            break;
    }
    return io_send_response_pointer(G_io_apdu_buffer, length, sw);
}

/******************************************/
/*             U2F UX Flows               */
/******************************************/

#if defined(HAVE_BAGL)

static unsigned int u2f_callback_cancel(void) {
    io_send_sw(SW_PROPRIETARY_INTERNAL);
    ui_idle();
    return 0;
}

static unsigned int u2f_callback_confirm(void) {
    u2f_process_user_presence_confirmed();
    ui_idle();
    return 0;
}

/* Register Flow */
UX_STEP_CB(ux_register_flow_0_step,
           pbb,
           u2f_callback_confirm(),
           {
               &C_icon_validate_14,
               "Register",
               verifyName,
           });
UX_STEP_NOCB(ux_register_flow_1_step,
             bnnn_paging,
             {
                 .title = "Identifier",
                 .text = verifyHash,
             });
UX_STEP_CB(ux_register_flow_2_step,
           pbb,
           u2f_callback_cancel(),
           {
               &C_icon_crossmark,
               "Abort",
               "register",
           });

UX_FLOW(ux_register_flow,
        &ux_register_flow_0_step,
        &ux_register_flow_1_step,
        &ux_register_flow_2_step,
        FLOW_LOOP);

/* Authenticate Flow */
UX_STEP_CB(ux_login_flow_0_step,
           pbb,
           u2f_callback_confirm(),
           {
               &C_icon_validate_14,
               "Login",
               verifyName,
           });
UX_STEP_NOCB(ux_login_flow_1_step,
             bnnn_paging,
             {
                 .title = "Identifier",
                 .text = verifyHash,
             });
UX_STEP_CB(ux_login_flow_2_step,
           pbb,
           u2f_callback_cancel(),
           {
               &C_icon_crossmark,
               "Abort",
               "login",
           });

UX_FLOW(ux_login_flow,
        &ux_login_flow_0_step,
        &ux_login_flow_1_step,
        &ux_login_flow_2_step,
        FLOW_LOOP);

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"

#define NB_OF_PAIRS 2
static const nbgl_layoutTagValue_t pairs[NB_OF_PAIRS] = {{
                                                             .item = "Website",
                                                             .value = verifyName,
                                                         },
                                                         {
                                                             .item = "Website ID",
                                                             .value = verifyHash,
                                                         }};

static void on_register_choice(bool confirm) {
    if (confirm) {
        u2f_process_user_presence_confirmed();
        app_nbgl_status("Registration details\nsent", true, ui_idle, TUNE_SUCCESS);
    } else {
        io_send_sw(SW_PROPRIETARY_INTERNAL);
        app_nbgl_status("Registration cancelled", false, ui_idle, NBGL_NO_TUNE);
    }
}

static void on_login_choice(bool confirm) {
    if (confirm) {
        u2f_process_user_presence_confirmed();
        app_nbgl_status("Login request signed", true, ui_idle, TUNE_SUCCESS);
    } else {
        io_send_sw(SW_PROPRIETARY_INTERNAL);
        app_nbgl_status("Log in cancelled", false, ui_idle, NBGL_NO_TUNE);
    }
}

#endif

static void u2f_prompt_user_presence(bool enroll, uint8_t *applicationParameter) {
    UX_WAKE_UP();

    format_hex(applicationParameter, 32, verifyHash, sizeof(verifyHash));
    strcpy(verifyName, "Unknown");

    const char *name = fido_match_known_appid(applicationParameter);
    if (name != NULL) {
        strlcpy(verifyName, name, sizeof(verifyName));
    }

#if defined(HAVE_BAGL)
    if (enroll) {
        ux_flow_init(0, ux_register_flow, NULL);
    } else {
        ux_flow_init(0, ux_login_flow, NULL);
    }
#elif defined(HAVE_NBGL)
    if (enroll) {
        app_nbgl_start_review(NB_OF_PAIRS, pairs, "Register", on_register_choice, NULL);
    } else {
        app_nbgl_start_review(NB_OF_PAIRS, pairs, "Login", on_login_choice, NULL);
    }
#endif
}

/******************************************/
/*           U2F APDU handlers            */
/******************************************/

static int u2f_handle_apdu_enroll(const uint8_t *rx, uint32_t data_length, const uint8_t *data) {
    // Parse request and check length validity
    u2f_reg_req_t *reg_req = (u2f_reg_req_t *) data;
    if (data_length != sizeof(u2f_reg_req_t)) {
        return io_send_sw(SW_WRONG_LENGTH);
    }

    // Check P1
    if (rx[OFFSET_P1] != 0) {
        if (rx[OFFSET_P1] == P1_U2F_REQUEST_USER_PRESENCE) {
            // Some platforms wrongly uses 0x03 as P1 for enroll:
            // https://searchfox.org/mozilla-central/source/third_party/rust/authenticator/src/consts.rs#55
            // https://github.com/Yubico/python-u2flib-host/issues/34
            // We choose to allow it.
        } else {
            return io_send_sw(SW_INCORRECT_P1P2);
        }
    }
    // Check P2
    if (rx[OFFSET_P2] != 0) {
        return io_send_sw(SW_INCORRECT_P1P2);
    }

    // Backup challenge and application parameters to be used if user accept the request
    memmove(globals_get_u2f_data()->challenge_param,
            reg_req->challenge_param,
            sizeof(reg_req->challenge_param));
    memmove(globals_get_u2f_data()->application_param,
            reg_req->application_param,
            sizeof(reg_req->application_param));

    if (G_io_u2f.media == U2F_MEDIA_USB) {
        u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
    }
    u2f_prompt_user_presence(true, globals_get_u2f_data()->application_param);
    return 0;
}

static int u2f_handle_apdu_sign(const uint8_t *rx, uint32_t data_length, uint8_t *data) {
    uint8_t *nonce;
    // Parse request base and check length validity
    u2f_auth_req_base_t *auth_req_base = (u2f_auth_req_base_t *) data;
    if (data_length < sizeof(u2f_auth_req_base_t)) {
        return io_send_sw(SW_WRONG_LENGTH);
    }

    // Parse request key handle and check length validity
    uint8_t *key_handle = data + sizeof(u2f_auth_req_base_t);
    if (data_length != sizeof(u2f_auth_req_base_t) + auth_req_base->key_handle_length) {
        return io_send_sw(SW_WRONG_LENGTH);
    }

    // Parse request P1
    bool sign = false;
    switch (rx[OFFSET_P1]) {
        case P1_U2F_CHECK_IS_REGISTERED:
            break;
        case P1_U2F_REQUEST_USER_PRESENCE:
        case P1_U2F_OPTIONAL_USER_PRESENCE:  // proof of user presence is always required (1.2)
            sign = true;
            break;
        default:
            return io_send_sw(SW_INCORRECT_P1P2);
    }

    // Check P2
    if (rx[OFFSET_P2] != 0) {
        return io_send_sw(SW_INCORRECT_P1P2);
    }

    // Check the key handle validity immediately
    // Store the nonce in globals u2f_data for response generation
    if (credential_unwrap(auth_req_base->application_param,
                          key_handle,
                          auth_req_base->key_handle_length,
                          &nonce,
                          NULL,
                          NULL) < 0) {
        return io_send_sw(SW_WRONG_DATA);
    }

    // If we only check user presence answer immediately
    if (!sign) {
        return io_send_sw(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Backup nonce, challenge and application parameters to be used if user accept the request
    memmove(globals_get_u2f_data()->nonce, nonce, CREDENTIAL_NONCE_SIZE);
    memmove(globals_get_u2f_data()->challenge_param,
            auth_req_base->challenge_param,
            sizeof(auth_req_base->challenge_param));
    memmove(globals_get_u2f_data()->application_param,
            auth_req_base->application_param,
            sizeof(auth_req_base->application_param));

    if (G_io_u2f.media == U2F_MEDIA_USB) {
        u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
    }
    u2f_prompt_user_presence(false, globals_get_u2f_data()->application_param);
    return 0;
}

static int u2f_handle_apdu_get_version(const uint8_t *rx,
                                       uint32_t data_length,
                                       const uint8_t *data) {
    UNUSED(data);
    if (data_length != 0) {
        return io_send_sw(SW_WRONG_LENGTH);
    }

    if ((rx[OFFSET_P1] != 0) || (rx[OFFSET_P2] != 0)) {
        return io_send_sw(SW_INCORRECT_P1P2);
    }

    return io_send_response_pointer((const uint8_t *) U2F_VERSION, U2F_VERSION_SIZE, SW_NO_ERROR);
}

static int u2f_handle_apdu_ctap2_proxy(uint8_t *rx, int data_length, uint8_t *data) {
    if ((rx[OFFSET_P1] != 0) || (rx[OFFSET_P2] != 0)) {
        return io_send_sw(SW_INCORRECT_P1P2);
    }

    ctap2_handle_cmd_cbor(&G_io_u2f, data, data_length);
    return 0;
}

int u2f_handle_apdu(uint8_t *rx, int rx_length) {
    uint8_t *data = NULL;
    uint16_t le = 0;
    // PRINTF("Media handleApdu %d\n", G_io_app.apdu_state);

    // Make sure cmd is detected as over U2F_CMD and not as CMD_IS_OVER_CTAP2_CBOR_CMD
    if (!CMD_IS_OVER_U2F_CMD) {
        return io_send_sw(SW_CONDITIONS_NOT_SATISFIED);
    }

    int data_length = u2f_get_cmd_msg_data(rx, rx_length, &data, &le);
    if (data_length < 0) {
        return io_send_sw(SW_WRONG_LENGTH);
    }

    PRINTF("INS %d, P1 %d P2 %d L %d\n", rx[OFFSET_INS], rx[OFFSET_P1], rx[OFFSET_P2], data_length);

    if (rx[OFFSET_CLA] == FIDO_CLA) {
        switch (rx[OFFSET_INS]) {
            case FIDO_INS_ENROLL:
                PRINTF("enroll\n");
                return u2f_handle_apdu_enroll(rx, data_length, data);

            case FIDO_INS_SIGN:
                PRINTF("sign\n");
                return u2f_handle_apdu_sign(rx, data_length, data);

            case FIDO_INS_GET_VERSION:
                PRINTF("version\n");
                return u2f_handle_apdu_get_version(rx, data_length, data);

            case FIDO_INS_CTAP2_PROXY:
                PRINTF("ctap2_proxy\n");
                return u2f_handle_apdu_ctap2_proxy(rx, data_length, data);

            default:
                PRINTF("unsupported\n");
                return io_send_sw(SW_INS_NOT_SUPPORTED);
        }
    } else {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }
}
