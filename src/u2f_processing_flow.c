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

#include "cx.h"
#include "format.h"
#include "io.h"
#include "ux.h"

#include "config.h"
#include "crypto.h"
#include "crypto_data.h"
#include "fido_known_apps.h"
#include "globals.h"
#include "nfc_io.h"
#include "sw_code.h"
#include "u2f_processing_flow.h"
#include "ui_shared.h"

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

#ifdef HAVE_NFC
static bool nfc_nonce_and_pubkey_ready;
static uint8_t nfc_nonce[CREDENTIAL_NONCE_SIZE];
static uint8_t nfc_pubkey[U2F_ENROLL_USER_KEY_SIZE];

void nfc_idle_work(void) {
    // Generate a new nonce/pubkey pair only if not already available and in idle
    if (nfc_nonce_and_pubkey_ready || nfc_io_is_response_pending()) {
        return;
    }

    cx_rng_no_throw(nfc_nonce, CREDENTIAL_NONCE_SIZE);
    if (u2f_generate_pubkey(nfc_nonce, nfc_pubkey) != 0) {
        return;
    }

    nfc_nonce_and_pubkey_ready = true;
}
#endif

uint16_t u2f_prepare_enroll_response(uint8_t *buffer, uint16_t *length) {
    int offset = 0;
    int result;
    int key_handle_length;

    *length = 0;

    u2f_reg_resp_base_t *reg_resp_base = (u2f_reg_resp_base_t *) buffer;
    offset += sizeof(u2f_reg_resp_base_t);

    // Fill reserved byte
    reg_resp_base->reserved_byte = U2F_ENROLL_RESERVED;

#ifdef HAVE_NFC
    // Spare response time by pre-generating part of the answer
    if (nfc_nonce_and_pubkey_ready) {
        memcpy(globals_get_u2f_data()->nonce, nfc_nonce, CREDENTIAL_NONCE_SIZE);
        memcpy(reg_resp_base->user_key, nfc_pubkey, U2F_ENROLL_USER_KEY_SIZE);
        nfc_nonce_and_pubkey_ready = false;
    } else
#endif
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

uint16_t u2f_prepare_sign_response(uint8_t *buffer, uint16_t *length) {
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

    switch (globals_get_u2f_data()->ins) {
        case FIDO_INS_REGISTER:
            sw = u2f_prepare_enroll_response(responseBuffer, &length);
            break;

        case FIDO_INS_SIGN:
            sw = u2f_prepare_sign_response(responseBuffer, &length);
            break;

        default:
            break;
    }
    return io_send_response_pointer(responseBuffer, length, sw);
}

/******************************************/
/*             U2F UX Flows               */
/******************************************/

#if defined(HAVE_BAGL)

static unsigned int u2f_callback_cancel(void) {
    io_send_sw(SW_USER_REFUSED);
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
               g.buffer_20,
           });
UX_STEP_NOCB(ux_register_flow_1_step,
             bnnn_paging,
             {
                 .title = "Identifier",
                 .text = g.username_buffer,
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
               g.buffer_20,
           });
UX_STEP_NOCB(ux_login_flow_1_step,
             bnnn_paging,
             {
                 .title = "Identifier",
                 .text = g.username_buffer,
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
                                                             .value = g.buffer_20,
                                                         },
                                                         {
                                                             .item = "Website ID",
                                                             .value = g.username_buffer,
                                                         }};

static void on_register_choice(bool confirm) {
    if (confirm) {
        u2f_process_user_presence_confirmed();
        app_nbgl_status("Registration details\nsent", true, ui_idle);
    } else {
        io_send_sw(SW_USER_REFUSED);
        app_nbgl_status("Registration cancelled", false, ui_idle);
    }
}

static void on_login_choice(bool confirm) {
    if (confirm) {
        u2f_process_user_presence_confirmed();
        app_nbgl_status("Login request signed", true, ui_idle);
    } else {
        io_send_sw(SW_USER_REFUSED);
        app_nbgl_status("Log in cancelled", false, ui_idle);
    }
}

#endif

void u2f_prompt_user_presence(bool enroll) {
    UX_WAKE_UP();

    char tmp_buf[sizeof(g.username_buffer)] = {0};
    format_hex(globals_get_u2f_data()->application_param, 32, tmp_buf, sizeof(tmp_buf));
    globals_display_set_username(tmp_buf, strlen(tmp_buf));
    const char *name = fido_match_known_appid(globals_get_u2f_data()->application_param);
    if (name != NULL) {
        strlcpy(g.buffer_20, name, sizeof(g.buffer_20));
    } else {
        strcpy(g.buffer_20, "Unknown");
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
