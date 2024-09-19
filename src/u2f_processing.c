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

#include "io.h"
#include "u2f_processing.h"

#include "u2f_process.h"
#include "u2f_processing_flow.h"
#include "config.h"
#include "ui_shared.h"
#include "globals.h"
#include "nfc_io.h"
#include "sw_code.h"

static int u2f_get_cmd_msg_data(uint8_t *rx, uint16_t rx_length, uint8_t **data, uint32_t *le) {
    uint32_t data_length;
    /* Parse buffer to retrieve the data length.
       Both Short and Extended encodings are supported */

    // By default, if absent, le == 0
    *le = 0;

    if (rx_length < APDU_MIN_HEADER) {
        return -1;
    }

    if (rx_length == APDU_MIN_HEADER) {
        // Short encoding with Lc and Le omitted
        *le = SHORT_ENC_DEFAULT_LE;
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

        if (*le == 0) {
            *le = SHORT_ENC_DEFAULT_LE;
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

        if (*le == 0) {
            *le = SHORT_ENC_DEFAULT_LE;
        }
        return data_length;
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

            if (*le == 0) {
                *le = SHORT_ENC_DEFAULT_LE;
            }
            return data_length;
        } else {
            // Can't be short encoding as Lc = 0x00 would lead to invalid length
            // so extended encoding and either:
            // - Lc = 0x00 0x00 0x00 and Le is omitted
            // - Lc omitted and Le = 0x00 0xyy 0xzz
            // so no way to check the value
            // but anyway the data length is 0
            *le = (rx[APDU_MIN_HEADER + 1] << 8) + rx[APDU_MIN_HEADER + 2];

            if (*le == 0) {
                *le = EXT_ENC_DEFAULT_LE;
            }

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

        if (*le == 0) {
            *le = SHORT_ENC_DEFAULT_LE;
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
                  rx[EXT_ENC_DATA_OFFSET + data_length + 1];
        } else {
            return -1;
        }
        if (*le == 0) {
            *le = EXT_ENC_DEFAULT_LE;
        }
        return data_length;
    }
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

    // Backup ins, challenge and application parameters to be used if user accept the request
    globals_get_u2f_data()->ins = FIDO_INS_ENROLL;
    memmove(globals_get_u2f_data()->challenge_param,
            reg_req->challenge_param,
            sizeof(reg_req->challenge_param));
    memmove(globals_get_u2f_data()->application_param,
            reg_req->application_param,
            sizeof(reg_req->application_param));

    if (CMD_IS_OVER_U2F_NFC) {
        uint16_t length = 0;
        uint16_t sw = u2f_prepare_enroll_response(responseBuffer, &length);

        nfc_io_set_response_ready(sw, length, "Registration details\nsent");

        return nfc_io_send_prepared_response(false);
    } else if (CMD_IS_OVER_U2F_USB) {
        u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
    }
    u2f_prompt_user_presence(true);
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

    // Backup ins, nonce, challenge and application parameters to be used if user accept the request
    globals_get_u2f_data()->ins = FIDO_INS_SIGN;
    memmove(globals_get_u2f_data()->nonce, nonce, CREDENTIAL_NONCE_SIZE);
    memmove(globals_get_u2f_data()->challenge_param,
            auth_req_base->challenge_param,
            sizeof(auth_req_base->challenge_param));
    memmove(globals_get_u2f_data()->application_param,
            auth_req_base->application_param,
            sizeof(auth_req_base->application_param));

    // clang-format off
    // following macros + `else if` was messing with clang until the `return`
#ifdef HAVE_NFC
    if (CMD_IS_OVER_U2F_NFC) {
        // Android doesn't support answering SW_MORE_DATA here...
        // so compute the real answer as fast as possible
        uint16_t length = 0;
        uint16_t sw = u2f_prepare_sign_response(responseBuffer, &length);
        // Message fit in a single response, answer directly without nfc_io features
        io_send_response_pointer(responseBuffer, length, sw);

        app_nbgl_status("Login request signed", true, ui_idle);
        return 0;
    } else
#endif  // HAVE_NFC
    if (CMD_IS_OVER_U2F_USB) {
        u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
    }

    u2f_prompt_user_presence(false);
    return 0;

    // clang-format on
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

static int u2f_handle_apdu_applet_select(uint8_t *rx, int data_length, const uint8_t *data) {
    if ((rx[OFFSET_P1] != 0x04) || (rx[OFFSET_P2] != 0)) {
        return io_send_sw(SW_INCORRECT_P1P2);
    }

    if ((data_length != FIDO_AID_SIZE) || (memcmp(data, FIDO_AID, FIDO_AID_SIZE) != 0)) {
        return io_send_sw(SW_WRONG_DATA);
    }

    return io_send_response_pointer((const uint8_t *) U2F_VERSION, U2F_VERSION_SIZE, SW_NO_ERROR);
}

int u2f_handle_apdu(uint8_t *rx, int rx_length) {
    // PRINTF("=> RAW=%.*H\n", rx_length, rx);

    uint8_t *data = NULL;
    uint32_t le = 0;
    // PRINTF("Media handleApdu %d\n", G_io_app.apdu_state);

    // Make sure cmd is detected as over U2F_CMD and not as CMD_IS_OVER_CTAP2_CBOR_CMD
    if (!CMD_IS_OVER_U2F_CMD) {
        return io_send_sw(SW_CONDITIONS_NOT_SATISFIED);
    }

    int data_length = u2f_get_cmd_msg_data(rx, rx_length, &data, &le);
    if (data_length < 0) {
        return io_send_sw(SW_WRONG_LENGTH);
    }

    if (CMD_IS_OVER_U2F_NFC) {
        nfc_io_set_le(le);
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

            case FIDO_INS_APPLET_SELECT:
                PRINTF("applet_select\n");
                // return io_send_sw(SW_INS_NOT_SUPPORTED);
                return u2f_handle_apdu_applet_select(rx, data_length, data);

            case 0xc0:
                if (!CMD_IS_OVER_U2F_NFC) {
                    return io_send_sw(SW_INS_NOT_SUPPORTED);
                }
                return nfc_io_send_prepared_response(false);

            default:
                PRINTF("unsupported\n");
                return io_send_sw(SW_INS_NOT_SUPPORTED);
        }
    } else if (CMD_IS_OVER_U2F_NFC && (rx[OFFSET_CLA] == FIDO2_NFC_CLA)) {
        switch (rx[OFFSET_INS]) {
            case FIDO2_NFC_INS_CTAP2_PROXY:
                PRINTF("ctap2_proxy\n");
                return u2f_handle_apdu_ctap2_proxy(rx, data_length, data);

            case 0x11:
                PRINTF("NFCCTAP_GETRESPONSE\n");
                return nfc_io_send_prepared_response(false);

            case FIDO2_NFC_INS_APPLET_DESELECT:
                PRINTF("unsupported\n");
                return io_send_sw(SW_INS_NOT_SUPPORTED);

            case 0xc0:
                return nfc_io_send_prepared_response(false);

            default:
                PRINTF("unsupported\n");
                return io_send_sw(SW_INS_NOT_SUPPORTED);
        }
    } else if (CMD_IS_OVER_U2F_NFC && (rx[OFFSET_CLA] == FIDO2_NFC_CHAINING_CLA)) {
        // TODO but as of now it's not used neither on:
        // - iOS: using extended encoding
        // - Android: using U2F only
        switch (rx[OFFSET_INS]) {
            case 0x60:
                return io_send_sw(0x9000);

            default:
                PRINTF("unsupported\n");
                return io_send_sw(SW_INS_NOT_SUPPORTED);
        }
    } else {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }
}
