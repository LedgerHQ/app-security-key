/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2022-2025 Ledger
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

#include "os.h"
#include "os_io_seproxyhal.h"
#include "ux.h"
#include "io.h"

#include "app_storage_data.h"
#include "globals.h"
#include "config.h"
#include "u2f_process.h"
#include "ui_shared.h"
#include "ctap2.h"
#include "rk_storage.h"

/**
 * Override app_ticker_event_callback io_event() dummy implementation
 */
void app_ticker_event_callback(void) {
    if (ctap2UxState != CTAP2_UX_STATE_NONE) {
        u2f_transport_ctap2_send_keepalive(&G_io_u2f, KEEPALIVE_REASON_TUP_NEEDED);
    }
#ifdef HAVE_NFC
    nfc_idle_work();
    nfc_idle_work2();
#endif
}

/**
 * Override lib_standard_app io_event() implementation
 *
 * This is necessary to remove the call to
 * io_seproxyhal_general_status() that's done at the end
 * and which ends up with throwing a SWO_IOL_STA_01
 * exception.
 */
uint8_t io_event(uint8_t channel) {
    (void) channel;

    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
#ifdef HAVE_BAGL
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif  // HAVE_BAGL
            break;
        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&  //
                !(U4BE(G_io_seproxyhal_spi_buffer, 3) &      //
                  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                THROW(EXCEPTION_IO_RESET);
            }
            __attribute__((fallthrough));
        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
            UX_DISPLAYED_EVENT({});
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL
            UX_DEFAULT_EVENT();
#endif  // HAVE_NBGL
            break;
#ifdef HAVE_NBGL
        case SEPROXYHAL_TAG_FINGER_EVENT:
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;
#endif  // HAVE_NBGL
        case SEPROXYHAL_TAG_TICKER_EVENT:
            app_ticker_event_callback();
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
            break;
        default:
            UX_DEFAULT_EVENT();
            break;
    }

    return 1;
}

static bool init_persistent_storage(void) {
    bool need_reinit = true;
    uint32_t version = 0;

    if (app_storage_get_size() > 0) {
        APP_STORAGE_READ_F(version, &version);
        if (version == APP_STORAGE_DATA_STRUCT_CURRENT_VERSION) {
            need_reinit = false;
        }
    }

    if (need_reinit) {
        PRINTF("Not initialized yet!\n");
        version = APP_STORAGE_DATA_STRUCT_CURRENT_VERSION;
        APP_STORAGE_WRITE_F(version, &version);
        if (config_init() != 0) {
            PRINTF("=> config_init failure\n");
            return false;
        }

    } else {
        PRINTF("Initialized with data version: %d\n", app_storage_get_data_version());
    }
    return true;
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void app_main() {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;

    io_init();

    if (!init_persistent_storage()) {
        PRINTF("Error while configuring the storage - aborting\n");
        return;
    }
    rk_storage_init();
    ctap2UxState = CTAP2_UX_STATE_NONE;
    ctap2_client_pin_reset_ctx();

    ui_idle();

    for (;;) {
        g.is_nfc = false;
        // Receive command bytes in G_io_apdu_buffer
        input_len = io_recv_command();
        // WARNING - For most basic U2F usages on USB, the SDK proxies U2F calls and directly calls
        // the `ctap2_handle_cmd_cbor` or `ctap2_handle_cmd_cancel` functions (implemented in SK) by
        // itself.
        // This means that in these cases this position is not even reached.
        if (input_len < 0) {
            PRINTF("=> io_recv_command failure\n");
            return;
        }
        g.is_nfc = CMD_IS_OVER_U2F_NFC;

        // Dispatch APDU command to handler
        if (u2f_handle_apdu(G_io_apdu_buffer, input_len) < 0) {
            PRINTF("=> apdu_dispatcher failure\n");
            return;
        }
    }
}
