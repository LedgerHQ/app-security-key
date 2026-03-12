/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2025 Ledger
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

/**
 * @file  ble_io.c
 * @brief BLE FIDO transport IO implementation for the Security Key app.
 *
 * This module provides the BLE-specific response path for CTAP2 commands
 * received over the FIDO BLE GATT service (UUID 0xFFFD).
 *
 * Responses are sent as CTAP2-BLE MSG frames via the SDK's BLE_LEDGER_send().
 * Keepalive notifications use the CTAP2-BLE KEEPALIVE command (0x82).
 */

#if defined(HAVE_BLE_FIDO) && defined(HAVE_BLE)

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "os_io.h"
#include "io.h"
#include "sw_code.h"
#include "globals.h"
#include "ble_io.h"
#include "ui_shared.h"
#include "u2f_types.h"
#include "ble_ledger.h"

/* BLE_LEDGER_PROFILE_U2F = 0x0004 from ble_ledger.h */
#ifndef BLE_LEDGER_PROFILE_U2F
#define BLE_LEDGER_PROFILE_U2F 0x0004
#endif

/* CTAP2 BLE command bytes (without the 0x80 init flag) */
#define FIDO_BLE_CMD_MSG_RAW       (0x03)  /* U2F_COMMAND_MSG */
#define FIDO_BLE_CMD_KEEPALIVE_RAW (0x02)  /* U2F_COMMAND_BLE_KEEP_ALIVE */

static bool     ble_data_ready;
static uint16_t ble_sw;
static uint16_t ble_buffer_len;
static const char *ble_status;

void ble_io_set_response_ready(uint16_t sw, uint16_t len, const char *status) {
    ble_sw         = sw;
    ble_buffer_len = len;
    ble_status     = status;
    ble_data_ready = true;
}

bool ble_io_is_response_pending(void) {
    return ble_data_ready;
}

int ble_io_send_prepared_response(void) {
    if (!ble_data_ready) {
        return -1;
    }

    ble_data_ready = false;

    if (ble_sw != SW_NO_ERROR) {
        /* Send an error as a CTAP2 error byte */
        return -1;
    }

    /*
     * Build a packet for BLE_LEDGER_send():
     * packet[0] = U2F command byte (MSG = 0x03)
     * packet[1..N] = CTAP2 CBOR response payload
     *
     * The BLE profile's send_packet() will pass this to U2F_TRANSPORT_tx
     * which adds the BLE framing (CMD|HLEN|LLEN|...) and fragments.
     */
    uint8_t cmd_byte = FIDO_BLE_CMD_MSG_RAW;

    /* We use os_io_tx_cmd to send through the SDK IO dispatch which routes
     * to BLE_LEDGER_send for BLE_U2F_APDU packet type */
    os_io_tx_cmd(OS_IO_PACKET_TYPE_BLE_U2F_APDU,
                 responseBuffer,
                 ble_buffer_len,
                 NULL);
    UNUSED(cmd_byte);

#ifdef HAVE_NBGL
    if (ble_status != NULL && g.display_status) {
        app_nbgl_status(ble_status, true, ui_idle);
    }
#endif
    g.display_status = true;

    return 0;
}

void ble_io_send_keepalive(uint8_t reason) {
    /*
     * CTAP2 BLE KEEPALIVE frame:
     * CMD = 0x82 (KEEPALIVE), payload = 1 byte reason code
     *
     * Build the packet as: [CMD_BYTE, REASON]
     * where CMD_BYTE is the raw command (0x02) passed to U2F_TRANSPORT_tx
     */
    uint8_t keepalive_pkt[2];
    keepalive_pkt[0] = FIDO_BLE_CMD_KEEPALIVE_RAW;
    keepalive_pkt[1] = reason;

    BLE_LEDGER_send(BLE_LEDGER_PROFILE_U2F,
                    keepalive_pkt,
                    sizeof(keepalive_pkt),
                    0);
}

#endif /* HAVE_BLE_FIDO && HAVE_BLE */
