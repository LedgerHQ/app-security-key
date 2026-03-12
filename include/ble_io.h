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
 * @file  ble_io.h
 * @brief BLE FIDO transport IO helpers for the Security Key app.
 *
 * Provides thin wrappers around the SDK BLE_LEDGER_send() path, analogous
 * to nfc_io.h for the NFC transport.
 */

#pragma once

#if defined(HAVE_BLE_FIDO) && defined(HAVE_BLE)

#include <stdint.h>
#include <stdbool.h>

/**
 * Prepare a CBOR response for sending over BLE FIDO transport.
 *
 * @param sw     Status word (SW_NO_ERROR on success)
 * @param len    Payload length in responseBuffer
 * @param status Human-readable status string (for optional on-screen display)
 */
void ble_io_set_response_ready(uint16_t sw, uint16_t len, const char *status);

/**
 * Check whether a BLE FIDO response is pending.
 */
bool ble_io_is_response_pending(void);

/**
 * Send the previously prepared BLE FIDO response.
 *
 * This sends the full CTAP2 response as a MSG command via the BLE profile,
 * which handles fragmentation into CTAP2 BLE frames.
 *
 * @return 0 on success, negative on error
 */
int ble_io_send_prepared_response(void);

/**
 * Send a CTAP2 BLE KEEPALIVE notification with the given reason code.
 *
 * @param reason  KEEPALIVE_REASON_PROCESSING or KEEPALIVE_REASON_TUP_NEEDED
 */
void ble_io_send_keepalive(uint8_t reason);

#else /* !(HAVE_BLE_FIDO && HAVE_BLE) */

static inline void ble_io_set_response_ready(uint16_t sw, uint16_t len, const char *status) {
    (void) sw;
    (void) len;
    (void) status;
}

static inline bool ble_io_is_response_pending(void) {
    return false;
}

static inline int ble_io_send_prepared_response(void) {
    return -1;
}

static inline void ble_io_send_keepalive(uint8_t reason) {
    (void) reason;
}

#endif /* HAVE_BLE_FIDO && HAVE_BLE */
