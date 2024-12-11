/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2024 Ledger
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

#ifdef HAVE_NFC
#include <stdint.h>
#include <stdbool.h>

#include "os_math.h"
#include "io.h"
#include "sw_code.h"
#include "globals.h"
#include "nfc_io.h"
#include "ui_shared.h"

static bool nfc_data_ready;
static uint16_t nfc_sw;
static uint16_t nfc_buffer_len;
static uint16_t nfc_buffer_offset;
static uint32_t nfc_le;
static const char *nfc_status;

void nfc_io_set_le(uint32_t le) {
    nfc_le = le;
}

void nfc_io_set_response_ready(uint16_t sw, uint16_t len, const char *status) {
    nfc_sw = sw;
    nfc_buffer_len = len;
    nfc_status = status;
    nfc_buffer_offset = 0;
    nfc_data_ready = true;
}

bool nfc_io_is_response_pending(void) {
    return nfc_data_ready;
}

int nfc_io_send_prepared_response() {
    if (!nfc_data_ready) {
        return io_send_sw(SW_WRONG_DATA);
    }

    if (nfc_sw != SW_NO_ERROR) {
        nfc_data_ready = false;
        return io_send_sw(nfc_sw);
    }

    if (nfc_buffer_offset >= nfc_buffer_len) {
        nfc_data_ready = false;
        return io_send_sw(SW_WRONG_DATA);
    }

    uint16_t size = MIN(nfc_le, nfc_buffer_len - nfc_buffer_offset);
    uint16_t start = nfc_buffer_offset;

    nfc_buffer_offset += size;

    uint16_t sw;
    if ((nfc_buffer_len - nfc_buffer_offset) >= 256) {
        sw = SW_MORE_DATA;
    } else if (nfc_buffer_len == nfc_buffer_offset) {
        nfc_data_ready = false;
        sw = SW_NO_ERROR;
    } else {
        sw = SW_MORE_DATA + (nfc_buffer_len - nfc_buffer_offset);
    }

    int ret = io_send_response_pointer(responseBuffer + start, size, sw);
    if (sw == SW_NO_ERROR && nfc_status != NULL && g.display_status) {
        app_nbgl_status(nfc_status, true, ui_idle);
    }
    g.display_status = true;
    return ret;
}

#endif
