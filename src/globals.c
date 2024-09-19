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

#include "format.h"
#include "os.h"
#include "os_io_seproxyhal.h"

#include "globals.h"

global_t g;

shared_ctx_t shared_ctx;
ctap2_ux_state_t ctap2UxState;

#ifdef TARGET_NANOS
// Spare RAM on Nanos
#else
uint8_t responseBuffer[IO_APDU_BUFFER_SIZE];
#endif

#include "string_utils.h"

void ctap2_copy_info_on_buffers(void) {
    ctap2_register_data_t *ctap2RegisterData = globals_get_ctap2_register_data();

    // TODO show that rp.id is truncated if necessary
    uint8_t len = MIN(sizeof(g.buffer1_65) - 1, ctap2RegisterData->rpIdLen);
    memcpy(g.buffer1_65, ctap2RegisterData->rpId, len);
    g.buffer1_65[len] = '\0';

    // TODO show that user.id is truncated if necessary
    if (ctap2RegisterData->userStr) {
        uint8_t nameLength = MIN(ctap2RegisterData->userStrLen, sizeof(g.buffer2_65) - 1);

        memcpy(g.buffer2_65, ctap2RegisterData->userStr, nameLength);
        g.buffer2_65[nameLength] = '\0';
    } else {
        uint8_t nameLength = MIN(ctap2RegisterData->userIdLen, (sizeof(g.buffer2_65) - 1) / 2);

        format_hex(ctap2RegisterData->userId, nameLength, g.buffer2_65, sizeof(g.buffer2_65));
    }
}

void truncate_pairs_for_display(bool large) {
    /* truncate_for_nb_lines(g.buffer_20, large); */
    /* PRINTF("buffer_20 after truncation: '%s'\n", g.buffer_20); */
    truncate_for_nb_lines(g.buffer1_65, large);
    PRINTF("buffer1_65 after truncation: '%s'\n", g.buffer1_65);
    truncate_for_nb_lines(g.buffer2_65, large);
    PRINTF("buffer2_65 after truncation: '%s'\n", g.buffer2_65);
}

void prepare_display_status(bool clean_buffer) {
    if (!g.is_nfc || clean_buffer) {
        PRINTF("NO NFC or cleaning, so no display status for buffer1_65 '%s' and buffer2_65 '%s'\n",
               g.buffer1_65,
               g.buffer2_65);
        g.display_status[0] = '\0';
        return;
    }
    snprintf(g.display_status, sizeof(g.display_status), "%s\n%s", g.buffer1_65, g.buffer2_65);
    PRINTF("NFC so display status is: '%s'\n", g.display_status);
}
