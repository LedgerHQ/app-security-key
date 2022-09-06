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
uint32_t uptime_ms = 0;
ctap2_ux_state_t ctap2UxState;

#ifdef TARGET_NANOS
// Spare RAM on Nanos
#else
uint8_t responseBuffer[IO_APDU_BUFFER_SIZE];
#endif

#include "string_utils.h"

static void copy_name_in_buffer65(char *buffer, const char *name, uint8_t nameLength) {
    bool name_too_long = (nameLength >= NAME_BUFFER_SIZE);
    if (name_too_long) {
        nameLength = NAME_BUFFER_SIZE - 4;
        memcpy(buffer, name, nameLength);
        // Appending '...' at the end of the name, to highlight it was truncated
        buffer[nameLength] = '.';
        buffer[nameLength + 1] = '.';
        buffer[nameLength + 2] = '.';
        buffer[nameLength + 3] = '\0';
    } else {
        memcpy(buffer, name, nameLength);
        buffer[nameLength] = '\0';
    }
}

void ctap2_display_copy_username(const char *name, uint8_t nameLength) {
    copy_name_in_buffer65(g.buffer2_65, name, nameLength);
}

void ctap2_display_copy_rp(const char *name, uint8_t nameLength) {
    copy_name_in_buffer65(g.buffer1_65, name, nameLength);
}

void truncate_pairs_for_display(bool large) {
    /* truncate_for_nb_lines(g.buffer_20, large); */
    /* PRINTF("buffer_20 after truncation: '%s'\n", g.buffer_20); */
    truncate_for_nb_lines(g.buffer1_65, large);
    PRINTF("buffer1_65 after truncation: '%s'\n", g.buffer1_65);
    truncate_for_nb_lines(g.buffer2_65, large);
    PRINTF("buffer2_65 after truncation: '%s'\n", g.buffer2_65);
}

void prepare_displayed_message(bool clean_buffer) {
    if (clean_buffer) {
        PRINTF("NO NFC or cleaning, so no display status for buffer1_65 '%s' and buffer2_65 '%s'\n",
               g.buffer1_65,
               g.buffer2_65);
        g.displayed_message[0] = '\0';
        return;
    }
    snprintf(g.displayed_message,
             sizeof(g.displayed_message),
             "%s\n%s",
             g.buffer1_65,
             g.buffer2_65);
    PRINTF("NFC so display status is: '%s'\n", g.displayed_message);
}
