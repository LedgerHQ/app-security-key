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

void truncate_pairs_for_display() {
    truncate_for_nb_lines(g.rpID);
    PRINTF("rpID after truncation: '%s'\n", glonal.rpID);
    truncate_for_nb_lines(g.verifyHash);
    PRINTF("verifyHash after truncation: '%s'\n", g.verifyHash);
}

void prepare_display_status() {
    if (!g.is_nfc) {
        PRINTF("NOT NFC so no display status for rpID '%s' and verifyHash '%s'\n",
               g.rpID,
               g.verifyHash);
        g.display_status[0] = '\0';
        return;
    }
    g.is_nfc = false;
    strncpy(g.display_status, g.rpID, strlen(g.rpID));
    g.display_status[strlen(g.rpID)] = '\n';
    strncpy(g.display_status + strlen(g.rpID) + 1, g.verifyHash, strlen(g.verifyHash));
    PRINTF("NFC so display status is: '%s'\n", g.display_status);
}
