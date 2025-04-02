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

#include <os.h>

#include "ctap2.h"
#include "get_assertion_utils.h"
#include "globals.h"
#include "rk_storage.h"

void ctap2_get_next_assertion_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(buffer);
    UNUSED(length);
    ctap2_assert_data_t *ctap2AssertData = globals_get_ctap2_assert_data();

    if (!g.get_next_assertion_enabled) {
        PRINTF("GET_NEXT_ASSERTION only implemented for RK credentials over NFC.\n");
        send_cbor_error(service, ERROR_NOT_ALLOWED);
        return;
    } else {
        // No allow list -> RK credentials
        PRINTF("GET_NEXT_ASSERTION: looking for the next RK credential.\n");
        ctap2AssertData->availableCredentials = 1;
        int status = rk_next_credential_from_RKList(NULL,
                                                    ctap2AssertData->nonce,
                                                    ctap2AssertData->credential,
                                                    &ctap2AssertData->credentialLen);
        if (status == RK_NOT_FOUND) {
            PRINTF("GET_NEXT_ASSERTION: no remaining RK credential.\n");
            send_cbor_error(service, ERROR_NOT_ALLOWED);
            return;
        }
        g.display_status = false;
        get_assertion_send();
    }
}
