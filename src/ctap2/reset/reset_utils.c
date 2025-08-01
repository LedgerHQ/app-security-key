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

#include <u2f_transport.h>

#include "config.h"
#include "globals.h"
#include "ctap2_utils.h"

void ctap2_reset_confirm() {
    config_process_ctap2_reset();

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1, NULL);
}

void ctap2_reset_cancel() {
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
}
