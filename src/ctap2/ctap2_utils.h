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

#pragma once

#ifndef UNIT_TESTS
#include <u2f_service.h>
#else
#include "unit_test.h"
#endif

bool ctap2_check_rpid_filter(const char *rpId, uint32_t rpIdLen);
void send_cbor_error(u2f_service_t *service, uint8_t error);

/*
 * Sends the CBOR response on the relevant transport.
 *
 * If the `status` is not NULL AND the transport is NFC, displays a `status`
 * message on the screen (this is for GET_ASSERTION and MAKE_CREDENTIALS cmds).
 */
void send_cbor_response(u2f_service_t *service, uint32_t length, const char *status);
void ctap2_send_keepalive_processing(void);
