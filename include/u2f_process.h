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

#ifndef __U2F_PROCESS_H__
#define __U2F_PROCESS_H__

#include "credential.h"

typedef struct u2f_data_t {
    uint8_t ins;
    uint8_t challenge_param[32];
    uint8_t application_param[32];
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
} u2f_data_t;

int u2f_handle_apdu(uint8_t *rx, int length);

#ifdef HAVE_NFC
void nfc_idle_work(void);
#endif  // HAVE_NFC

#endif  // __U2F_PROCESS_H__
