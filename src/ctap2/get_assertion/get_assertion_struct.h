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

#include <lcx_sha256.h>
#include "cbip_decode.h"

typedef union ctap2_assert_multiple_flow_data_s {
    struct {
        cbipItem_t credentialItem;
        uint32_t currentCredential;
    } allowList;
    struct {
        uint16_t minAge;
    } rk;
} ctap2_assert_multiple_flow_data_t;

typedef struct ctap2_assert_data_s {
    uint8_t rpIdHash[CX_SHA256_SIZE];
    uint8_t *buffer;  // pointer to the CBOR message in the APDU buffer
    char *rpId;
    uint32_t rpIdLen;
    uint8_t clientDataHash[CX_SHA256_SIZE];  // Could be reused over successive GET_ASSERTION /
                                             // GET_NEXT_ASSERTION calls
    uint8_t *credId;
    uint32_t credIdLen;
    uint8_t *nonce;
    uint8_t *credential;
    uint32_t credentialLen;
    uint8_t pinRequired;   // set if uv is set
    uint8_t pinPresented;  // set if the PIN request was acknowledged by the user
    uint8_t
        clientPinAuthenticated;    // set if a standard FIDO client PIN authentication was performed
    uint8_t userPresenceRequired;  // set if up is set
    uint8_t extensions;            // extensions flags as a bitmask

    uint8_t allowListPresent;
    uint16_t availableCredentials;

    // Multiple flow data
    uint16_t currentCredentialIndex;
    ctap2_assert_multiple_flow_data_t multipleFlowData;
} ctap2_assert_data_t;
