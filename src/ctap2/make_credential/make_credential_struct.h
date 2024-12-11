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

typedef struct ctap2_register_data_s {
    uint8_t rpIdHash[CX_SHA256_SIZE];
    uint8_t *buffer;  // pointer to the CBOR message in the APDU buffer
    char *rpId;
    uint32_t rpIdLen;
    uint8_t *clientDataHash;
    uint8_t *userId;
    uint32_t userIdLen;
    char *userStr;
    uint32_t userStrLen;
    int coseAlgorithm;     // algorithm chosen following the request message
    uint8_t pinRequired;   // set if uv is set
    uint8_t pinPresented;  // set if the PIN request was acknowledged by the user
    uint8_t
        clientPinAuthenticated;  // set if a standard FIDO client PIN authentication was performed
    uint8_t residentKey;         // set if the credential shall be created as a resident key
    uint8_t extensions;          // extensions flags as a bitmask
} ctap2_register_data_t;
