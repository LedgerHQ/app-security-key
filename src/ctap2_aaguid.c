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

#if defined(TARGET_NANOS)

// sha256 "Ledger FIDO 2 1.0"
uint8_t const AAGUID[16] = {0x34,
                            0x1e,
                            0x4d,
                            0xa9,
                            0x3c,
                            0x2e,
                            0x81,
                            0x03,
                            0x5a,
                            0x9f,
                            0xaa,
                            0xd8,
                            0x87,
                            0x13,
                            0x52,
                            0x00};

#endif

#if defined(TARGET_NANOX)

// sha256 "Ledger FIDO 2 1.0 NanoX"
uint8_t const AAGUID[16] = {0xfc,
                            0xb1,
                            0xbc,
                            0xb4,
                            0xf3,
                            0x70,
                            0x07,
                            0x8c,
                            0x69,
                            0x93,
                            0xbc,
                            0x24,
                            0xd0,
                            0xae,
                            0x3f,
                            0xbe};

#endif

#if defined(TARGET_NANOS2)

// sha256 "Ledger FIDO 2 1.0 NanoS+"
uint8_t const AAGUID[16] = {0x58,
                            0xb4,
                            0x4d,
                            0x0b,
                            0x0a,
                            0x7c,
                            0xf3,
                            0x3a,
                            0xfd,
                            0x48,
                            0xf7,
                            0x15,
                            0x3c,
                            0x87,
                            0x13,
                            0x52};
#endif
