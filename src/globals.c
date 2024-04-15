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

#include "globals.h"

char verifyName[20];
char verifyHash[65];
char rpID[65];

shared_ctx_t shared_ctx;
ctap2_ux_state_t ctap2UxState;

#ifdef TARGET_NANOS
// Spare RAM on Nanos
#else
uint8_t responseBuffer[IO_APDU_BUFFER_SIZE];
#endif
