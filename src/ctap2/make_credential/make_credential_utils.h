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

#define TAG_ALGORITHM        "alg"
#define TAG_SIGNATURE        "sig"
#define TAG_CERTIFICATE_X509 "x5c"

void ctap2_make_credential_confirm(void);
void ctap2_make_credential_user_cancel(void);
#ifdef HAVE_NFC
void check_and_generate_new_pubkey(void);
#endif
