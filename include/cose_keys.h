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

#ifndef __COSE_KEYS_H__
#define __COSE_KEYS_H__

#include "cbip_encode.h"
#include "cbip_decode.h"

int encode_cose_key(cbipEncoder_t *encoder, cx_ecfp_public_key_t *key, bool forExchange);
int decode_cose_key(cbipDecoder_t *decoder,
                    cbipItem_t *map,
                    cx_ecfp_public_key_t *key,
                    bool forExchange);
cx_curve_t cose_alg_to_cx(int coseAlgorithn);

#endif