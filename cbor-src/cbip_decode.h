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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#ifndef __CBIP_DECODE_H__

#define __CBIP_DECODE_H__

typedef struct cbipDecoder_s {
    uint8_t *buffer;
    uint32_t length;
    uint32_t offset;
} cbipDecoder_t;

typedef enum cbipType_e {
    cbipNone = 0,
    cbipInt,
    cbipNegativeInt,
    cbipByteString,
    cbipTextString,
    cbipArray,
    cbipMap,
    cbipTrue,
    cbipFalse
} cbipType_t;

typedef struct cbipItem_s {
    cbipType_t type;
    uint32_t offset;
    uint32_t value;
    uint32_t headerLength;
} cbipItem_t;

int cbip_decoder_init(cbipDecoder_t *decoder, uint8_t *buffer, uint32_t length);
int cbip_first(cbipDecoder_t *decoder, cbipItem_t *item);
int cbip_next(cbipDecoder_t *decoder, cbipItem_t *item);
int cbip_get_int(cbipItem_t *item);

#endif
