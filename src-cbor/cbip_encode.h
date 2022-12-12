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

#ifndef __CBIP_ENCODE_H__

#define __CBIP_ENCODE_H__

#define CBIP_HEADER_MAX_SIZE 5

typedef struct cbipEncoder_s {
    uint8_t *buffer;
    uint32_t length;
    uint32_t offset;
    bool fault;
} cbipEncoder_t;

int cbip_encoder_init(cbipEncoder_t *encoder, uint8_t *buffer, uint32_t length);
int cbip_add_int(cbipEncoder_t *encoder, int value);
int cbip_add_byte_string(cbipEncoder_t *encoder, const uint8_t *value, uint32_t valueLength);
int cbip_add_string(cbipEncoder_t *encoder, const char *value, uint32_t valueLength);
int cbip_add_boolean(cbipEncoder_t *encoder, bool value);
int cbip_add_array_header(cbipEncoder_t *encoder, uint32_t length);
int cbip_add_map_header(cbipEncoder_t *encoder, uint32_t length);

#endif
