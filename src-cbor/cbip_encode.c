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

#include <string.h>

#include "cbip_encode.h"
#include "cbip_internal.h"

#define CHECK_AVAILABLE(x)                             \
    do {                                               \
        if ((encoder->offset + x) > encoder->length) { \
            encoder->fault = true;                     \
            return -1;                                 \
        }                                              \
    } while (0)

#define CHECK_FAULT()         \
    do {                      \
        if (encoder->fault) { \
            return -1;        \
        }                     \
    } while (0)

static int cbip_add_header(cbipEncoder_t *encoder, uint8_t tag, uint32_t value) {
    if (value < CBOR_LEN_U8) {
        CHECK_AVAILABLE(1);
        encoder->buffer[encoder->offset++] = (uint8_t) (tag + value);
        return 0;
    }
    if (value <= 0xFF) {
        CHECK_AVAILABLE(2);
        encoder->buffer[encoder->offset++] = (uint8_t) (tag + CBOR_LEN_U8);
        encoder->buffer[encoder->offset++] = (uint8_t) value;
        return 0;
    }
    if (value <= 0xFFFF) {
        CHECK_AVAILABLE(3);
        encoder->buffer[encoder->offset++] = (uint8_t) (tag + CBOR_LEN_U16);
        encoder->buffer[encoder->offset++] = (uint8_t) ((value >> 8) & 0xff);
        encoder->buffer[encoder->offset++] = (uint8_t) (value & 0xff);
        return 0;
    }
    CHECK_AVAILABLE(5);
    encoder->buffer[encoder->offset++] = (uint8_t) (tag + CBOR_LEN_U32);
    encoder->buffer[encoder->offset++] = (uint8_t) ((value >> 24) & 0xff);
    encoder->buffer[encoder->offset++] = (uint8_t) ((value >> 16) & 0xff);
    encoder->buffer[encoder->offset++] = (uint8_t) ((value >> 8) & 0xff);
    encoder->buffer[encoder->offset++] = (uint8_t) (value & 0xff);
    return 0;
}

int cbip_encoder_init(cbipEncoder_t *encoder, uint8_t *buffer, uint32_t length) {
    memset(encoder, 0, sizeof(cbipEncoder_t));
    encoder->buffer = buffer;
    encoder->length = length;
    return 0;
}

int cbip_add_int(cbipEncoder_t *encoder, int value) {
    CHECK_FAULT();
    return cbip_add_header(encoder,
                           (value >= 0 ? CBOR_UNSIGNED_INT : CBOR_NEGATIVE_INT),
                           (value >= 0 ? value : -1 - value));
}

static int cbip_add_raw(cbipEncoder_t *encoder,
                        uint8_t tag,
                        const uint8_t *value,
                        uint32_t valueLength) {
    int result;
    result = cbip_add_header(encoder, tag, valueLength);
    if (result < 0) {
        return result;
    }
    CHECK_AVAILABLE(valueLength);
    memmove(encoder->buffer + encoder->offset, value, valueLength);
    encoder->offset += valueLength;
    return 0;
}

int cbip_add_byte_string(cbipEncoder_t *encoder, const uint8_t *value, uint32_t valueLength) {
    CHECK_FAULT();
    return cbip_add_raw(encoder, CBOR_BYTE_STRING, value, valueLength);
}

int cbip_add_string(cbipEncoder_t *encoder, const char *value, uint32_t valueLength) {
    CHECK_FAULT();
    return cbip_add_raw(encoder, CBOR_TEXT_STRING, (uint8_t *) value, valueLength);
}

int cbip_add_boolean(cbipEncoder_t *encoder, bool value) {
    CHECK_FAULT();
    CHECK_AVAILABLE(1);
    encoder->buffer[encoder->offset++] =
        (uint8_t) (CBOR_PRIMITIVE + (value ? CBOR_TRUE : CBOR_FALSE));
    return 0;
}

int cbip_add_array_header(cbipEncoder_t *encoder, uint32_t length) {
    CHECK_FAULT();
    return cbip_add_header(encoder, CBOR_ARRAY, length);
}

int cbip_add_map_header(cbipEncoder_t *encoder, uint32_t length) {
    CHECK_FAULT();
    return cbip_add_header(encoder, CBOR_MAP, length);
}
