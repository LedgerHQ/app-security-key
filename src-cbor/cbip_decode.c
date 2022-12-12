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

#ifndef UNIT_TESTS
#include "os.h"
#endif

#include "cbip_decode.h"
#include "cbip_internal.h"

#define CHECK_AVAILABLE(x)                             \
    do {                                               \
        if ((decoder->offset + x) > decoder->length) { \
            return -1;                                 \
        }                                              \
    } while (0)

static int cbip_read_lv(cbipDecoder_t *decoder, uint8_t suppl, uint32_t *length, uint32_t *value) {
    if (suppl < CBOR_LEN_U8) {
        CHECK_AVAILABLE(1);
        *value = suppl;
        *length = 1;
        return 0;
    }
    if (suppl == CBOR_LEN_U8) {
        CHECK_AVAILABLE(2);
        *length = 2;
        *value = decoder->buffer[decoder->offset + 1];
        return 0;
    }
    if (suppl == CBOR_LEN_U16) {
        CHECK_AVAILABLE(3);
        *length = 3;
        *value =
            (decoder->buffer[decoder->offset + 1] << 8) + (decoder->buffer[decoder->offset + 2]);
        return 0;
    }
    if (suppl == CBOR_LEN_U32) {
        CHECK_AVAILABLE(5);
        *length = 5;
        *value = (((uint32_t) decoder->buffer[decoder->offset + 1]) << 24) +
                 (decoder->buffer[decoder->offset + 2] << 16) +
                 (decoder->buffer[decoder->offset + 3] << 8) +
                 (decoder->buffer[decoder->offset + 4]);
        return 0;
    }
    return -1;
}

int cbip_decoder_init(cbipDecoder_t *decoder, uint8_t *buffer, uint32_t length) {
    memset(decoder, 0, sizeof(cbipDecoder_t));
    decoder->buffer = buffer;
    decoder->length = length;
    return 0;
}

static int cbip_get(cbipDecoder_t *decoder, cbipItem_t *item) {
    uint8_t tag;
    uint8_t type;
    uint8_t suppl;
    int status;
    uint32_t next_offset;

    if (decoder->offset == decoder->length) {
        item->type = cbipNone;
        item->headerLength = 0;
        return 0;
    }
    item->offset = decoder->offset;
    CHECK_AVAILABLE(1);
    tag = decoder->buffer[decoder->offset];
    type = (tag & CBOR_TYPE_MASK);
    suppl = (tag & CBOR_INFO_BITS);
    status = cbip_read_lv(decoder, suppl, &item->headerLength, &item->value);
    if (status >= 0) {
        switch (type) {
            case CBOR_UNSIGNED_INT:
                item->type = cbipInt;
                return 0;
            case CBOR_NEGATIVE_INT:
                item->type = cbipNegativeInt;
                return 0;
            case CBOR_BYTE_STRING:
                item->type = cbipByteString;
                // Ensure that the length does not overflow uint32_t
                next_offset = decoder->offset + item->headerLength + item->value;
                if (next_offset < decoder->offset + item->headerLength ||
                    next_offset > decoder->length)
                    break;
                return 0;
            case CBOR_TEXT_STRING:
                item->type = cbipTextString;
                next_offset = decoder->offset + item->headerLength + item->value;
                if (next_offset < decoder->offset + item->headerLength ||
                    next_offset > decoder->length)
                    break;
                return 0;
            case CBOR_ARRAY:
                item->type = cbipArray;
                return 0;
            case CBOR_MAP:
                item->type = cbipMap;
                return 0;
            case CBOR_PRIMITIVE:
                switch (suppl) {
                    case CBOR_FALSE:
                        item->type = cbipFalse;
                        return 0;
                    case CBOR_TRUE:
                        item->type = cbipTrue;
                        return 0;
                    default:
                        PRINTF("Unknown primitive item %d\n", suppl);
                }
                break;
            default:
                PRINTF("Unknown item %d\n", type);
        }
    }
    item->type = cbipNone;
    item->headerLength = 0;
    return -1;
}

int cbip_first(cbipDecoder_t *decoder, cbipItem_t *item) {
    return cbip_get(decoder, item);
}

int cbip_next(cbipDecoder_t *decoder, cbipItem_t *item) {
    uint32_t offset = item->headerLength;
    switch (item->type) {
        case cbipNone:
            return -1;
        case cbipByteString:
        case cbipTextString:
            offset += item->value;
            break;
        default:
            break;
    }
    decoder->offset = item->offset;
    CHECK_AVAILABLE(offset);
    decoder->offset += offset;
    return cbip_get(decoder, item);
}

int cbip_get_int(cbipItem_t *item) {
    if (item->type == cbipInt) {
        return item->value;
    } else if (item->type == cbipNegativeInt) {
        return -1 - item->value;
    } else {
        return 0;
    }
}
