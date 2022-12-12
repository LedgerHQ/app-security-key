/**
 * Fuzz implementation of CBOR in-place parsing in src-cbor/cbip_decode.c
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

extern "C" {
#include "cbip_decode.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *writable_data;
    int status;
    cbipDecoder_t decoder;
    cbipItem_t item;
    bool first = true;

    writable_data = (uint8_t *)malloc(size);
    if (!writable_data)
        return 0;
    memcpy(writable_data, data, size);

    status = cbip_decoder_init(&decoder, writable_data, size);
    // cbip_decoder_init always succeeds
    assert(status == 0);
    for (;;) {
        if (first) {
            status = cbip_first(&decoder, &item);
            first = false;
        } else {
            status = cbip_next(&decoder, &item);
        }
        if (status < 0) {
            // Read item failed
            break;
        }
        if (item.type == cbipNone) {
            break;
        }
    }

    free(writable_data);
    return 0;
}
