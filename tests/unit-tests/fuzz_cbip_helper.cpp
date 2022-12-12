/**
 * Fuzz helper functions for CBIP in src/cbip_helper.c
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

extern "C" {
#include "cbip_decode.h"
#include "cbip_helper.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *writable_data;
    int status;
    cbipDecoder_t decoder;
    cbipItem_t item, item2;
    bool boolValue;

    writable_data = (uint8_t *)malloc(size);
    if (!writable_data)
        return 0;
    memcpy(writable_data, data, size);

    if (cbiph_validate(writable_data, size) < 0) {
        free(writable_data);
        return 0;
    }

    cbiph_dump(writable_data, size);

    status = cbip_decoder_init(&decoder, writable_data, size);
    assert(status == 0);
    status = cbip_first(&decoder, &item);
    if (status >= 0 && item.type == cbipMap) {
        // If reading a map, call some helpers
        cbiph_get_map_item(&decoder, &item, 1, NULL, &item2, cbipTextString);
        cbiph_get_map_key_str_bool(&decoder, &item, "up", &boolValue);
        cbiph_check_credential(&decoder, &item);
    }
    free(writable_data);
    return 0;
}
