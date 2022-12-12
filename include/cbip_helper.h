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

#ifndef __CBIB_HELPER_H__
#define __CBIB_HELPER_H__

#include "cbip_encode.h"
#include "cbip_decode.h"

// cbipTrue or cbipFalse
#define CBIPH_TYPE_BOOLEAN 0xfe
// cbipInt or cbipNegativeInt
#define CBIPH_TYPE_INT 0xff

#define CBIPH_STATUS_FOUND       1
#define CBIPH_STATUS_NOT_FOUND   0
#define CBIPH_ERROR_INVALID      -1
#define CBIPH_ERROR_WRONG_TYPE   -2
#define CBIPH_ERROR_MISSING_TYPE -3

int cbiph_validate(uint8_t *buffer, uint32_t length);

// go to the next field, supports map & arrays
int cbiph_next_deep(cbipDecoder_t *decoder, cbipItem_t *item);

/**
 * Find the item associated with a key (integer or string) in a map
 *
 * If stringKey is not NULL, the keys of the map are all expected to be of type
 * cbipTextString and the function returns the item whose key matches.
 *
 * Otherwise, the keys of the map are all expected to be of type cbipInt or
 * cbipNegativeInt and the function returns the item whose key matches the
 * parameter key.
 *
 * Return:
 * * CBIPH_STATUS_FOUND if the item was found
 * * CBIPH_STATUS_NOT_FOUND = 0 if the item was not found
 * * CBIPH_ERROR_... < 0 if an error occurred
 */
int cbiph_get_map_item(cbipDecoder_t *decoder,
                       cbipItem_t *mapItem,
                       int key,
                       const char *stringKey,
                       cbipItem_t *keyItem,
                       uint8_t checkType);

int cbiph_get_map_key_str_bool(cbipDecoder_t *decoder,
                               cbipItem_t *mapItem,
                               const char *stringKey,
                               bool *value);

int cbiph_get_map_key_str_int(cbipDecoder_t *decoder,
                              cbipItem_t *mapItem,
                              const char *stringKey,
                              int *value);

int cbiph_get_map_key_int(cbipDecoder_t *decoder, cbipItem_t *mapItem, int key, int *value);

/**
 * Parse a map to search for an item data
 *
 * Return:
 * * CBIPH_STATUS_FOUND if the item was found
 * * CBIPH_STATUS_NOT_FOUND = 0 if the item was not found
 * * CBIPH_ERROR_... < 0 if an error occurred
 */
int cbiph_get_map_key_data(cbipDecoder_t *decoder,
                           cbipItem_t *mapItem,
                           int key,
                           const char *stringKey,
                           uint8_t **data,
                           uint32_t *dataLength,
                           uint8_t checkType);

/**
 * Parse a credential map
 *
 * Return:
 * * CBIPH_STATUS_FOUND if the "type" entry of the credential map is "public-key"
 * * CBIPH_STATUS_NOT_FOUND = 0 if the "type" entry is not "public-key"
 * * CBIPH_ERROR_INVALID < 0 if the CBOR data is invalid
 * * CBIPH_ERROR_MISSING_TYPE < 0 if the credential map does not have a "type" entry
 */
int cbiph_check_credential(cbipDecoder_t *decoder, cbipItem_t *mapItem);

int cbiph_get_map_key_item_offset(uint8_t *buffer, uint32_t length, int key);

int cbiph_map_cbor_error(int status);

#ifdef HAVE_CBOR_DEBUG
void cbiph_dump(uint8_t *buffer, uint32_t length);
#endif

static inline int cbiph_get_map_key_bytes(cbipDecoder_t *decoder,
                                          cbipItem_t *mapItem,
                                          int key,
                                          uint8_t **bytes,
                                          uint32_t *bytesLength) {
    return cbiph_get_map_key_data(decoder, mapItem, key, NULL, bytes, bytesLength, cbipByteString);
}

static inline int cbiph_get_map_key_text(cbipDecoder_t *decoder,
                                         cbipItem_t *mapItem,
                                         int key,
                                         char **text,
                                         uint32_t *textLength) {
    return cbiph_get_map_key_data(decoder,
                                  mapItem,
                                  key,
                                  NULL,
                                  (uint8_t **) text,
                                  textLength,
                                  cbipTextString);
}

static inline int cbiph_get_map_key_str_bytes(cbipDecoder_t *decoder,
                                              cbipItem_t *mapItem,
                                              const char *stringKey,
                                              uint8_t **bytes,
                                              uint32_t *bytesLength) {
    return cbiph_get_map_key_data(decoder,
                                  mapItem,
                                  0,
                                  stringKey,
                                  bytes,
                                  bytesLength,
                                  cbipByteString);
}

static inline int cbiph_get_map_key_str_text(cbipDecoder_t *decoder,
                                             cbipItem_t *mapItem,
                                             const char *stringKey,
                                             char **text,
                                             uint32_t *textLength) {
    return cbiph_get_map_key_data(decoder,
                                  mapItem,
                                  0,
                                  stringKey,
                                  (uint8_t **) text,
                                  textLength,
                                  cbipTextString);
}

#define GET_MAP_KEY_ITEM(decoder, map, key, item, type)                    \
    do {                                                                   \
        status = cbiph_get_map_item(decoder, map, key, NULL, &item, type); \
        if (status != CBIPH_STATUS_FOUND) {                                \
            PRINTF("Error fetching %d\n", key);                            \
            return cbiph_map_cbor_error(status);                           \
        }                                                                  \
    } while (0)

#define CHECK_MAP_KEY_ITEM_IS_VALID(decoder, map, key, item, type)         \
    do {                                                                   \
        status = cbiph_get_map_item(decoder, map, key, NULL, &item, type); \
        if (status < CBIPH_STATUS_NOT_FOUND) {                             \
            PRINTF("Error fetching %d\n", key);                            \
            return cbiph_map_cbor_error(status);                           \
        }                                                                  \
    } while (0)

#define CHECK_MAP_KEY_ITEM_EXIST(decoder, map, key, item, type)            \
    do {                                                                   \
        status = cbiph_get_map_item(decoder, map, key, NULL, &item, type); \
        if (status != CBIPH_STATUS_FOUND) {                                \
            PRINTF("Error fetching %d\n", key);                            \
            return cbiph_map_cbor_error(status);                           \
        }                                                                  \
    } while (0)

#define GET_MAP_STR_KEY_ITEM(decoder, map, key_str, item, type)             \
    do {                                                                    \
        status = cbiph_get_map_item(decoder, map, 0, key_str, &item, type); \
        if (status != CBIPH_STATUS_FOUND) {                                 \
            PRINTF("Error fetching %s\n", key_str);                         \
            return cbiph_map_cbor_error(status);                            \
        }                                                                   \
    } while (0)

#define CHECK_MAP_STR_KEY_ITEM_IS_VALID(decoder, map, key_str, item, type)  \
    do {                                                                    \
        status = cbiph_get_map_item(decoder, map, 0, key_str, &item, type); \
        if (status < CBIPH_STATUS_NOT_FOUND) {                              \
            PRINTF("Error fetching %s\n", key_str);                         \
            return cbiph_map_cbor_error(status);                            \
        }                                                                   \
    } while (0)

#define CHECK_MAP_STR_KEY_ITEM_EXIST(decoder, map, key_str, item, type)     \
    do {                                                                    \
        status = cbiph_get_map_item(decoder, map, 0, key_str, &item, type); \
        if (status != CBIPH_STATUS_FOUND) {                                 \
            PRINTF("Error fetching %s\n", key_str);                         \
            return cbiph_map_cbor_error(status);                            \
        }                                                                   \
    } while (0)

#endif
