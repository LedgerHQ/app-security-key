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

#include "cbip_helper.h"
#include "ctap2.h"

int cbiph_validate(uint8_t *buffer, uint32_t length) {
    cbipDecoder_t decoder;
    cbipItem_t item;
    int status;
    bool first = true;
    uint32_t extraParse = 0;

    if (length == 0) {
        return 0;
    }
    status = cbip_decoder_init(&decoder, buffer, length);
    if (status < 0) {
        return status;
    }
    for (;;) {
        if (first) {
            status = cbip_first(&decoder, &item);
            first = false;
        } else {
            status = cbip_next(&decoder, &item);
        }
        if (status < 0) {
            return status;
        }
        if (extraParse != 0) {
            extraParse--;
        }
        switch (item.type) {
            case cbipArray:
                extraParse += item.value;
                break;
            case cbipMap:
                extraParse += 2 * item.value;
                break;
            default:
                break;
        }
        if (item.type == cbipNone) {
            if (extraParse != 0) {
                PRINTF("%d cbor items left to parse when validating\n", extraParse);
                return -1;
            }
            break;
        }
    }

    return 0;
}

#if 0
int cbiph_validate(uint8_t *buffer, uint32_t length) {
	cbipDecoder_t decoder;
	cbipItem_t item;
	int status;
	bool first = true;
	uint8_t depth[4];
	int currentDepth = -1;

	if (length == 0) {
		return 0;
	}
	status = cbip_decoder_init(&decoder, buffer, length);
	if (status < 0) {
		return status;
	}
	for (;;) {
		if (first) {
			status = cbip_first(&decoder, &item);		
			first = false;
		}
		else {
			status = cbip_next(&decoder, &item);
		}
		if (status < 0) {
			return status;
		}
		if (!first && (currentDepth >= 0)) {
			depth[currentDepth]--;
			if (depth[currentDepth] == 0) {
				currentDepth--;
			}
		}
		switch (item.type) {
			case cbipArray:
				currentDepth++;
				depth[currentDepth] = item.value;
				break;
			case cbipMap:
				currentDepth++;
				depth[currentDepth] = 2 * item.value;
				break;
			default:
				break;
		}
		if (item.type == cbipNone) {
			if (currentDepth >= 0) {
				PRINTF("Invalid depth at end\n", currentDepth);
				return -1;
			}
			break;
		}
	}	

	return 0;
}
#endif

#if 0
int cbiph_next_deep(cbipDecoder_t *decoder, cbipItem_t *item) {
	uint8_t depth[4];
	int currentDepth = -1;
	int status;
	do {
		PRINTF("next_deep pre type %d currentDepth %d\n", item->type, currentDepth);
		if (currentDepth >= 0) {
			PRINTF("depth %d\n", depth[currentDepth]);
		}
		if (currentDepth >= 0) {
			depth[currentDepth]--;
			if (depth[currentDepth] == 0) {
				currentDepth--;
			}
		}						
		switch (item->type) {
			case cbipArray:
				currentDepth++;
				depth[currentDepth] = item->value;
				break;
			case cbipMap:
				currentDepth++;
				depth[currentDepth] = 2 * item->value;
				break;
			default:
				break;
		}
		if (currentDepth >= 0) {
			status = cbip_next(decoder, item);
			if (status < 0) {
				return status;
			}
		}
	}
	while (currentDepth >= 0);
	PRINTF("next_deep end\n");
	status = cbip_next(decoder, item);
	if (status < 0) {
		return status;
	}
	return 0;
}
#endif

int cbiph_next_deep(cbipDecoder_t *decoder, cbipItem_t *item) {
    uint32_t extraParse = 0;
    int status;
    do {
        if (extraParse > 0) {
            extraParse--;
        }
        switch (item->type) {
            case cbipArray:
                extraParse += item->value;
                break;
            case cbipMap:
                extraParse += 2 * item->value;
                break;
            default:
                break;
        }
        if (extraParse > 0) {
            status = cbip_next(decoder, item);
            if (status < 0) {
                return status;
            }
        }
    } while (extraParse > 0);
    status = cbip_next(decoder, item);
    if (status < 0) {
        return status;
    }
    return 0;
}

int cbiph_get_map_item(cbipDecoder_t *decoder,
                       cbipItem_t *mapItem,
                       int key,
                       const char *stringKey,
                       cbipItem_t *keyItem,
                       uint8_t checkType) {
    int status;
    uint32_t i;
    uint32_t keyLen = (stringKey != NULL ? strlen(stringKey) : 0);
    if (mapItem->type != cbipMap) {
        PRINTF("cbiph_get_map_key : not a map\n");
        return CBIPH_ERROR_WRONG_TYPE;
    }
    memmove(keyItem, mapItem, sizeof(cbipItem_t));
    status = cbip_next(decoder, keyItem);  // get key
    if (status < 0) {
        return status;
    }
    for (i = 0; i < mapItem->value; i++) {
        if ((stringKey == NULL) &&
            ((keyItem->type != cbipInt) && (keyItem->type != cbipNegativeInt))) {
            PRINTF("cbiph_get_map_key : unexpected key type %d\n", keyItem->type);
            return CBIPH_ERROR_WRONG_TYPE;
        } else if ((stringKey != NULL) && (keyItem->type != cbipTextString)) {
            PRINTF("cbiph_get_map_key : unexpected key type %d\n", keyItem->type);
            return CBIPH_ERROR_WRONG_TYPE;
        }
        if (((stringKey == NULL) && (cbip_get_int(keyItem) == key)) ||
            ((stringKey != NULL) && (keyItem->value == keyLen) &&
             (memcmp(decoder->buffer + keyItem->offset + keyItem->headerLength,
                     stringKey,
                     keyLen) == 0))) {
            status = cbip_next(decoder, keyItem);  // get value
            if (status < 0) {
                return status;
            }
            switch (checkType) {
                case cbipNone:
                    break;
                case CBIPH_TYPE_BOOLEAN:
                    if ((keyItem->type != cbipTrue) && (keyItem->type != cbipFalse)) {
                        PRINTF("cbiph_get_map_key : expected boolean type, got %d\n",
                               keyItem->type);
                        return CBIPH_ERROR_WRONG_TYPE;
                    }
                    break;
                case CBIPH_TYPE_INT:
                    if ((keyItem->type != cbipInt) && (keyItem->type != cbipNegativeInt)) {
                        PRINTF("cbiph_get_map_key : expected int type, got %d\n", keyItem->type);
                        return CBIPH_ERROR_WRONG_TYPE;
                    }
                    break;
                default:
                    if (keyItem->type != checkType) {
                        PRINTF("cbiph_get_map_key : expected %d type, got %d\n",
                               checkType,
                               keyItem->type);
                        return CBIPH_ERROR_WRONG_TYPE;
                    }
                    break;
            }
            return CBIPH_STATUS_FOUND;
        }
        status = cbip_next(decoder, keyItem);  // get value
        if (status < 0) {
            return status;
        }
        status = cbiph_next_deep(decoder, keyItem);  // skip value
        if (status < 0) {
            return status;
        }
    }
    // PRINTF("Key not found\n");
    return CBIPH_STATUS_NOT_FOUND;
}

int cbiph_get_map_key_str_bool(cbipDecoder_t *decoder,
                               cbipItem_t *mapItem,
                               const char *stringKey,
                               bool *value) {
    int status;
    cbipItem_t item;

    status = cbiph_get_map_item(decoder, mapItem, 0, stringKey, &item, CBIPH_TYPE_BOOLEAN);
    if (status != CBIPH_STATUS_FOUND) {
        return status;
    }
    switch (item.type) {
        case cbipTrue:
            *value = true;
            break;
        case cbipFalse:
            *value = false;
            break;
        default:
            return CBIPH_ERROR_INVALID;
    }
    return CBIPH_STATUS_FOUND;
}

int cbiph_get_map_key_int(cbipDecoder_t *decoder, cbipItem_t *mapItem, int key, int *value) {
    int status;
    cbipItem_t item;

    status = cbiph_get_map_item(decoder, mapItem, key, NULL, &item, CBIPH_TYPE_INT);
    if (status == CBIPH_STATUS_FOUND) {
        *value = cbip_get_int(&item);
    }

    return status;
}

int cbiph_get_map_key_str_int(cbipDecoder_t *decoder,
                              cbipItem_t *mapItem,
                              const char *stringKey,
                              int *value) {
    int status;
    cbipItem_t item;

    status = cbiph_get_map_item(decoder, mapItem, 0, stringKey, &item, CBIPH_TYPE_INT);
    if (status == CBIPH_STATUS_FOUND) {
        *value = cbip_get_int(&item);
    }

    return status;
}

int cbiph_get_map_key_data(cbipDecoder_t *decoder,
                           cbipItem_t *mapItem,
                           int key,
                           const char *stringKey,
                           uint8_t **data,
                           uint32_t *dataLength,
                           uint8_t checkType) {
    int status;
    cbipItem_t tmpItem;

    if (stringKey != NULL) {
        status = cbiph_get_map_item(decoder, mapItem, 0, stringKey, &tmpItem, checkType);
    } else {
        status = cbiph_get_map_item(decoder, mapItem, key, NULL, &tmpItem, checkType);
    }
    if (status != CBIPH_STATUS_FOUND) {
        return status;
    }

    if (data != NULL) {
        *data = decoder->buffer + tmpItem.offset + tmpItem.headerLength;
    }
    if (dataLength != NULL) {
        *dataLength = tmpItem.value;
    }

    return CBIPH_STATUS_FOUND;
}

int cbiph_check_credential(cbipDecoder_t *decoder, cbipItem_t *mapItem) {
    cbipItem_t tmpItem;
    int status;
    status = cbiph_get_map_item(decoder,
                                mapItem,
                                0,
                                CREDENTIAL_DESCRIPTOR_TYPE,
                                &tmpItem,
                                cbipTextString);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("cbiph_check_credential : invalid type\n");
        return (status == 0) ? CBIPH_ERROR_MISSING_TYPE : CBIPH_ERROR_INVALID;
    }
    if (tmpItem.value != CREDENTIAL_TYPE_PUBLIC_KEY_LENGTH) {
        PRINTF("cbiph_check_credential : invalid length %u\n", tmpItem.value);
        return CBIPH_STATUS_NOT_FOUND;
    }
    if (memcmp(decoder->buffer + tmpItem.offset + tmpItem.headerLength,
               CREDENTIAL_TYPE_PUBLIC_KEY,
               CREDENTIAL_TYPE_PUBLIC_KEY_LENGTH) != 0) {
        PRINTF("cbiph_check_credential : not a public key\n");
        return CBIPH_STATUS_NOT_FOUND;
    }
    return 1;
}

int cbiph_get_map_key_item_offset(uint8_t *buffer, uint32_t length, int key) {
    cbipDecoder_t decoder;
    cbipItem_t tmpItem, mapItem;
    int status;

    cbip_decoder_init(&decoder, buffer, length);
    cbip_first(&decoder, &mapItem);
    status = cbiph_get_map_item(&decoder, &mapItem, key, NULL, &tmpItem, cbipNone);
    if (status != CBIPH_STATUS_FOUND) {
        return status;
    }

    return tmpItem.offset;
}

int cbiph_map_cbor_error(int status) {
    switch (status) {
        case CBIPH_STATUS_NOT_FOUND:
            return ERROR_MISSING_PARAMETER;
        case CBIPH_ERROR_WRONG_TYPE:
            return ERROR_CBOR_UNEXPECTED_TYPE;
        case CBIPH_ERROR_MISSING_TYPE:
            return ERROR_MISSING_PARAMETER;
        default:
            return ERROR_INVALID_CBOR;
    }
}

#ifdef HAVE_CBOR_DEBUG

void display_item(uint8_t *buffer, cbipItem_t *item) {
    switch (item->type) {
        case cbipInt:
            PRINTF("Int %d\n", item->value);
            break;
        case cbipNegativeInt:
            PRINTF("Negative int %d\n", -1 - item->value);
            break;
        case cbipByteString: {
            PRINTF("Bytestring %.*H\n", item->value, buffer + item->offset + item->headerLength);
            break;
        }
        case cbipTextString: {
            PRINTF("String %.*s\n", item->value, buffer + item->offset + item->headerLength);
            break;
        }
        case cbipArray:
            PRINTF("Array of %d elements\n", item->value);
            break;
        case cbipMap:
            PRINTF("Map of %d elements\n", item->value);
            break;
        case cbipTrue:
            PRINTF("True\n");
            break;
        case cbipFalse:
            PRINTF("False\n");
            break;
        default:
            break;
    }
}

void cbiph_dump(uint8_t *buffer, uint32_t length) {
    cbipDecoder_t decoder;
    cbipItem_t item;
    int status;
    bool first = true;

    if (length == 0) {
        return;
    }
    status = cbip_decoder_init(&decoder, buffer, length);
    if (status < 0) {
        PRINTF("cbiph_dump failed to initialize decoder\n");
        return;
    }
    for (;;) {
        int startOffset = decoder.offset;
        if (first) {
            status = cbip_first(&decoder, &item);
            first = false;
        } else {
            status = cbip_next(&decoder, &item);
        }
        if (status < 0) {
            PRINTF("cbiph_dump error offset %d\n", startOffset);
            break;
        }
        if (item.type == cbipNone) {
            break;
        }
        display_item(buffer, &item);
    }
}
#endif
