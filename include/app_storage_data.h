#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

#define APP_STORAGE_VERSION_V1 1
#define APP_STORAGE_DATA_STRUCT_VERSION APP_STORAGE_VERSION_V1

#define APP_STORAGE_PROPERTIES (APP_STORAGE_PROP_SETTINGS | APP_STORAGE_PROP_DATA)

typedef struct {
#ifdef ENABLE_RK_CONFIG
    uint8_t rk_enabled;
#endif
    bool initialized;
} app_storage_data_t;
