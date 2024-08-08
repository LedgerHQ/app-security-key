#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "config.h"
#include "rk_storage.h"

#define APP_STORAGE_VERSION_V1 1
#define APP_STORAGE_DATA_STRUCT_VERSION APP_STORAGE_VERSION_V1

#define APP_STORAGE_PROPERTIES (APP_STORAGE_PROP_SETTINGS | APP_STORAGE_PROP_DATA)

typedef struct {
    bool initialized;
#ifdef ENABLE_RK_CONFIG
    uint8_t rk_enabled;
    rk_storage_t rk;
#endif
    config_t config;
} app_storage_data_t;
