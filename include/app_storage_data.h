#pragma once

#include <app_storage.h>

#include "config.h"
#include "rk_storage.h"

#define APP_STORAGE_DATA_STRUCT_CURRENT_VERSION 1

#define APP_STORAGE_PROPERTIES (APP_STORAGE_PROP_SETTINGS | APP_STORAGE_PROP_DATA)

typedef struct {
    uint32_t version;  // This structure version (for future evolution)
    config_t config;
#ifdef ENABLE_RK_CONFIG
    rk_storage_t rk;
#endif
} app_storage_data_t;
CCASSERT("The application storage size requested in Makefile is not sufficient",
         sizeof(app_storage_data_t) <= APP_STORAGE_SIZE);

/* RAM representation of the config part of the app data storage */
extern config_t config;

#define APP_STORAGE_WRITE_ALL(src_buf) app_storage_pwrite(src_buf, sizeof(app_storage_data_t), 0)

#define APP_STORAGE_WRITE_F(field, src_buf)                       \
    app_storage_pwrite(src_buf,                                   \
                       sizeof(((app_storage_data_t *) 0)->field), \
                       offsetof(app_storage_data_t, field))

#define APP_STORAGE_WRITE_F_WITH_SIZE(field, src_buf, size) \
    app_storage_pwrite(src_buf, size, offsetof(app_storage_data_t, field))

#define APP_STORAGE_READ_ALL(dst_buf) app_storage_pread(dst_buf, sizeof(app_storage_data_t), 0)

#define APP_STORAGE_READ_F(field, dst_buf)                       \
    app_storage_pread(dst_buf,                                   \
                      sizeof(((app_storage_data_t *) 0)->field), \
                      offsetof(app_storage_data_t, field))

#define APP_STORAGE_READ_F_WITH_SIZE(field, dst_buf, size) \
    app_storage_pread(dst_buf, size, offsetof(app_storage_data_t, field))
