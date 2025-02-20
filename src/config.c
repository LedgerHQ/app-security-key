/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2022-2025 Ledger
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

#include "os.h"
#include "cx.h"

#include "app_storage_data.h"
#include "config.h"
#include "globals.h"
#include "ctap2.h"
#include "rk_storage.h"
#include "crypto.h"

config_t config;

static int derive_and_store_keys(void) {
    cx_err_t error;
    uint8_t key[64];
    uint8_t derivateKey[CX_SHA256_SIZE];
    uint32_t keyPath[3];
    uint8_t version;

    keyPath[1] = 0x80000000;
    keyPath[2] = config.resetGeneration;

    // privateKeySeed
    keyPath[0] = PRIVATE_KEY_SEED_PATH;
    error = os_derive_bip32_no_throw(CX_CURVE_SECP256R1, keyPath, 3, key, key + 32);
    if (error != CX_OK) {
        return -1;
    }
    if (memcmp(key, (uint8_t *) &config.privateKeySeed, sizeof(config.privateKeySeed)) == 0) {
        // Keys are already initialized with the proper seed and resetGeneration
        return 0;
    }
    memcpy((void *) &config.privateKeySeed, (void *) key, sizeof(config.privateKeySeed));

    // wrappingKey
    keyPath[0] = WRAPPING_KEY_PATH;
    error = os_derive_bip32_no_throw(CX_CURVE_SECP256R1, keyPath, 3, key, key + 32);
    if (error != CX_OK) {
        return -1;
    }

    // wrappingKeyU2F: aes_key = SHA256(VERSION || wrappingKeys)
    version = CREDENTIAL_VERSION_U2F;
    crypto_compute_sha256(&version, sizeof(version), key, sizeof(key), derivateKey);
    memcpy((void *) &config.wrappingKeyU2F, (void *) derivateKey, sizeof(config.wrappingKeyU2F));

    // wrappingKeyCTAP2: aes_key = SHA256(VERSION || wrappingKeys)
    version = CREDENTIAL_VERSION_CTAP2;
    crypto_compute_sha256(&version, sizeof(version), key, sizeof(key), derivateKey);
    memcpy((void *) &config.wrappingKeyCTAP2,
           (void *) derivateKey,
           sizeof(config.wrappingKeyCTAP2));

    return 1;
}

int config_init(void) {
    int ret = 0;
    APP_STORAGE_READ_F(config, &config);

    if (config.initialized != 1) {
#ifdef HAVE_COUNTER_MARKER
        config.authentificationCounter = 0xF1D0C001;
#else
        config.authentificationCounter = 1;
#endif
        config.resetGeneration = 0;

        // Initialize keys derived from seed
        if (derive_and_store_keys() == -1) return ret;

        config.pinSet = 0;

#ifdef ENABLE_RK_CONFIG
        // Initialize rk_enable value: Disabled by default
        config.rk_enabled = 0;
#endif
        config.initialized = 1;

        APP_STORAGE_WRITE_F(config, (void *) &config);

    } else {
        // Check that the seed did not change - if it did, overwrite the keys
        ret = derive_and_store_keys();
        if (ret == 1) {
            APP_STORAGE_WRITE_F(config, (void *) &config);
            ret = 0;
        }
    }
    app_storage_increment_data_version();
    return ret;
}

uint8_t config_increase_and_get_authentification_counter(uint8_t *buffer) {
    // Increase the counter by a random value according to WebAuthN privacy requirements
    // Draw a number between 1 and 5 (included), in a uniform way.
    config.authentificationCounter += cx_rng_u32_range_func(1, 6, cx_rng_u32);
    APP_STORAGE_WRITE_F(config.authentificationCounter, (void *) &config.authentificationCounter);
    app_storage_increment_data_version();
    buffer[0] = ((config.authentificationCounter >> 24) & 0xff);
    buffer[1] = ((config.authentificationCounter >> 16) & 0xff);
    buffer[2] = ((config.authentificationCounter >> 8) & 0xff);
    buffer[3] = (config.authentificationCounter & 0xff);
    return 4;
}

void config_process_ctap2_reset(void) {
#ifndef HAVE_NO_RESET_GENERATION_INCREMENT
    config.resetGeneration += 1;

    // Update keys derived from seed
    derive_and_store_keys();
#endif

    config.pinSet = 0;
    APP_STORAGE_WRITE_F(config, (void *) &config);
    app_storage_increment_data_version();

    ctap2_client_pin_reset_ctx();
    rk_storage_erase_all();
}

#define CTAP2_PIN_RETRIES 8

void config_set_ctap2_pin(uint8_t *pin) {
    memcpy((void *) &config.pin, (void *) pin, sizeof(config.pin));
    config.pinRetries = CTAP2_PIN_RETRIES;
    config.pinSet = 1;
    APP_STORAGE_WRITE_F(config, (void *) &config);
    app_storage_increment_data_version();
}

void config_decrease_ctap2_pin_retry_counter(void) {
    if (config.pinRetries != 0) {
        config.pinRetries--;
        APP_STORAGE_WRITE_F(config.pinRetries, (void *) &config.pinRetries);
        app_storage_increment_data_version();
    }
}

void config_reset_ctap2_pin_retry_counter(void) {
    config.pinRetries = CTAP2_PIN_RETRIES;
    APP_STORAGE_WRITE_F(config.pinRetries, (void *) &config.pinRetries);
    app_storage_increment_data_version();
}

#ifdef ENABLE_RK_CONFIG
void config_set_rk_enabled(bool enabled) {
    config.rk_enabled = enabled ? 1 : 0;
    APP_STORAGE_WRITE_F(config.rk_enabled, (void *) &config.rk_enabled);
    app_storage_increment_data_version();
}

bool config_get_rk_enabled(void) {
    return config.rk_enabled == 1;
}
#endif
