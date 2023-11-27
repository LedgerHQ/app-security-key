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

#include "os.h"
#include "cx.h"

#include "config.h"
#include "globals.h"
#include "ctap2.h"
#include "rk_storage.h"
#include "crypto.h"

config_t const N_u2f_real;

static int derive_and_store_keys(uint32_t resetGeneration) {
    cx_err_t error;
    uint8_t key[64];
    uint8_t derivateKey[CX_SHA256_SIZE];
    uint32_t keyPath[3];
    uint8_t version;

    keyPath[1] = 0x80000000;
    keyPath[2] = resetGeneration;

    // privateKeySeed
    keyPath[0] = PRIVATE_KEY_SEED_PATH;
    error = os_derive_bip32_no_throw(CX_CURVE_SECP256R1, keyPath, 3, key, key + 32);
    if (error != CX_OK) {
        return -1;
    }
    if (memcmp(key, (uint8_t *) N_u2f.privateKeySeed, sizeof(N_u2f.privateKeySeed)) == 0) {
        // Keys are already initialized with the proper seed and resetGeneration
        return 0;
    }
    nvm_write((void *) N_u2f.privateKeySeed, (void *) key, sizeof(N_u2f.privateKeySeed));

    // wrappingKey
    keyPath[0] = WRAPPING_KEY_PATH;
    error = os_derive_bip32_no_throw(CX_CURVE_SECP256R1, keyPath, 3, key, key + 32);
    if (error != CX_OK) {
        return -1;
    }

    // wrappingKeyU2F: aes_key = SHA256(VERSION || wrappingKeys)
    version = CREDENTIAL_VERSION_U2F;
    crypto_compute_sha256(&version, sizeof(version), key, sizeof(key), derivateKey);
    nvm_write((void *) N_u2f.wrappingKeyU2F, (void *) derivateKey, sizeof(N_u2f.wrappingKeyU2F));

    // wrappingKeyCTAP2: aes_key = SHA256(VERSION || wrappingKeys)
    version = CREDENTIAL_VERSION_CTAP2;
    crypto_compute_sha256(&version, sizeof(version), key, sizeof(key), derivateKey);
    nvm_write((void *) N_u2f.wrappingKeyCTAP2,
              (void *) derivateKey,
              sizeof(N_u2f.wrappingKeyCTAP2));

    return 0;
}

int config_init(void) {
    int ret = 0;
    uint32_t tmp32;
    uint8_t tmp8;
    if (N_u2f.initialized != 1) {
#ifdef HAVE_COUNTER_MARKER
        tmp32 = 0xF1D0C001;
#else
        tmp32 = 1;
#endif
        nvm_write((void *) &N_u2f.authentificationCounter, (void *) &tmp32, sizeof(uint32_t));

        tmp32 = 0;
        nvm_write((void *) &N_u2f.resetGeneration, (void *) &tmp32, sizeof(uint32_t));

        // Initialize keys derived from seed
        derive_and_store_keys(N_u2f.resetGeneration);

        tmp8 = 0;
        nvm_write((void *) &N_u2f.pinSet, (void *) &tmp8, sizeof(uint8_t));

#ifdef HAVE_RK_SUPPORT_SETTING
        // Initialize rk_enable value: Disabled by default
        tmp8 = 0;
        nvm_write((void *) &N_u2f.rk_enabled, (void *) &tmp8, sizeof(uint8_t));
#endif

        tmp8 = 1;
        nvm_write((void *) &N_u2f.initialized, (void *) &tmp8, sizeof(uint8_t));
    } else {
        // Check that the seed did not change - if it did, overwrite the keys
        ret = derive_and_store_keys(N_u2f.resetGeneration);
    }
    return ret;
}

uint8_t config_increase_and_get_authentification_counter(uint8_t *buffer) {
    uint32_t counter = N_u2f.authentificationCounter;
    // Increase the counter by a random value according to WebAuthN privacy requirements
    // Draw a number between 1 and 5 (included), in a uniform way.
    counter += cx_rng_u32_range_func(1, 6, cx_rng_u32);
    nvm_write((void *) &N_u2f.authentificationCounter, &counter, sizeof(uint32_t));
    buffer[0] = ((counter >> 24) & 0xff);
    buffer[1] = ((counter >> 16) & 0xff);
    buffer[2] = ((counter >> 8) & 0xff);
    buffer[3] = (counter & 0xff);
    return 4;
}

void config_process_ctap2_reset(void) {
#ifndef HAVE_NO_RESET_GENERATION_INCREMENT
    uint32_t resetGeneration = N_u2f.resetGeneration + 1;

    nvm_write((void *) &N_u2f.resetGeneration, (void *) &resetGeneration, sizeof(uint32_t));

    // Update keys derived from seed
    derive_and_store_keys(N_u2f.resetGeneration);
#endif

    uint8_t pinSet = 0;
    nvm_write((void *) &N_u2f.pinSet, (void *) &pinSet, sizeof(uint8_t));

    ctap2_client_pin_reset_ctx();
    rk_storage_erase_all();
}

#define CTAP2_PIN_RETRIES 8

void config_set_ctap2_pin(uint8_t *pin) {
    uint8_t tmp;
    nvm_write((void *) &N_u2f.pin, (void *) pin, sizeof(N_u2f.pin));
    tmp = CTAP2_PIN_RETRIES;
    nvm_write((void *) &N_u2f.pinRetries, (void *) &tmp, sizeof(uint8_t));
    tmp = 1;
    nvm_write((void *) &N_u2f.pinSet, (void *) &tmp, sizeof(uint8_t));
}

void config_decrease_ctap2_pin_retry_counter(void) {
    uint8_t tmp = N_u2f.pinRetries;
    if (tmp != 0) {
        tmp--;
    }
    nvm_write((void *) &N_u2f.pinRetries, (void *) &tmp, sizeof(uint8_t));
}

void config_reset_ctap2_pin_retry_counter(void) {
    uint8_t tmp = CTAP2_PIN_RETRIES;
    nvm_write((void *) &N_u2f.pinRetries, (void *) &tmp, sizeof(uint8_t));
}

#ifdef HAVE_RK_SUPPORT_SETTING
void config_set_rk_enabled(bool enabled) {
    uint8_t tmp8 = enabled ? 1 : 0;
    nvm_write((void *) &N_u2f.rk_enabled, (void *) &tmp8, sizeof(uint8_t));
}

bool config_get_rk_enabled(void) {
    return N_u2f.rk_enabled == 1;
}
#endif
