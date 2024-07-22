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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "os.h"

#define WRAPPING_KEY_PATH     0x80575241  // "WRA".encode("ascii").hex()
#define PRIVATE_KEY_SEED_PATH 0x80504b53  // "PKS".encode("ascii").hex()

typedef struct config_t {
    uint32_t authentificationCounter;
    uint8_t initialized;
    uint8_t wrappingKeyU2F[32];
    uint8_t wrappingKeyCTAP2[32];
    uint8_t privateKeySeed[64];
    uint32_t resetGeneration;
    uint8_t pin[16];
    uint8_t pinSet;
    uint8_t pinRetries;
#ifdef ENABLE_RK_CONFIG
    uint8_t rk_enabled;
#endif
} config_t;

extern config_t const N_u2f_real;

#define N_u2f (*(volatile config_t *) PIC(&N_u2f_real))

int config_init(void);

uint8_t config_increase_and_get_authentification_counter(uint8_t *buffer);

void config_process_ctap2_reset(void);
void config_set_ctap2_pin(uint8_t *pin);
void config_decrease_ctap2_pin_retry_counter(void);
void config_reset_ctap2_pin_retry_counter(void);

#ifdef ENABLE_RK_CONFIG
void config_set_rk_enabled(bool enabled);
bool config_get_rk_enabled(void);
#endif

#endif
