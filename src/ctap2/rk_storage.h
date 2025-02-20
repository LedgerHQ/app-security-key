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

#pragma once

#include "ctap2.h"
#include "credential.h"

#define RK_STORAGE_FULL -2
#define RK_NOT_FOUND    0

typedef struct __attribute__((__packed__)) rk_header_s {
    uint8_t rpIdHash[RP_ID_HASH_SIZE];
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
    uint8_t credentialLen;
    uint8_t unused;
    uint16_t idx;  // used as "age" (increases only)
} rk_header_t;

#define SLOT_SIZE 256
// Currently 24 on all devices, except NanoS which only allows 8
#define CREDENTIAL_MAX_NUMBER (RK_SIZE / SLOT_SIZE)
#define CREDENTIAL_MAX_SIZE   (SLOT_SIZE - sizeof(rk_header_t))
CCASSERT("credentialLen should fit in an uint8_t", CREDENTIAL_MAX_SIZE <= 0xFF);

typedef struct __attribute__((__packed__)) rk_slot_s {
    rk_header_t header;
    uint8_t credential[CREDENTIAL_MAX_SIZE];
} rk_slot_t;

CCASSERT("Slot size alignment", SLOT_SIZE == sizeof(rk_slot_t));

#define UNUSED_IDX_VALUE     0  // default value
#define MAX_IDX_VALUE        0xFFFF
#define SLOT_IS_USED(slot)   (slot.header.idx != UNUSED_IDX_VALUE)
#define SLOT_IS_UNUSED(slot) (slot.header.idx == UNUSED_IDX_VALUE)

typedef struct rk_storage_s {
    rk_slot_t slot[CREDENTIAL_MAX_NUMBER];
} rk_storage_t;

/**
 * Initialise the rk storage
 */
void rk_storage_init(void);

/**
 * Erase all credentials from the rk storage
 */
void rk_storage_erase_all(void);

/**
 * Store a credential in the rk storage
 */
int rk_storage_store(const uint8_t *rpIdHash,
                     const uint8_t *nonce,
                     const uint8_t *credential,
                     uint32_t credentialLen);

/**
 * Count stored credentials associated to a rpIdHash
 */
int rk_storage_count(const uint8_t *rpIdHash);

/**
 * Find the most recent credential associated to a rpIdHash.
 * A minimum age constraint can be added so that one can iterate on all
 * credentials associated to a rpIdHash from the most recent to the oldest.
 */
int rk_storage_find_youngest(const uint8_t *rpIdHash,
                             uint16_t *minAge,
                             uint8_t **nonce,
                             uint8_t **credential,
                             uint32_t *credentialLen);

/**
 * Find a credential associated to a rpIdHash and nonce.
 */
int rk_storage_find_account(const uint8_t *rpIdHash,
                            const uint8_t *nonce,
                            uint8_t **credential,
                            uint32_t *credentialLen);

/**
 * Erase a credential associated to a rpIdHash and userId.
 */
int rk_storage_erase_account(const uint8_t *rpIdHash, const uint8_t *userId, uint32_t userIdLen);

/*
 * Initiates an internal list containing the indexes of the existing RKs matching the given rpID.
 *
 * Returns the number of matching RKs (size of the list)
 */
uint8_t rk_build_RKList_from_rpID(const uint8_t *rpIdHash);

/*
 * From the RK list initiated by `build_RKList_from_rpID`, fills the first RK's information
 * into the given arguments, then removes it from the list.
 */
int rk_next_credential_from_RKList(uint16_t *idx,
                                   uint8_t **nonce,
                                   uint8_t **credential,
                                   uint32_t *credentialLen);
