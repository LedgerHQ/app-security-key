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

#ifndef __RK_STORAGE_H__
#define __RK_STORAGE_H__

#define RK_STORAGE_FULL -2
#define RK_NOT_FOUND    0

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

#endif
