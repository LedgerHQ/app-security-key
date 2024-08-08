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

#include "os.h"
#include "os_utils.h"
#include "app_storage.h"

#include "rk_storage.h"
#include "crypto.h"

static int nextIdx = 0;

static rk_slot_t *get_slot_addr(uint8_t rkSlotIdx) {
    if (rkSlotIdx >= CREDENTIAL_MAX_NUMBER) {
        return NULL;
    }

    return (rk_slot_t *) &N_app_storage.data.rk.rk[rkSlotIdx];
}

static rk_slot_t *find_free_slot(void) {
    rk_slot_t *slot;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        slot = get_slot_addr(i);
        if ((slot == NULL) || SLOT_IS_USED(slot)) {
            continue;
        }
        return slot;
    }
    PRINTF("No free slot found\n");
    return NULL;
}

static void erase_slot(uint8_t rkSlotIdx) {
    rk_slot_t *slot = get_slot_addr(rkSlotIdx);
    if (slot == NULL) {
        return;
    }

    if (SLOT_IS_USED(slot)) {
        rk_header_t header;
        header.idx = UNUSED_IDX_VALUE;
        nvm_write(&slot->header, (uint8_t *) &header, sizeof(header));
        app_storage_set_data_version(app_storage_get_data_version() + 1);
    }
}

void rk_storage_init(void) {
    rk_slot_t *slot;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        slot = get_slot_addr(i);
        if ((slot == NULL) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        nextIdx = MAX(slot->header.idx, nextIdx);
    }
    nextIdx += 1;
    PRINTF("rk detected nextIdx %d\n", nextIdx);
}

void rk_storage_erase_all(void) {
    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        erase_slot(i);
    }
    nextIdx = 1;
}

int rk_storage_store(const uint8_t *rpIdHash,
                     const uint8_t *nonce,
                     const uint8_t *credential,
                     uint32_t credentialLen) {
    rk_slot_t *slot;
    rk_header_t header;

    slot = find_free_slot();
    if (slot == NULL) {
        return RK_STORAGE_FULL;
    }

    if (nextIdx == MAX_IDX_VALUE) {
        return -1;
    }

    if (credentialLen > CREDENTIAL_MAX_SIZE) {
        return -1;
    }

    memmove(header.rpIdHash, rpIdHash, sizeof(header.rpIdHash));
    memmove(header.nonce, nonce, sizeof(header.nonce));
    header.credentialLen = credentialLen;
    header.unused = 0;
    header.idx = nextIdx;
    nextIdx += 1;
    nvm_write(&slot->header, (uint8_t *) &header, sizeof(header));
    nvm_write(&slot->credential, (uint8_t *) credential, credentialLen);
    app_storage_set_data_version(app_storage_get_data_version() + 1);
    PRINTF("rk_storage_store idx %d size %d\n", header.idx, credentialLen);

    return 0;
}

int rk_storage_count(const uint8_t *rpIdHash) {
    rk_slot_t *slot;
    uint32_t count = 0;
    uint32_t idx = 0;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        slot = get_slot_addr(i);
        if ((slot == NULL) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot->header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        count += 1;
        idx = MAX(slot->header.idx, idx);
    }
    PRINTF("rk_storage_count %d newest %d\n", count, idx);
    return count;
}

int rk_storage_find_youngest(const uint8_t *rpIdHash,
                             uint16_t *requestMinAge,
                             uint8_t **nonce,
                             uint8_t **credential,
                             uint32_t *credentialLen) {
    rk_slot_t *slot;
    uint16_t slotAge;
    bool found = false;
    uint16_t foundMinAge = 0xFFFF;  // start with maximum age

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        slot = get_slot_addr(i);
        if ((slot == NULL) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot->header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        // Credential idx is based on an incrementing counter.
        // Basically, the more recent credential is the one with the greatest idx.
        // Therefore, the "age" of the credential can be considered as the opposite of
        // the idx. With an offset of MAX_IDX_VALUE to stay with positive ages.
        slotAge = MAX_IDX_VALUE - slot->header.idx;
        if ((slotAge < foundMinAge) && ((requestMinAge == NULL) || (slotAge > *requestMinAge))) {
            found = true;
            foundMinAge = slotAge;
            if (nonce != NULL) {
                *nonce = slot->header.nonce;
            }
            if (credential != NULL) {
                *credential = slot->credential;
            }
            if (credentialLen != NULL) {
                *credentialLen = slot->header.credentialLen;
            }
        }
    }

    if (!found) {
        PRINTF("Not found\n");
        return RK_NOT_FOUND;
    }

    if (requestMinAge != NULL) {
        *requestMinAge = foundMinAge;
    }
    return 1;
}

int rk_storage_find_account(const uint8_t *rpIdHash,
                            const uint8_t *nonce,
                            uint8_t **credential,
                            uint32_t *credentialLen) {
    rk_slot_t *slot;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        slot = get_slot_addr(i);
        if ((slot == NULL) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot->header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        if (crypto_compare(slot->header.nonce, nonce, CREDENTIAL_NONCE_SIZE)) {
            if (credential != NULL) {
                *credential = slot->credential;
            }
            if (credentialLen != NULL) {
                *credentialLen = slot->header.credentialLen;
            }
            return 1;
        }
    }
    PRINTF("Not found\n");
    return RK_NOT_FOUND;
}

int rk_storage_erase_account(const uint8_t *rpIdHash, const uint8_t *userId, uint32_t userIdLen) {
    rk_slot_t *slot;
    credential_data_t credData;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        slot = get_slot_addr(i);
        if ((slot == NULL) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot->header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        if (credential_decode(&credData, slot->credential, slot->header.credentialLen, true) != 0) {
            // Should not happen
            continue;
        }

        if (credData.userIdLen != userIdLen) {
            continue;
        }

        if (crypto_compare(credData.userId, userId, userIdLen)) {
            PRINTF("Erasing credential for rpId %.*H userId %.*H\n",
                   RP_ID_HASH_SIZE,
                   rpIdHash,
                   userIdLen,
                   userId);
            erase_slot(i);
            return 1;
        }
    }

    return RK_NOT_FOUND;
}
