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

#include <string.h>

#include "app_storage_data.h"
#include "os.h"
#include "os_utils.h"

#include "rk_storage.h"
#include "crypto.h"

// Index used for the next created RK.
static int nextIdx = 0;

static bool get_slot_addr(uint8_t rkSlotIdx, rk_slot_t *slot) {
    if (rkSlotIdx >= CREDENTIAL_MAX_NUMBER) {
        return false;
    }
    int res = APP_STORAGE_READ_F(rk.slot[rkSlotIdx].header, (void *) &slot->header);

    if (res < 0) {
        if (res == APP_STORAGE_ERR_NO_DATA_AVAILABLE) {
            memset(slot, 0, sizeof(rk_slot_t));
            slot->header.idx = UNUSED_IDX_VALUE;
        } else {
            return false;
        }
    } else {
        APP_STORAGE_READ_F_WITH_SIZE(rk.slot[rkSlotIdx].credential,
                                     (void *) &slot->credential,
                                     slot->header.credentialLen);
    }
    return true;
}

static bool find_free_slot(uint8_t *rkSlotIdx, rk_slot_t *slot) {
    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, slot)) || SLOT_IS_USED((*slot))) {
            continue;
        }
        *rkSlotIdx = i;
        return true;
    }
    PRINTF("No free slot found\n");
    return false;
}

static bool erase_slot(uint8_t rkSlotIdx) {
    rk_slot_t slot;
    if (!get_slot_addr(rkSlotIdx, &slot)) {
        return false;
    }

    if (SLOT_IS_USED(slot)) {
        rk_header_t header;
        header.idx = UNUSED_IDX_VALUE;
        APP_STORAGE_WRITE_F(rk.slot[rkSlotIdx].header, (void *) &header);
        return true;
    }
    return false;
}

void rk_storage_init(void) {
    rk_slot_t slot;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, &slot)) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        nextIdx = MAX(slot.header.idx, nextIdx);
    }
    nextIdx += 1;
    PRINTF("rk detected nextIdx %d\n", nextIdx);
}

void rk_storage_erase_all(void) {
    bool incr = false;
    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        bool ret = erase_slot(i);
        if (ret) incr = true;
    }
    if (incr) {
        app_storage_increment_data_version();
    }
    nextIdx = 1;
}

int rk_storage_store(const uint8_t *rpIdHash,
                     const uint8_t *nonce,
                     const uint8_t *credential,
                     uint32_t credentialLen) {
    rk_slot_t slot;
    rk_header_t header;

    uint8_t rkSlotIdx = 0;
    if (!find_free_slot(&rkSlotIdx, &slot)) {
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
    header.idx = nextIdx;
    nextIdx += 1;
    APP_STORAGE_WRITE_F(rk.slot[rkSlotIdx].header, (void *) &header);
    APP_STORAGE_WRITE_F_WITH_SIZE(rk.slot[rkSlotIdx].credential,
                                  (void *) credential,
                                  credentialLen);
    app_storage_increment_data_version();
    PRINTF("rk_storage_store idx %d size %d\n", header.idx, credentialLen);

    return 0;
}

int rk_storage_count(const uint8_t *rpIdHash) {
    rk_slot_t slot;
    uint32_t count = 0;
    uint32_t idx = 0;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, &slot)) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot.header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        count += 1;
        idx = MAX(slot.header.idx, idx);
    }
    PRINTF("rk_storage_count %d newest %d\n", count, idx);
    return count;
}

int rk_storage_find_youngest(const uint8_t *rpIdHash,
                             uint16_t *requestMinAge,
                             uint8_t *nonce,
                             uint8_t *credential,
                             uint32_t *credentialLen) {
    rk_slot_t slot;
    uint16_t slotAge;
    bool found = false;
    uint16_t foundMinAge = 0xFFFF;  // start with maximum age

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, &slot)) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot.header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        // Credential idx is based on an incrementing counter.
        // Basically, the more recent credential is the one with the greatest idx.
        // Therefore, the "age" of the credential can be considered as the opposite of
        // the idx. With an offset of MAX_IDX_VALUE to stay with positive ages.
        slotAge = MAX_IDX_VALUE - slot.header.idx;
        if ((slotAge < foundMinAge) && ((requestMinAge == NULL) || (slotAge > *requestMinAge))) {
            found = true;
            foundMinAge = slotAge;
            if (nonce != NULL) {
                memcpy(nonce, slot.header.nonce, CREDENTIAL_NONCE_SIZE);
            }
            if (credential != NULL) {
                memcpy(credential, slot.credential, slot.header.credentialLen);
            }
            if (credentialLen != NULL) {
                *credentialLen = slot.header.credentialLen;
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
                            uint8_t *credential,
                            uint32_t *credentialLen) {
    rk_slot_t slot;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, &slot)) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot.header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        if (crypto_compare(slot.header.nonce, nonce, CREDENTIAL_NONCE_SIZE)) {
            if (credential != NULL) {
                memcpy(credential, slot.credential, slot.header.credentialLen);
            }
            if (credentialLen != NULL) {
                *credentialLen = slot.header.credentialLen;
            }
            return 1;
        }
    }
    PRINTF("Not found\n");
    return RK_NOT_FOUND;
}

int rk_storage_erase_account(const uint8_t *rpIdHash, const uint8_t *userId, uint32_t userIdLen) {
    credential_data_t credData;
    rk_slot_t slot;

    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, &slot)) || SLOT_IS_UNUSED(slot)) {
            continue;
        }

        if (!crypto_compare(slot.header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }

        if (credential_decode(&credData, slot.credential, slot.header.credentialLen, true) != 0) {
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
            if (erase_slot(i)) {
                app_storage_increment_data_version();
            }
            return 1;
        }
    }

    return RK_NOT_FOUND;
}

// Used to store list of rkSlotIdx, to be returned to getAssertion and getnextAssertion
// calls when several RKs match a request.
typedef struct next_rk_list_s {
    uint8_t slotIdx[CREDENTIAL_MAX_NUMBER];
    uint8_t next_idx;
} next_rk_list_t;

static next_rk_list_t nextRKList = {0};

static void init_RKList(void) {
    memset(&nextRKList, 0, sizeof(nextRKList));
}

static void push_RKList(uint8_t idx) {
    nextRKList.slotIdx[nextRKList.next_idx++] = idx;
}

static uint8_t pop_RKList() {
    return nextRKList.slotIdx[--nextRKList.next_idx];
}

static uint8_t count_RKList(void) {
    return nextRKList.next_idx;
}

uint8_t rk_build_RKList_from_rpID(const uint8_t *rpIdHash) {
    rk_slot_t slot;
    init_RKList();
    for (uint8_t i = 0; i < CREDENTIAL_MAX_NUMBER; i++) {
        if ((!get_slot_addr(i, &slot)) || SLOT_IS_UNUSED(slot)) {
            continue;
        }
        if (!crypto_compare(slot.header.rpIdHash, rpIdHash, RP_ID_HASH_SIZE)) {
            continue;
        }
        push_RKList(i);
    }
    return count_RKList();
}

int rk_next_credential_from_RKList(uint16_t *idx,
                                   uint8_t *nonce,
                                   uint8_t *credential,
                                   uint32_t *credentialLen) {
    rk_slot_t slot;
    if (count_RKList() == 0) {
        PRINTF("No more creds in the RKList\n");
        return RK_NOT_FOUND;
    }
    if ((!get_slot_addr(pop_RKList(), &slot)) || SLOT_IS_UNUSED(slot)) {
        PRINTF("Invalid cred from RKList!\n");
        return RK_NOT_FOUND;
    }
    if (idx != NULL) {
        *idx = slot.header.idx;
    }
    if (nonce != NULL) {
        memcpy(nonce, slot.header.nonce, CREDENTIAL_NONCE_SIZE);
    }
    if (credential != NULL) {
        memcpy(credential, slot.credential, slot.header.credentialLen);
    }
    if (credentialLen != NULL) {
        *credentialLen = slot.header.credentialLen;
    }
    return 1;
}
