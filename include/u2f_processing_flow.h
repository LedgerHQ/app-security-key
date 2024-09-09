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

#pragma once

#include <unistd.h>

#include "credential.h"

#define U2F_ENROLL_RESERVED 0x05
static const uint8_t DUMMY_ZERO[] = {0x00};
#define SIGN_USER_PRESENCE_MASK 0x01
static const uint8_t DUMMY_USER_PRESENCE[] = {SIGN_USER_PRESENCE_MASK};

#define U2F_ENROLL_USER_KEY_SIZE 65

/******************************************/
/*     U2F message payload structures     */
/******************************************/

/* Registration Request Message
 *
 * +-------------------------+
 * | Challenge | Application |
 * +-------------------------+
 * | 32 bytes  |  32 bytes   |
 * +-------------------------+
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_reg_req_t {
    uint8_t challenge_param[32];
    uint8_t application_param[32];
} u2f_reg_req_t;

/* Registration Response Message: Success
 *
 * +----------+----------+----------------+------------+-------------+-----------*
 * | Reserved | User key | Key handle len | Key handle | Attestation | Signature |
 * +----------+----------+----------------+------------+-------------+-----------*
 * |  1 byte  | 65 bytes |    1 byte      |  L bytes   |             |           |
 * +----------+----------+----------------+------------+-------------+-----------*
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_reg_resp_base_t {
    uint8_t reserved_byte;
    uint8_t user_key[U2F_ENROLL_USER_KEY_SIZE];
    uint8_t key_handle_length;
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];  // We generate fix size key handles
    // attestation certificate: not in this base struct due to not const length
    // signature: not in this base struct due to not const offset nor length
} u2f_reg_resp_base_t;

/* Authentication Request Message
 *
 * +-------------------------+----------------+------------+
 * | Challenge | Application | Key handle len | Key handle |
 * +-------------------------+----------------+------------+
 * | 32 bytes  |  32 bytes   |    1 byte      |  L bytes   |
 * +-------------------------+----------------+------------+
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_auth_req_base_t {
    uint8_t challenge_param[32];
    uint8_t application_param[32];
    uint8_t key_handle_length;
    // key handle: not in this base struct due to not const length
} u2f_auth_req_base_t;

/* Authentication Response Message: Success
 *
 * +---------------+---------+-----------*
 * | User presence | Counter | Signature |
 * +---------------+---------+-----------*
 * |  1 byte       | 4 bytes |           |
 * +---------------+---------+-----------*
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_auth_resp_base_t {
    uint8_t user_presence;
    uint8_t counter[4];
    // signature: not in this base struct due to not const length
} u2f_auth_resp_base_t;

uint16_t u2f_prepare_enroll_response(uint8_t *buffer, uint16_t *length);
uint16_t u2f_prepare_sign_response(uint8_t *buffer, uint16_t *length);
void u2f_prompt_user_presence(bool enroll, uint8_t *applicationParameter);
