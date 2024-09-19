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

#ifndef __CREDENTIAL_H__
#define __CREDENTIAL_H__

#include "lcx_aes_siv.h"

#define STATUS_RK_CREDENTIAL 0x01

#define CREDENTIAL_VERSION_U2F   0x01
#define CREDENTIAL_VERSION_CTAP2 0x02
#define CREDENTIAL_UNWRAPPED_BIT 0x80

/**
 * This API expose credentials in 3 different forms:
 * - credId form (bytes):
 *   This is the form that is exchanged with the platform.
 *   It structure is:
 *   +---------+----------+------------------------------+
 *   | VERSION | AES Tag  | AES-SIV encrypted credential |
 *   |         |          |------------------------------+
 *   |         |          | Nonce    | encodedCredential |
 *   +---------+----------+------------------------------+
 *   | 1 byte  | 16 bytes | 16 bytes |encodedLength bytes|
 *   +---------+----------+------------------------------+

 *
 * - encodedCredential form (bytes):
 *   This is a list of byte containing information encoded in CBOR.
 *   It always contains:
 *   - A version
 *   - A flag (currently only storing if the resident key option is used)
 *
 *   It additionally contains in fullCredentials version:
 *   - The cose algorithm selected
 *   - The userID
 *   - The username if available
 *
 *   When a key is resident, the resident storage should contains all necessary information
 *   so that the key can be used without allowList.
 *   Therefore, many fields can be optimized out when the encodedCredential will be send to
 *   the platform and is associated to a resident key as the resident storage already
 *   contains these information.
 *
 *   In brief:
 *   - when the key is not resident, the fullCredentials is sent to the platform.
 *   - when the key is resident, the fullCredentials is stored in NVM storage, and the light
 *     version is encapsulated in the credId form to be sent to the platform.
 *
 * - credData form (credential_data_t structure instance):
 *   This is the form that can be used in makeCredential and getAssertion flow to access the
 *   different fields encoded into a CBOR in encodedCredential so that the encoding/decoding
 *   logic is localized in a single place.
 */

#define CREDENTIAL_VERSION_SIZE            1
#define CREDENTIAL_TAG_SIZE                CX_AES_BLOCK_SIZE
#define CREDENTIAL_NONCE_SIZE              16
#define CREDENTIAL_PRIVATE_KEY_SIZE        CX_SHA256_SIZE
#define CREDENTIAL_ENCRYPTED_DATA_MIN_SIZE CREDENTIAL_NONCE_SIZE

#define CREDENTIAL_MINIMAL_SIZE \
    (CREDENTIAL_VERSION_SIZE + CREDENTIAL_TAG_SIZE + CREDENTIAL_ENCRYPTED_DATA_MIN_SIZE)

typedef struct credential_data_s {
    int coseAlgorithm;
    uint8_t *userId;
    uint32_t userIdLen;
    char *userStr;
    uint32_t userStrLen;
    uint8_t residentKey;
} credential_data_t;

/**
 * Wrap credential to be sent to platform and store key in rk_storage if necessary:
 * inputs:
 *  - rpIdHash (or application parameter in U2F)
 *  - the random nonce to be associated to this credential
 *  - the credData
 *  - isCtap2 to inform if credData is expected and should be encoded
 *    in output credId.
 *  - alreadyResident to inform that the key is already stored in NVM storage
 *
 * outputs:
 * - credId will be stored in buffer
 *
 * Return:
 * - > 0 the credIdLen
 * - < 0 an error occurred
 */
int credential_wrap(const uint8_t *rpIdHash,
                    const uint8_t *nonce,
                    credential_data_t *credData,
                    uint8_t *buffer,
                    uint32_t bufferLen,
                    bool isCtap2,
                    bool alreadyResident);

/**
 * Check and unwrap credential from credId received from platform:
 * inputs:
 *  - rpIdHash (or application parameter in U2F)
 *  - credId and credIdLen
 *
 * outputs:
 * - the random nonce to associated to this credential
 * - the encodedCredential and encodedCredentialLen
 *
 * Return:
 * - == 0 if everything went fine
 * - < 0 an error occurred (wrong size, wrong signature, wrong version,
 *   bad encryption, residentKey missing, ...)
 */
int credential_unwrap(const uint8_t *rpIdHash,
                      uint8_t *credId,
                      uint32_t credIdLen,
                      uint8_t **nonce,
                      uint8_t **encodedCredential,
                      uint32_t *encodedCredentialLen);

/**
 * Extract credential from already checked and unwrapped (decrypt in place) credId:
 * inputs:
 *  - rpIdHash (or application parameter in U2F)
 *  - credId and credIdLen
 *
 * outputs:
 * - the random nonce to associated to this credential
 * - the encodedCredential and encodedCredentialLen
 *
 * Return:
 * - == 0 if everything went fine
 * - < 0 an error occurred (wrong size, wrong signature, wrong version,
 *   bad encryption, residentKey missing, ...)
 */
int credential_extract(const uint8_t *rpIdHash,
                       const uint8_t *credId,
                       uint32_t credIdLen,
                       uint8_t **nonce,
                       uint8_t **encodedCredential,
                       uint32_t *encodedCredentialLen);

/**
 * Decode credential from CBOR encoded form into credData form
 */
int credential_decode(credential_data_t *credData,
                      uint8_t *encodedCredential,
                      uint32_t encodedCredentialLen,
                      bool fullCredentials);

/**
 * Re-wrap credential to be sent to platform.
 * It only works with credId input from allowList that was previously unwrapped.
 * Return:
 * - > 0 the credIdLen
 * - < 0 an error occurred
 */
int credential_rewrap_in_place(const uint8_t *rpIdHash, uint8_t *credId, uint32_t credIdLen);

#endif
