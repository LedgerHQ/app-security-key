/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2023 Ledger
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

#include "client_pin_utils.h"
#include "cbip_encode.h"
#include "ui_shared.h"

#define TOKEN_MAX_USAGE_LIMIT_MS     (10 * 60 * 1000)  // 10 minutes in msec
#define TOKEN_USER_PRESENT_LIMIT_MS  (30 * 1000)       // 30 seconds in msec
#define TOKEN_INITIAL_USAGE_LIMIT_MS (30 * 1000)       // 30 seconds in msec

auth_token_t authToken = {};

static uint32_t authTokenStartUptimeMs;
static bool authTokeninUse;
static bool authTokenFirstUsageDone;
static uint8_t authTokenUserVerifiedFlag;
static uint8_t authTokenUserPresentFlag;


/******************************************/
/*   Pin Uv Auth Token Protocol helpers   */
/******************************************/
static uint32_t get_uptime_ms(void) {
    return uptime_ms;
}

static void beginUsingPinUvAuthToken(bool userIsPresent) {
    authTokenUserPresentFlag = userIsPresent;
    authTokenUserVerifiedFlag = true;
    authTokenStartUptimeMs = get_uptime_ms();
    authTokeninUse = true;
}

void stopUsingPinUvAuthToken(void) {
    authTokeninUse = false;
}

// Equivalent to spec pinUvAuthTokenUsageTimerObserver()
bool is_token_valid(void) {
    uint32_t currentUptimeMs = get_uptime_ms();

    if (!authTokeninUse) {
        return false;
    }

    if (currentUptimeMs > authTokenStartUptimeMs + TOKEN_MAX_USAGE_LIMIT_MS) {
        stopUsingPinUvAuthToken();
        return false;
    }

    if (authTokenUserPresentFlag) {
        if (currentUptimeMs > authTokenStartUptimeMs + TOKEN_USER_PRESENT_LIMIT_MS) {
            authTokenUserPresentFlag = false;
        }
    }

    if (!authTokenFirstUsageDone) {
        if (currentUptimeMs > authTokenStartUptimeMs + TOKEN_INITIAL_USAGE_LIMIT_MS) {
            stopUsingPinUvAuthToken();
            return false;
        } else {
            // consider that the token has been used
            authTokenFirstUsageDone = true;
        }
    }
    return true;
}

bool getUserPresentFlagValue(void) {
    if (authTokeninUse) {
        return authTokenUserPresentFlag;
    }
    return false;
}

bool getUserVerifiedFlagValue(void) {
    if (authTokeninUse) {
        return authTokenUserVerifiedFlag;
    }
    return false;
}

void clearUserPresentFlag(void) {
    authTokenUserPresentFlag = false;
}

void clearUserVerifiedFlag(void) {
    authTokenUserVerifiedFlag = false;
}

void clearPinUvAuthTokenPermissionsExceptLbw(void) {
    authToken.perms &= (AUTH_TOKEN_PERM_RP_ID | AUTH_TOKEN_PERM_LARGE_BLOB_wRITE);
}


void user_cancel_client_pin_get_token(void) {
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
    ui_idle();
}


void confirm_client_pin_get_token(void) {
    cbipEncoder_t encoder;
    uint8_t tokenEnc[AUTH_TOKEN_MAX_ENC_SIZE];
    uint32_t encryptedLength;
    ctap2_pin_data_t *ctap2PinData = get_ctap2_pin_data();

    ctap2UxState = CTAP2_UX_STATE_NONE;

    PRINTF("ctap2_confirm_client_pin_get_token\n");

    // Prepare token
    authToken.protocol = ctap2PinData->protocol;
    cx_rng_no_throw(authToken.value, AUTH_TOKEN_SIZE);
    PRINTF("Generated pin token %.*H\n", AUTH_TOKEN_SIZE, authToken.value);
    authToken.perms = ctap2PinData->perms;
    if (ctap2PinData->rpId != NULL) {
        authToken.perms |= AUTH_TOKEN_PERM_RP_ID;
        memcpy(authToken.rpIdHash, ctap2PinData->rpIdHash, CX_SHA256_SIZE);
    }
    beginUsingPinUvAuthToken(false);

    ctap2_client_pin_encrypt(ctap2PinData->protocol,
                             ctap2PinData->sharedSecret,
                             authToken.value,
                             AUTH_TOKEN_SIZE,
                             tokenEnc,
                             &encryptedLength);

    // Generate the response
    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_PIN_TOKEN);
    cbip_add_byte_string(&encoder, tokenEnc, encryptedLength);

    G_io_apdu_buffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset, NULL);
    ui_idle();
}
