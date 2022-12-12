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

#include "cbip_helper.h"
#include "ctap2.h"

int encode_cose_key(cbipEncoder_t *encoder, cx_ecfp_public_key_t *key, bool forExchange) {
    uint32_t alg, crv, kty;
    switch (key->curve) {
        case CX_CURVE_SECP256K1:
            alg = (forExchange ? COSE_ALG_ECDH_ES_HKDF_256 : COSE_ALG_ES256K);
            crv = COSE_CURVE_P256K;
            kty = COSE_KEYTYPE_EC2;
            break;
        case CX_CURVE_SECP256R1:
            alg = (forExchange ? COSE_ALG_ECDH_ES_HKDF_256 : COSE_ALG_ES256);
            crv = COSE_CURVE_P256;
            kty = COSE_KEYTYPE_EC2;
            break;
        case CX_CURVE_Ed25519:
            if (forExchange) {
                return -1;
            }
            alg = COSE_ALG_EDDSA;
            crv = COSE_CURVE_ED25519;
            kty = COSE_KEYTYPE_OKP;
            break;
        default:
            return -1;
    }
    PRINTF("encode_cose_key alg %d crv %d kty %d\n", alg, crv, kty);
    cbip_add_map_header(encoder, (key->curve == CX_CURVE_Ed25519 ? 4 : 5));
    cbip_add_int(encoder, TAG_COSE_KTY);
    cbip_add_int(encoder, kty);
    cbip_add_int(encoder, TAG_COSE_ALG);
    cbip_add_int(encoder, alg);
    cbip_add_int(encoder, TAG_COSE_CRV);
    cbip_add_int(encoder, crv);
    if (key->curve == CX_CURVE_Ed25519) {
        /*
        uint8_t edPublicKey[33];
        uint32_t i;
        edPublicKey[0] = 0xED;
        for (i=0; i<32; i++) {
                edPublicKey[i + 1] = key->W[64 - i];
        }
        if ((key->W[1 + 31] & 1) != 0) {
                edPublicKey[1 + 31] |= 0x80;
        }
        cbip_add_int(encoder, TAG_COSE_X);
                cbip_add_byte_string(encoder, edPublicKey, sizeof(edPublicKey));
        */
        if (cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, key->W, sizeof(key->W)) != 0) {
            PRINTF("Ed compress failed\n");
            return -1;
        }
        PRINTF("Ed key %.*H\n", 33, key->W);
        cbip_add_int(encoder, TAG_COSE_X);
        cbip_add_byte_string(encoder, key->W + 1, 32);

    } else {
        cbip_add_int(encoder, TAG_COSE_X);
        cbip_add_byte_string(encoder, key->W + 1, 32);
        cbip_add_int(encoder, TAG_COSE_Y);
        cbip_add_byte_string(encoder, key->W + 1 + 32, 32);
    }
    return 0;
}

int decode_cose_key(cbipDecoder_t *decoder,
                    cbipItem_t *map,
                    cx_ecfp_public_key_t *key,
                    bool forExchange) {
    cbipItem_t tmpItem;
    int status, alg, crv, kty, xLength, yLength = 0;
    cx_curve_t bolosCurve;
    uint8_t *x, *y = NULL;
    status = cbiph_get_map_item(decoder, map, TAG_COSE_KTY, NULL, &tmpItem, CBIPH_TYPE_INT);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Missing cose kty\n");
        return -1;
    }
    kty = cbip_get_int(&tmpItem);
    status = cbiph_get_map_item(decoder, map, TAG_COSE_CRV, NULL, &tmpItem, CBIPH_TYPE_INT);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Missing cose crv\n");
        return -1;
    }
    crv = cbip_get_int(&tmpItem);
    status = cbiph_get_map_item(decoder, map, TAG_COSE_ALG, NULL, &tmpItem, CBIPH_TYPE_INT);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Missing cose alg\n");
        return -1;
    }
    alg = cbip_get_int(&tmpItem);
    status = cbiph_get_map_item(decoder, map, TAG_COSE_X, NULL, &tmpItem, cbipByteString);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Missing cose X\n");
        return -1;
    }
    x = decoder->buffer + tmpItem.offset + tmpItem.headerLength;
    xLength = tmpItem.value;
    status = cbiph_get_map_item(decoder, map, TAG_COSE_Y, NULL, &tmpItem, cbipByteString);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        PRINTF("Invalid cose Y\n");
        return -1;
    }
    if (status == CBIPH_STATUS_FOUND) {
        y = decoder->buffer + tmpItem.offset + tmpItem.headerLength;
        yLength = tmpItem.value;
    }
    switch (crv) {
        case COSE_CURVE_P256K:
            /*
            if ((forExchange && (alg != COSE_ALG_ECDH_ES_HKDF_256)) ||
                (!forExchange && (alg != COSE_ALG_ES256K))) {
            */
            if ((alg != COSE_ALG_ES256K) && (alg != COSE_ALG_ECDH_ES_HKDF_256)) {
                PRINTF("Unexpected alg %d for crv %d\n", alg, crv);
                return -1;
            }
            if (kty != COSE_KEYTYPE_EC2) {
                PRINTF("Unexpected kty %d for crv %d\n", kty, crv);
                return -1;
            }
            bolosCurve = CX_CURVE_SECP256K1;
            break;
        case COSE_CURVE_P256:
            /*
            if ((forExchange && (alg != COSE_ALG_ECDH_ES_HKDF_256)) ||
                (!forExchange && (alg != COSE_ALG_ES256))) {
            */
            if ((alg != COSE_ALG_ES256) && (alg != COSE_ALG_ECDH_ES_HKDF_256)) {
                PRINTF("Unexpected alg %d for crv %d\n", alg, crv);
                return -1;
            }
            if (kty != COSE_KEYTYPE_EC2) {
                PRINTF("Unexpected kty %d for crv %d\n", kty, crv);
                return -1;
            }
            bolosCurve = CX_CURVE_SECP256R1;
            break;
        case CX_CURVE_Ed25519:
            if (forExchange) {
                PRINTF("Ed25519 not supported for key exchange\n");
                return -1;
            }
            if (alg != COSE_ALG_EDDSA) {
                PRINTF("Unexpected alg %d for crv %d\n", alg, crv);
                return -1;
            }
            if (kty != COSE_KEYTYPE_OKP) {
                PRINTF("Unexpected kty %d for crv %d\n", kty, crv);
                return -1;
            }
            bolosCurve = CX_CURVE_Ed25519;
            break;
        default:
            PRINTF("Unsupported curve %d\n", crv);
            return -1;
    }
    switch (bolosCurve) {
        case CX_CURVE_SECP256K1:
        case CX_CURVE_SECP256R1: {
            uint8_t keyMaterial[65];
            if ((xLength != 32) || (yLength != 32)) {
                PRINTF("Invalid curve points length %d %d\n", xLength, yLength);
                return -1;
            }
            keyMaterial[0] = 0x04;
            memmove(keyMaterial + 1, x, 32);
            memmove(keyMaterial + 1 + 32, y, 32);
            if (cx_ecfp_init_public_key_no_throw(bolosCurve,
                                                 keyMaterial,
                                                 sizeof(keyMaterial),
                                                 key) != CX_OK) {
                PRINTF("Init key failed\n");
                return -1;
            }
            PRINTF("Parsed key on curve %d %.*H\n", bolosCurve, sizeof(keyMaterial), keyMaterial);
        } break;

        default:
            PRINTF("Unsupported bolos curve%d\n", bolosCurve);
            return -1;
    }
    return 0;
}

cx_curve_t cose_alg_to_cx(int coseAlgorithm) {
    switch (coseAlgorithm) {
        case COSE_ALG_ES256:
            return CX_CURVE_SECP256R1;
        case COSE_ALG_ES256K:
            return CX_CURVE_256K1;
        case COSE_ALG_EDDSA:
            return CX_CURVE_Ed25519;
        default:
            PRINTF("Unsupported cose algorithm %d\n", coseAlgorithm);
            return CX_CURVE_NONE;
    }
}
