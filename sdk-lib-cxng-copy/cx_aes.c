/* @BANNER@ */

#ifdef HAVE_AES

#include "cx_cipher.h"
#include "cx_ram.h"

#include <stddef.h>
#include <string.h>

cx_err_t aes_ctr(cx_aes_key_t  *ctx_key,
                 size_t         len,
                 size_t        *nc_off,
                 uint8_t       *nonce_counter,
                 uint8_t       *stream_block,
                 const uint8_t *input,
                 uint8_t       *output)
{
    uint8_t  c;
    size_t   n     = *nc_off;
    cx_err_t error = CX_INVALID_PARAMETER;

    while (len--) {
        if (n == 0) {
            CX_CHECK(cx_aes_enc_block(ctx_key, nonce_counter, stream_block));
            for (int i = CX_AES_BLOCK_SIZE; i > 0; i--) {
                if (++nonce_counter[i - 1] != 0) {
                    break;
                }
            }
        }
        c         = *input++;
        *output++ = c ^ stream_block[n];
        n         = (n + 1) & 0x0F;
    }
    *nc_off = n;
    error   = CX_OK;

end:
    return error;
}

cx_err_t aes_setkey(cx_aes_key_t  *ctx_key,
                    uint32_t       operation,
                    const uint8_t *key,
                    uint32_t       key_bitlen)
{
    cx_err_t error;
    CX_CHECK(cx_aes_init_key_no_throw(key, key_bitlen / 8, ctx_key));
    CX_CHECK(cx_aes_set_key_hw(ctx_key, operation));
end:
    return error;
}

static const cx_cipher_base_t aes_base
    = {(cx_err_t(*)(const cipher_key_t *ctx_key, const uint8_t *inblock, uint8_t *outblock))
           cx_aes_enc_block,
       (cx_err_t(*)(const cipher_key_t *ctx_key, const uint8_t *inblock, uint8_t *outblock))
           cx_aes_dec_block,
       (cx_err_t(*)(const cipher_key_t *ctx_key,
                    size_t              len,
                    size_t             *nc_off,
                    uint8_t            *nonce_counter,
                    uint8_t            *stream_block,
                    const uint8_t      *input,
                    uint8_t            *output)) aes_ctr,
       (cx_err_t(*)(const cipher_key_t *ctx_key,
                    uint32_t            operation,
                    const uint8_t      *key,
                    uint32_t            key_bitlen)) aes_setkey,
       (cx_err_t(*)(void)) cx_aes_reset_hw};

const cx_cipher_info_t cx_aes_128_info = {128, 16, CX_AES_BLOCK_SIZE, &aes_base};

const cx_cipher_info_t cx_aes_192_info = {192, 16, CX_AES_BLOCK_SIZE, &aes_base};

const cx_cipher_info_t cx_aes_256_info = {256, 16, CX_AES_BLOCK_SIZE, &aes_base};

#endif  // HAVE_AES
