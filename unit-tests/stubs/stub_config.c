#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"

#include "crypto.h"
#include "ctap2.h"
#include "rk_storage.h"

#include "stub_config.h"

uint32_t stub_derive_fail_mask;
unsigned int stub_derive_calls;
int stub_nvm_writes_before_power_cut = -1;
unsigned int stub_nvm_writes;
jmp_buf stub_power_cut;

void stub_config_reset(void) {
    stub_derive_fail_mask = 0;
    stub_derive_calls = 0;
    stub_nvm_writes_before_power_cut = -1;
    stub_nvm_writes = 0;
}

void stub_derived_key(uint32_t path0, uint8_t key[64]) {
    for (unsigned int i = 0; i < 64; i++) {
        key[i] = (uint8_t) ((path0 >> (8 * (i % 4))) + i + 1);
    }
}

void stub_sha256(const uint8_t *in1,
                 uint32_t in1_len,
                 const uint8_t *in2,
                 uint32_t in2_len,
                 uint8_t out[32]) {
    for (unsigned int i = 0; i < 32; i++) {
        out[i] = (uint8_t) (0xA5 ^ i);
    }
    for (uint32_t i = 0; i < in1_len; i++) {
        out[i % 32] = (uint8_t) (out[i % 32] * 31 + in1[i]);
    }
    for (uint32_t i = 0; i < in2_len; i++) {
        out[i % 32] = (uint8_t) (out[i % 32] * 31 + in2[i]);
    }
}

// The SDK exception frames, as the OS keeps them on the device.
static try_context_t *current_try_context;

try_context_t *try_context_get(void) {
    return current_try_context;
}

try_context_t *try_context_set(try_context_t *context) {
    try_context_t *previous = current_try_context;
    current_try_context = context;
    return previous;
}

void os_longjmp(unsigned int exception) {
    longjmp(try_context_get()->jmp_buf, exception);
}

// os_derive_bip32_no_throw() is a static inline wrapper around this syscall.
void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int *path,
                                        unsigned int pathLength,
                                        unsigned char *privateKey,
                                        unsigned char *chain,
                                        unsigned char *seed_key,
                                        unsigned int seed_key_length) {
    uint8_t key[64];

    (void) mode;
    (void) curve;
    (void) pathLength;
    (void) seed_key;
    (void) seed_key_length;

    unsigned int call = stub_derive_calls++;
    if ((call < 32) && ((stub_derive_fail_mask >> call) & 1)) {
        THROW(EXCEPTION_SECURITY);
    }

    stub_derived_key(path[0], key);
    memcpy(privateKey, key, 32);
    if (chain != NULL) {
        memcpy(chain, key + 32, 32);
    }
}

// A power cut ends the app mid-way: jump back to the test, keeping what already landed.
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    if (stub_nvm_writes_before_power_cut == 0) {
        longjmp(stub_power_cut, 1);
    }
    if (stub_nvm_writes_before_power_cut > 0) {
        stub_nvm_writes_before_power_cut--;
    }
    stub_nvm_writes++;

    if (src_adr == NULL) {
        memset(dst_adr, 0, src_len);
    } else {
        memmove(dst_adr, src_adr, src_len);
    }
}

void crypto_compute_sha256(uint8_t *in1,
                           uint32_t in1_len,
                           uint8_t *in2,
                           uint32_t in2_len,
                           uint8_t *out) {
    stub_sha256(in1, in1_len, in2, in2_len, out);
}

void cx_rng_no_throw(uint8_t *buffer, size_t len) {
    memset(buffer, 0, len);
}

uint32_t cx_rng_u32_range_func(uint32_t a, uint32_t b, cx_rng_u32_range_randfunc_t randfunc) {
    (void) b;
    (void) randfunc;
    return a;
}

void ctap2_client_pin_reset_ctx(void) {
}

void rk_storage_erase_all(void) {
}
