#pragma once

#include <setjmp.h>
#include <stdint.h>

// Derivation calls that throw instead of returning a key. Bit N is the Nth call, from 0.
extern uint32_t stub_derive_fail_mask;
extern unsigned int stub_derive_calls;

// Number of nvm_write() calls that still land before the power is cut. Negative means never.
extern int stub_nvm_writes_before_power_cut;
extern unsigned int stub_nvm_writes;
extern jmp_buf stub_power_cut;

// What the stubbed derivation returns for a given BIP32 path head (private key || chain code).
void stub_derived_key(uint32_t path0, uint8_t key[64]);

// What the stubbed crypto_compute_sha256() returns.
void stub_sha256(const uint8_t *in1,
                 uint32_t in1_len,
                 const uint8_t *in2,
                 uint32_t in2_len,
                 uint8_t out[32]);

void stub_config_reset(void);
