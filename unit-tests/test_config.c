/*
 * Unit tests for the key initialisation in src/config.c.
 *
 * The device seed derivation and the NVM writes are stubbed (stubs/stub_config.c), so the
 * tests can make a derivation fail or cut the power after any write, then "reboot" by
 * calling config_init() again on the NVM content left behind.
 */

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "unity.h"

#include "config.h"
#include "credential.h"
#include "stub_config.h"

#define BOOT_POWER_CUT (-1000)

typedef struct {
    uint8_t privateKeySeed[64];
    uint8_t wrappingKeyU2F[32];
    uint8_t wrappingKeyCTAP2[32];
} expected_keys_t;

static expected_keys_t expected;

// N_u2f_real is const, so the host linker puts it in .rodata; the device keeps it in NVM.
static void make_nvm_writable(void) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t) &N_u2f_real & ~((uintptr_t) page - 1);
    uintptr_t end = (uintptr_t) &N_u2f_real + sizeof(N_u2f_real);
    TEST_ASSERT_EQUAL_INT(0, mprotect((void *) start, end - start, PROT_READ | PROT_WRITE));
}

static void erase_nvm(void) {
    memset((void *) &N_u2f_real, 0, sizeof(N_u2f_real));
}

static config_t *nvm(void) {
    return (config_t *) &N_u2f_real;
}

static int boot(void) {
    if (setjmp(stub_power_cut) != 0) {
        return BOOT_POWER_CUT;
    }
    return config_init();
}

static void assert_keys_match_seed(const char *context) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, N_u2f.initialized, context);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected.privateKeySeed,
                                          (const uint8_t *) N_u2f.privateKeySeed,
                                          sizeof(expected.privateKeySeed),
                                          context);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected.wrappingKeyU2F,
                                          (const uint8_t *) N_u2f.wrappingKeyU2F,
                                          sizeof(expected.wrappingKeyU2F),
                                          context);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected.wrappingKeyCTAP2,
                                          (const uint8_t *) N_u2f.wrappingKeyCTAP2,
                                          sizeof(expected.wrappingKeyCTAP2),
                                          context);
}

void setUp(void) {
    uint8_t wrapping[64];
    uint8_t version;

    make_nvm_writable();
    erase_nvm();
    stub_config_reset();

    stub_derived_key(PRIVATE_KEY_SEED_PATH, expected.privateKeySeed);
    stub_derived_key(WRAPPING_KEY_PATH, wrapping);
    version = CREDENTIAL_VERSION_U2F;
    stub_sha256(&version, 1, wrapping, sizeof(wrapping), expected.wrappingKeyU2F);
    version = CREDENTIAL_VERSION_CTAP2;
    stub_sha256(&version, 1, wrapping, sizeof(wrapping), expected.wrappingKeyCTAP2);
}

void tearDown(void) {
}

// A clean first boot derives and stores every key.
void test_first_boot_stores_all_keys(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    assert_keys_match_seed("first boot");
}

// A later boot with the same seed finds the keys in place and rewrites nothing.
void test_second_boot_keeps_keys(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    stub_config_reset();

    TEST_ASSERT_EQUAL_INT(0, boot());
    TEST_ASSERT_EQUAL_UINT(0, stub_nvm_writes);
    assert_keys_match_seed("second boot");
}

// A failed seed derivation on first boot must stop the app, not mark it initialised.
void test_first_boot_seed_derivation_failure_is_fatal(void) {
    stub_derive_fail_mask = 1u << 0;
    TEST_ASSERT_NOT_EQUAL_INT(0, boot());
    TEST_ASSERT_NOT_EQUAL_UINT8(1, N_u2f.initialized);

    stub_config_reset();
    TEST_ASSERT_EQUAL_INT(0, boot());
    assert_keys_match_seed("reboot after a failed seed derivation");
}

// Same for the wrapping key, derived second.
void test_first_boot_wrapping_key_derivation_failure_is_fatal(void) {
    stub_derive_fail_mask = 1u << 1;
    TEST_ASSERT_NOT_EQUAL_INT(0, boot());
    TEST_ASSERT_NOT_EQUAL_UINT8(1, N_u2f.initialized);

    stub_config_reset();
    TEST_ASSERT_EQUAL_INT(0, boot());
    assert_keys_match_seed("reboot after a failed wrapping key derivation");
}

// Whatever write the power is cut after, the next boot must end with every key in place.
void test_power_cut_during_first_boot_heals(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    unsigned int writes = stub_nvm_writes;
    TEST_ASSERT_GREATER_THAN_UINT(0, writes);

    for (unsigned int cut = 0; cut < writes; cut++) {
        char context[64];
        snprintf(context, sizeof(context), "reboot after a power cut after %u writes", cut);

        erase_nvm();
        stub_config_reset();
        stub_nvm_writes_before_power_cut = (int) cut;
        TEST_ASSERT_EQUAL_INT_MESSAGE(BOOT_POWER_CUT, boot(), context);

        stub_config_reset();
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, boot(), context);
        assert_keys_match_seed(context);
    }
}

// An initialised device whose derivation fails at boot must not start either.
void test_later_boot_derivation_failure_is_fatal(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    stub_config_reset();

    stub_derive_fail_mask = 1u << 0;
    TEST_ASSERT_NOT_EQUAL_INT(0, boot());
}

// A seed already in place does not vouch for the wrapping keys: a state left by the older write
// order (seed first) is repaired at boot, not accepted with zero keys.
void test_matching_seed_with_zero_wrapping_keys_is_repaired(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    memset(nvm()->wrappingKeyU2F, 0, sizeof(nvm()->wrappingKeyU2F));
    memset(nvm()->wrappingKeyCTAP2, 0, sizeof(nvm()->wrappingKeyCTAP2));

    stub_config_reset();
    TEST_ASSERT_EQUAL_INT(0, boot());
    assert_keys_match_seed("seed in place, wrapping keys zero");
}

// The same for a stale wrapping key next to a matching seed.
void test_matching_seed_with_stale_wrapping_key_is_repaired(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    nvm()->wrappingKeyCTAP2[0] ^= 0xFF;

    stub_config_reset();
    TEST_ASSERT_EQUAL_INT(0, boot());
    assert_keys_match_seed("seed in place, one wrapping key stale");
}

// A device not marked initialised must not be promoted with such keys either.
void test_uninitialised_device_with_matching_seed_gets_its_keys(void) {
    TEST_ASSERT_EQUAL_INT(0, boot());
    nvm()->initialized = 0;
    memset(nvm()->wrappingKeyU2F, 0, sizeof(nvm()->wrappingKeyU2F));

    stub_config_reset();
    TEST_ASSERT_EQUAL_INT(0, boot());
    assert_keys_match_seed("not initialised, seed in place, a wrapping key zero");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_first_boot_stores_all_keys);
    RUN_TEST(test_second_boot_keeps_keys);
    RUN_TEST(test_first_boot_seed_derivation_failure_is_fatal);
    RUN_TEST(test_first_boot_wrapping_key_derivation_failure_is_fatal);
    RUN_TEST(test_power_cut_during_first_boot_heals);
    RUN_TEST(test_later_boot_derivation_failure_is_fatal);
    RUN_TEST(test_matching_seed_with_zero_wrapping_keys_is_repaired);
    RUN_TEST(test_matching_seed_with_stale_wrapping_key_is_repaired);
    RUN_TEST(test_uninitialised_device_with_matching_seed_gets_its_keys);
    return UNITY_END();
}
