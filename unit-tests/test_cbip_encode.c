#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "unity.h"

#include "cbip_encode.h"

void setUp(void) {
}

void tearDown(void) {
}

void test_rejects_wrapped_length(void) {
    unsigned char data[16] = {0};
    unsigned char value = 0;
    cbipEncoder_t encoder;

    cbip_encoder_init(&encoder, data, sizeof(data));
    encoder.offset = 8;

    TEST_ASSERT_LESS_THAN(0, cbip_add_byte_string(&encoder, &value, UINT32_MAX - 8));
    TEST_ASSERT_TRUE(encoder.fault);
}

void test_rejects_null_source(void) {
    unsigned char data[16] = {0};
    cbipEncoder_t encoder;

    /* A NULL source with a nonzero length is refused and latches fault. */
    cbip_encoder_init(&encoder, data, sizeof(data));
    TEST_ASSERT_LESS_THAN(0, cbip_add_byte_string(&encoder, NULL, 4));
    TEST_ASSERT_TRUE(encoder.fault);

    /* A NULL source with a zero length stays valid: an empty string is legal CBOR
       and no copy is made. Runs under UBSan, so a memmove() here would be caught. */
    cbip_encoder_init(&encoder, data, sizeof(data));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_byte_string(&encoder, NULL, 0));
    TEST_ASSERT_FALSE(encoder.fault);

    /* Same for a text string, which shares cbip_add_raw(). */
    cbip_encoder_init(&encoder, data, sizeof(data));
    TEST_ASSERT_LESS_THAN(0, cbip_add_string(&encoder, NULL, 4));
    TEST_ASSERT_TRUE(encoder.fault);
}

void test_encode_get_info(void) {
    // clang-format off
    unsigned char aaguid[16] = {0xf4, 0x60, 0xd3, 0xbf, 0xf8, 0x61, 0xcf, 0xe2,
                                0xf1, 0x90, 0x9d, 0x06, 0xf9, 0x8c, 0x7c, 0x83};
    // clang-format on
    unsigned char data[1024];
    unsigned char expected[1024];
    cbipEncoder_t encoder;

    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_encoder_init(&encoder, data, sizeof(data)));

    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_map_header(&encoder, 7));

    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_int(&encoder, 1));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_array_header(&encoder, 2));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_string(&encoder, "U2F_V2", sizeof("U2F_V2") - 1));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_string(&encoder, "FIDO_2_0", sizeof("FIDO_2_0") - 1));

    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_int(&encoder, 3));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_byte_string(&encoder, aaguid, sizeof(aaguid)));

    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_int(&encoder, 4));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_map_header(&encoder, 3));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_string(&encoder, "rk", sizeof("rk") - 1));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_boolean(&encoder, true));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_string(&encoder, "up", sizeof("up") - 1));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_boolean(&encoder, true));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_string(&encoder, "uv", sizeof("uv") - 1));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_boolean(&encoder, true));

    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_int(&encoder, 5));
    TEST_ASSERT_GREATER_OR_EQUAL(0, cbip_add_int(&encoder, 1024));
    TEST_ASSERT_FALSE(encoder.fault);

    FILE *fic = fopen(CBOR_DIR "/getinfo.cbor", "rb");
    TEST_ASSERT_NOT_NULL(fic);
    size_t expected_len = fread(expected, 1, sizeof(expected), fic);
    fclose(fic);

    TEST_ASSERT_EQUAL_size_t(expected_len, encoder.offset);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, data, expected_len);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_rejects_wrapped_length);
    RUN_TEST(test_rejects_null_source);
    RUN_TEST(test_encode_get_info);
    return UNITY_END();
}
