#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "unity.h"

#include "cbip_decode.h"

void setUp(void) {
}

void tearDown(void) {
}

// Reads every byte an item claims, so ASan catches an item that points past the buffer.
static uint32_t touch_item(const uint8_t *buffer, const cbipItem_t *item) {
    uint32_t sum = 0;

    if ((item->type == cbipByteString) || (item->type == cbipTextString)) {
        for (uint32_t i = 0; i < item->value; i++) {
            sum += buffer[item->offset + item->headerLength + i];
        }
    }
    return sum;
}

static void decode_file(const char *name) {
    char path[256];
    cbipDecoder_t decoder;
    cbipItem_t item;
    uint32_t sum = 0;

    snprintf(path, sizeof(path), "%s/%s", CBOR_DIR, name);
    FILE *fic = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(fic, path);
    fseek(fic, 0, SEEK_END);
    long size = ftell(fic);
    fseek(fic, 0, SEEK_SET);
    TEST_ASSERT_GREATER_THAN_MESSAGE(0, size, path);

    uint8_t *data = malloc(size);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(size, fread(data, 1, size, fic), path);
    fclose(fic);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, cbip_decoder_init(&decoder, data, size), path);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, cbip_first(&decoder, &item), path);
    while (item.type != cbipNone) {
        sum += touch_item(data, &item);
        TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, cbip_next(&decoder, &item), path);
    }
    (void) sum;

    free(data);
}

void test_decode_ex1(void) {
    decode_file("ex1.cbor");
}

void test_decode_ex2(void) {
    decode_file("ex2.cbor");
}

void test_decode_ex3(void) {
    decode_file("ex3.cbor");
}

void test_decode_ex4_cmd(void) {
    decode_file("ex4_cmd.cbor");
}

void test_decode_ex4_resp(void) {
    decode_file("ex4_resp.cbor");
}

void test_decode_ex5_cmd(void) {
    decode_file("ex5_cmd.cbor");
}

void test_decode_ex5_resp(void) {
    decode_file("ex5_resp.cbor");
}

void test_decode_getinfo(void) {
    decode_file("getinfo.cbor");
}

void test_decode_make_cred_1(void) {
    decode_file("make_cred_1.cbor");
}

void test_decode_pubkey(void) {
    decode_file("pubkey.cbor");
}

void test_decode_test(void) {
    decode_file("test.cbor");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_decode_ex1);
    RUN_TEST(test_decode_ex2);
    RUN_TEST(test_decode_ex3);
    RUN_TEST(test_decode_ex4_cmd);
    RUN_TEST(test_decode_ex4_resp);
    RUN_TEST(test_decode_ex5_cmd);
    RUN_TEST(test_decode_ex5_resp);
    RUN_TEST(test_decode_getinfo);
    RUN_TEST(test_decode_make_cred_1);
    RUN_TEST(test_decode_pubkey);
    RUN_TEST(test_decode_test);
    return UNITY_END();
}
