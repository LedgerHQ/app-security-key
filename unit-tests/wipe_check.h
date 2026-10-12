/*
 * Records the explicit_bzero() calls of the source under test.
 *
 * A stack buffer is gone once the function returns, so a test cannot read it back. A mock
 * that receives the buffer saves its address instead, and the test then checks that a
 * recorded wipe covered it. Include after the system headers and before the source.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WIPE_CHECK_MAX 64

static struct {
    uintptr_t start;
    size_t len;
} wipe_check_calls[WIPE_CHECK_MAX];
static size_t wipe_check_count;

static void wipe_check_bzero(void *buffer, size_t len) {
    if (wipe_check_count < WIPE_CHECK_MAX) {
        wipe_check_calls[wipe_check_count].start = (uintptr_t) buffer;
        wipe_check_calls[wipe_check_count].len = len;
        wipe_check_count++;
    }
    memset(buffer, 0, len);
}

static void wipe_check_reset(void) {
    wipe_check_count = 0;
}

// Only compares addresses: the buffer may be out of scope by now.
static bool wipe_check_covered(const void *buffer, size_t len) {
    uintptr_t start = (uintptr_t) buffer;
    for (size_t i = 0; i < wipe_check_count; i++) {
        if ((wipe_check_calls[i].start <= start) &&
            (start + len <= wipe_check_calls[i].start + wipe_check_calls[i].len)) {
            return true;
        }
    }
    return false;
}

#define explicit_bzero wipe_check_bzero
