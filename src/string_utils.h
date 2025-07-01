#pragma once

#include <stdbool.h>

/**
 * Truncate a string inplace depending on display restrictions.
 * Does something only on NBGL.
 * This function relies on SDK NBGL `nbgl_getTextMaxLenInNbLines` function to
 * evaluate if the given text can or cannot fit the required nb of lines on a
 * NBGL screen (3 for Stax, 2 for Flex).
 * If it fits, or if the graphic library is BAGL, nothing happens.
 * If not, the string is truncated to fit, and, the last 3 characters are
 * replaced with dots ('...').
 */
void truncate_for_nb_lines(char *input, bool large);
