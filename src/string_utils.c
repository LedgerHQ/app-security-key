#include <string.h>
#include "os_print.h"
#include "os_helpers.h"

#include "string_utils.h"

#if defined(HAVE_NBGL)
#include <nbgl_fonts.h>
#include <nbgl_layout.h>
#endif  // defined(HAVE_NBGL)

void truncate_for_nb_lines(char *input, bool large) {
#if !defined(HAVE_NBGL)
    UNUSED(input);
    UNUSED(large);
    return;
#else  // !defined(HAVE_NBGL)

#if defined(TARGET_STAX)
    const uint8_t line_nb = 3;
#elif defined(TARGET_FLEX)
    const uint8_t line_nb = 2;
#endif
    uint16_t max_bytes;
    uint8_t size = strlen(input);

    do {
        // 1. Trying to keep as much of the string as possible (hence the `do...` while loop)
        // Ex: on Flex, with a single call, 'MMMMMMMMMMMMMMMMMMMMMMMMMMMM' would be reduced to
        // 'MMMMMMMMMMMMMMMMMMMMMMM...', when it fact 'MMMMMMMMMMMMMMMMMMMMMMMM...' would fit.
        // As the truncation could be severe (down to 24B in this example), I think this is worth
        // the extra computation (in any case, this would take a maximum of 3 iterations into the
        // loop)
        // 2. 'large' is used on 'review' pages (needing user confirmation), while '!large' is used
        // on 'status' pages (NFC: no confirmation but still credential display)
        nbgl_getTextMaxLenInNbLines(large ? LARGE_MEDIUM_FONT : SMALL_REGULAR_1BPP_FONT,
                                    input,
                                    AVAILABLE_WIDTH,
                                    line_nb,
                                    &max_bytes,
                                    false);
        if (size <= max_bytes) {
            return;
        }
        uint8_t last_changing_index = max_bytes - 1;
        if ((size - max_bytes) >= 3) {
            last_changing_index += 3;
        } else if ((size - max_bytes) == 2) {
            last_changing_index += 2;
        } else if ((size - max_bytes) == 1) {
            last_changing_index += 1;
        }
        input[last_changing_index] = '\0';
        input[last_changing_index - 1] = '.';
        input[last_changing_index - 2] = '.';
        input[last_changing_index - 3] = '.';
        size = strlen(input);
    } while (size > max_bytes);

#endif  // !defined(HAVE_NBGL)
}
