import math

# The code in this file is dirtily adapted from SDK:
# lib_ux/src/ux_layout_paging_compute.c
# But it stll allow to compute the number of line needed
# to display a regular text on the Nano device screen.


PIXEL_PER_LINE = 114
NANOS_FIRST_CHAR = 0x20
NANOS_LAST_CHAR = 0x7F

nanos_characters_width = [
    3 << 4 | 3,   # code 0020
    3 << 4 | 3,   # code 0021
    4 << 4 | 6,   # code 0022
    7 << 4 | 7,   # code 0023
    6 << 4 | 6,   # code 0024
    9 << 4 | 10,  # code 0025
    8 << 4 | 9,   # code 0026
    2 << 4 | 3,   # code 0027
    3 << 4 | 4,   # code 0028
    3 << 4 | 4,   # code 0029
    6 << 4 | 6,   # code 002A
    6 << 4 | 6,   # code 002B
    3 << 4 | 3,   # code 002C
    4 << 4 | 4,   # code 002D
    3 << 4 | 3,   # code 002E
    4 << 4 | 5,   # code 002F
    6 << 4 | 8,   # code 0030
    6 << 4 | 6,   # code 0031
    6 << 4 | 7,   # code 0032
    6 << 4 | 7,   # code 0033
    8 << 4 | 8,   # code 0034
    6 << 4 | 6,   # code 0035
    6 << 4 | 8,   # code 0036
    6 << 4 | 7,   # code 0037
    6 << 4 | 8,   # code 0038
    6 << 4 | 8,   # code 0039
    3 << 4 | 3,   # code 003A
    3 << 4 | 3,   # code 003B
    6 << 4 | 5,   # code 003C
    6 << 4 | 6,   # code 003D
    6 << 4 | 5,   # code 003E
    5 << 4 | 6,   # code 003F
    10 << 4 | 10,  # code 0040
    7 << 4 | 8,   # code 0041
    7 << 4 | 7,   # code 0042
    7 << 4 | 7,   # code 0043
    8 << 4 | 8,   # code 0044
    6 << 4 | 6,   # code 0045
    6 << 4 | 6,   # code 0046
    8 << 4 | 8,   # code 0047
    8 << 4 | 8,   # code 0048
    3 << 4 | 4,   # code 0049
    4 << 4 | 5,   # code 004A
    7 << 4 | 8,   # code 004B
    6 << 4 | 6,   # code 004C
    10 << 4 | 11,  # code 004D
    8 << 4 | 9,   # code 004E
    9 << 4 | 9,   # code 004F
    7 << 4 | 7,   # code 0050
    9 << 4 | 9,   # code 0051
    7 << 4 | 8,   # code 0052
    6 << 4 | 6,   # code 0053
    7 << 4 | 6,   # code 0054
    8 << 4 | 8,   # code 0055
    7 << 4 | 6,   # code 0056
    10 << 4 | 11,  # code 0057
    6 << 4 | 8,   # code 0058
    6 << 4 | 7,   # code 0059
    6 << 4 | 7,   # code 005A
    4 << 4 | 5,   # code 005B
    4 << 4 | 5,   # code 005C
    4 << 4 | 5,   # code 005D
    6 << 4 | 7,   # code 005E
    5 << 4 | 6,   # code 005F
    6 << 4 | 7,   # code 0060
    6 << 4 | 7,   # code 0061
    7 << 4 | 7,   # code 0062
    5 << 4 | 6,   # code 0063
    7 << 4 | 7,   # code 0064
    6 << 4 | 7,   # code 0065
    5 << 4 | 6,   # code 0066
    6 << 4 | 7,   # code 0067
    7 << 4 | 7,   # code 0068
    3 << 4 | 4,   # code 0069
    4 << 4 | 5,   # code 006A
    6 << 4 | 7,   # code 006B
    3 << 4 | 4,   # code 006C
    10 << 4 | 10,  # code 006D
    7 << 4 | 7,   # code 006E
    7 << 4 | 7,   # code 006F
    7 << 4 | 7,   # code 0070
    7 << 4 | 7,   # code 0071
    4 << 4 | 5,   # code 0072
    5 << 4 | 6,   # code 0073
    4 << 4 | 5,   # code 0074
    7 << 4 | 7,   # code 0075
    6 << 4 | 7,   # code 0076
    9 << 4 | 10,  # code 0077
    6 << 4 | 7,   # code 0078
    6 << 4 | 7,   # code 0079
    5 << 4 | 6,   # code 007A
    4 << 4 | 5,   # code 007B
    6 << 4 | 6,   # code 007C
    4 << 4 | 5,   # code 007D
    6 << 4 | 6,   # code 007E
    7 << 4 | 6,   # code 007F
]


def is_delimiter(char):
    return char in [' ', '\n', '\t', '-', '_']


# This function is used to retrieve the width of a line of text.
def se_compute_line_width_light(text):
    line_width = 0

    for current_char in text:
        char_code = ord(current_char)
        if (char_code < NANOS_FIRST_CHAR or char_code > NANOS_LAST_CHAR):
            if (current_char == '\n' or current_char == '\r'):
                break

        else:
            # consider only Regular.
            line_width += (nanos_characters_width[char_code - NANOS_FIRST_CHAR] >> 0x04) & 0x0F

    return line_width


def get_message_nb_screen(model, message):
    if model == "nanos":
        nb_lines = 1
    else:
        nb_lines = 3

    offset = 0
    lines = 0
    while offset < len(message):
        line_start_offset = offset
        last_word_delim = 0
        line_offset = line_start_offset
        while line_offset < len(message):
            if se_compute_line_width_light(message[offset: line_offset + 1]) > PIXEL_PER_LINE:
                break

            c = message[line_offset]
            if is_delimiter(c):
                last_word_delim = line_offset
            line_offset += 1

            # new line, don't go further
            if c == '\n':
                break

        # if not splitting line onto a word delimiter, then cut at the previous word_delim,
        # adjust len accordingly
        if line_offset != len(message) and last_word_delim != 0:
            if not is_delimiter(message[line_offset - 1]) and \
               not is_delimiter(message[line_offset]):
                line_offset = last_word_delim

        lines += 1
        offset = line_offset

    return math.ceil(lines / nb_lines)
