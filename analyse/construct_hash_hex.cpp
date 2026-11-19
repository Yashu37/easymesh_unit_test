/*
 * TEST CASES / CONSTRUCTOR: construct_hash_hex
 *
 * The hash is a heap buffer of exactly len bytes between two poisoned 128 byte guards (filled by pattern: 0 zeros, 1 (i*7+3)&0xFF,
 * 2 all 0xFF, 3 i&0xFF). PASS = the returned string equals an independently built lower case hex string of the buffer. Cases named
 * rej_* / clamp_* ABORTED on the original code (NULL hash with a length, a length whose 2 * len + 1 byte stack array does not fit the 8 MB
 * stack): fix 1 returns an empty string for a NULL hash, fix 2 builds the string on the heap.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_hex.h"

namespace hhx {
/* {name, len, fill, null_hash, use_vector, crash} */
test_case_t suite[] = {
 {"ok_empty_null_hash",               0, 0, true,  false, false},
 {"ok_empty_buffer",                  0, 0, false, false, false},
 {"ok_one_byte",                      1, 1, false, false, false},
 {"ok_leading_zero_nibbles",          4, 0, false, false, false},
 {"ok_all_ff",                        8, 2, false, false, false},
 {"ok_sha1_length_20",                20, 1, false, false, false},
 {"ok_sha256_length_32",              32, 1, false, false, false},
 {"ok_sha384_length_48",              48, 3, false, false, false},
 {"ok_sha512_length_64",              64, 1, false, false, false},
 {"ok_every_byte_value_256",          256, 3, false, false, false},
 {"ok_tlv_max_length_65535",          65535, 1, false, false, false},
 {"ok_one_megabyte",                  1048576, 1, false, false, false},
 {"ok_vector_empty",                  0, 0, false, true, false},
 {"ok_vector_32",                     32, 1, false, true, false},
 {"ok_vector_every_byte_value",       256, 3, false, true, false},
 /* ---- were CRASH cases on the original code ---- */
 {"rej_null_hash_length_1",         1, 0, true,  false, false},
 {"rej_null_hash_length_32",        32, 0, true, false, false},
 {"clamp_stack_array_6_million",      6000000, 1, false, false, false},
 {"clamp_stack_array_20_million",     20000000, 1, false, false, false},
 {"clamp_vector_6_million",           6000000, 1, false, true, false},
 {NULL, 0, 0, false, false, false}
};

void construct_input(const test_case_t *tc)
{
    g_len = tc->len;
    g_raw = (uint8_t *)calloc(1, HHX_GUARD + g_len + HHX_GUARD);
    g_hash = g_raw + HHX_GUARD;
    for (size_t i = 0; i < g_len; i++)
        g_hash[i] = tc->fill == 0 ? 0 : tc->fill == 1 ? (uint8_t)((i * 7 + 3) & 0xFF) : tc->fill == 2 ? 0xFF : (uint8_t)(i & 0xFF);
}
void teardown(void) { free(g_raw); g_raw = NULL; g_hash = NULL; }
} /* namespace hhx */
