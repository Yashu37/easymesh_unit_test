/*
 * TEST CASES / CONSTRUCTOR: construct_wps_kdf
 *
 * key = 32 bytes (i*5+1), label_prefix = prefix_len bytes (i*3+7), label = the case string, result buffer = res_buf bytes; each one is
 * exactly its length between two poisoned 128 byte guards. PASS = return value and, when requested, the output equals an independently
 * computed WPS KDF (HMAC-SHA256 over i || prefix || label || res_len * 8, OpenSSL one-shot HMAC). Cases named crash_* ABORT on the
 * original code (NULL label, NULL result buffer, NULL prefix with a length): they run last and UNFORKED so a plain `make` stops with the
 * report; FORK_CRASH=1 forks each one. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wps_kdf.h"

namespace wkd {
static void mk(gbuf_t *b, size_t n, int mul, int add)
{
    b->n = n; b->raw = (uint8_t *)calloc(1, WKD_GUARD + n + WKD_GUARD); b->p = b->raw + WKD_GUARD;
    for (size_t i = 0; i < n; i++) b->p[i] = (uint8_t)(i * mul + add);
}
static void fr(gbuf_t *b) { free(b->raw); b->raw = b->p = NULL; b->n = 0; }

/* {name, res_len, res_buf, label, prefix_len, null_prefix, null_key, null_res, expect_ret, check_output, crash} */
test_case_t suite[] = {
 {"ok_zero_length_key",                0, 0, "Label", 4, false, false, false, 1, true, false},
 {"ok_zero_length_null_res",           0, 0, "Label", 4, false, false, true, 1, false, false},
 {"ok_one_byte",                       1, 1, "Label", 4, false, false, false, 1, true, false},
 {"ok_16_bytes",                       16, 16, "Label", 4, false, false, false, 1, true, false},
 {"ok_31_bytes",                       31, 31, "Label", 4, false, false, false, 1, true, false},
 {"ok_32_bytes_one_block",             32, 32, "Label", 4, false, false, false, 1, true, false},
 {"ok_33_bytes_two_blocks",            33, 33, "Label", 4, false, false, false, 1, true, false},
 {"ok_64_bytes",                       64, 64, "Label", 4, false, false, false, 1, true, false},
 {"ok_65_bytes",                       65, 65, "Label", 4, false, false, false, 1, true, false},
 {"ok_hundred_bytes",                  100, 100, "Label", 4, false, false, false, 1, true, false},
 {"ok_1000_bytes",                     1000, 1000, "Label", 4, false, false, false, 1, true, false},
 {"ok_prefix_zero_length",             48, 48, "Label", 0, false, false, false, 1, true, false},
 {"ok_prefix_null_zero_length",        48, 48, "Label", 0, true, false, false, 1, true, false},
 {"ok_empty_label",                    48, 48, "", 4, false, false, false, 1, true, false},
 {"ok_long_label_200",                 48, 48, "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL", 4, false, false, false, 1, true, false},
 {"ok_long_prefix_1000",               48, 48, "Label", 1000, false, false, false, 1, true, false},
 {"ok_null_key_rejected",              48, 48, "Label", 4, false, true, false, 0, false, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_res_len_near_uint_max_must_be_rejected [spec]", 0xFFFFFFF0u, 1, "Label", 4, false, false, false, 0, false, false},
 /* ---- CRASH cases on the original code: run last, unforked ---- */
 {"crash_null_label",                  48, 48, NULL, 4, false, false, false, 0, false, true},
 {"crash_null_result_buffer",          48, 48, "Label", 4, false, false, true, 0, false, true},
 {"crash_null_prefix_with_length",     48, 48, "Label", 4, true, false, false, 0, false, true},
 {NULL, 0, 0, NULL, 0, false, false, false, 0, false, false}
};

void construct_input(const test_case_t *tc)
{
    mk(&g_key, SHA256_MAC_LEN, 5, 1);
    mk(&g_prefix, tc->prefix_len, 3, 7);
    mk(&g_label, tc->label ? strlen(tc->label) + 1 : 1, 0, 0); if (tc->label) memcpy(g_label.p, tc->label, strlen(tc->label) + 1);
    mk(&g_res, tc->res_buf, 0, 0);
}
void teardown(void) { fr(&g_key); fr(&g_prefix); fr(&g_label); fr(&g_res); }
} /* namespace wkd */
