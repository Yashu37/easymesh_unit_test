/*
 * TEST CASES / CONSTRUCTOR: construct_kdf_len
 *
 * key = key_len bytes (i*5+1), context = context_len bytes (i*3+7), label = the case string, output buffer = out_buf bytes; each one
 * is exactly its length between two poisoned 128 byte guards. PASS = return value and, when requested, the output equals an
 * independently computed 802.11 KDF-Hash-Length (HMAC over LE16(i) || label || context || LE16(output_len * 8), OpenSSL one-shot
 * HMAC). Cases named rej_* ABORTED on the original code (NULL context with a length): fix 1 returns false. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kdf_len.h"

namespace kdl {
static void mk(gbuf_t *b, size_t n, int mul, int add)
{
    b->n = n; b->raw = (uint8_t *)calloc(1, KDL_GUARD + n + KDL_GUARD); b->p = b->raw + KDL_GUARD;
    for (size_t i = 0; i < n; i++) b->p[i] = (uint8_t)(i * mul + add);
}
static void fr(gbuf_t *b) { free(b->raw); b->raw = b->p = NULL; b->n = 0; }
#define LONGLABEL "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL"
/* {name, algo, key_len, label, context_len, null_context, null_key, null_output, output_len, out_buf, expect_ret, check_output, crash} */
test_case_t suite[] = {
 {"ok_sha256_32",                   0, 32, "Pairwise key expansion", 12, false, false, false, 32, 32, 1, true, false},
 {"ok_sha256_48",                   0, 32, "Pairwise key expansion", 12, false, false, false, 48, 48, 1, true, false},
 {"ok_sha256_64",                   0, 32, "Group key expansion", 12, false, false, false, 64, 64, 1, true, false},
 {"ok_sha256_one_byte",             0, 32, "L", 12, false, false, false, 1, 1, 1, true, false},
 {"ok_sha256_31",                   0, 32, "L", 12, false, false, false, 31, 31, 1, true, false},
 {"ok_sha256_33_two_blocks",        0, 32, "L", 12, false, false, false, 33, 33, 1, true, false},
 {"ok_sha256_100",                  0, 32, "L", 12, false, false, false, 100, 100, 1, true, false},
 {"ok_sha384_48",                   1, 48, "L", 12, false, false, false, 48, 48, 1, true, false},
 {"ok_sha384_49",                   1, 48, "L", 12, false, false, false, 49, 49, 1, true, false},
 {"ok_sha384_96",                   1, 48, "L", 12, false, false, false, 96, 96, 1, true, false},
 {"ok_sha512_64",                   2, 64, "L", 12, false, false, false, 64, 64, 1, true, false},
 {"ok_sha512_65",                   2, 64, "L", 12, false, false, false, 65, 65, 1, true, false},
 {"ok_sha512_128",                  2, 64, "L", 12, false, false, false, 128, 128, 1, true, false},
 {"ok_key_one_byte",                0, 1, "L", 12, false, false, false, 32, 32, 1, true, false},
 {"ok_key_100_bytes",               0, 100, "L", 12, false, false, false, 32, 32, 1, true, false},
 {"ok_context_null_zero_length",    0, 32, "L", 0, true, false, false, 32, 32, 1, true, false},
 {"ok_context_zero_length",         0, 32, "L", 0, false, false, false, 32, 32, 1, true, false},
 {"ok_context_1000_bytes",          0, 32, "L", 1000, false, false, false, 32, 32, 1, true, false},
 {"ok_empty_label",                 0, 32, "", 12, false, false, false, 32, 32, 1, true, false},
 {"ok_long_label",                  0, 32, LONGLABEL, 12, false, false, false, 32, 32, 1, true, false},
 {"ok_largest_valid_length_8191",   0, 32, "L", 12, false, false, false, 8191, 8191, 1, true, false},
 {"ok_null_algo_rejected",         -1, 32, "L", 12, false, false, false, 32, 32, 0, false, false},
 {"ok_null_key_rejected",           0, 32, "L", 12, false, true, false, 32, 32, 0, false, false},
 {"ok_zero_key_length_rejected",    0, 0, "L", 12, false, false, false, 32, 32, 0, false, false},
 {"ok_null_label_rejected",         0, 32, NULL, 12, false, false, false, 32, 32, 0, false, false},
 {"ok_null_output_rejected",        0, 32, "L", 12, false, false, true, 32, 32, 0, false, false},
 {"ok_zero_output_length_rejected", 0, 32, "L", 12, false, false, false, 0, 1, 0, false, false},
 {"ok_65536_iterations_rejected",   0, 32, "L", 12, false, false, false, 2097152, 1, 0, false, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_output_8192_length_field_wraps_to_0_must_be_rejected [spec]", 0, 32, "L", 12, false, false, false, 8192, 8192, 0, false, false},
 {"spec_output_len_size_max_must_be_rejected [spec]", 0, 32, "L", 12, false, false, false, (size_t)-1, 1, 0, false, false},
 /* ---- were CRASH cases on the original code ---- */
 {"rej_null_context_with_length_12", 0, 32, "L", 12, true, false, false, 32, 32, 0, false, false},
 {"rej_null_context_with_length_1",  2, 64, "L", 1, true, false, false, 64, 64, 0, false, false},
 {NULL, 0, 0, NULL, 0, false, false, false, 0, 0, 0, false, false}
};

void construct_input(const test_case_t *tc)
{
    mk(&g_key, tc->key_len, 5, 1);
    mk(&g_ctx, tc->context_len, 3, 7);
    mk(&g_label, tc->label ? strlen(tc->label) + 1 : 1, 0, 0); if (tc->label) memcpy(g_label.p, tc->label, strlen(tc->label) + 1);
    mk(&g_out, tc->out_buf, 0, 0);
}
void teardown(void) { fr(&g_key); fr(&g_ctx); fr(&g_label); fr(&g_out); }
} /* namespace kdl */
