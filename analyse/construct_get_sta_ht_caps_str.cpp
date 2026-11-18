/*
 * TEST CASES / CONSTRUCTOR: construct_get_sta_ht_caps_str
 *
 * The input string lives in gsh::g_sta.ht_cap (em_long_string_t[128], as in em_sta_info_t) with guard
 * arrays before and after it (the runner poisons them); NULL input passes NULL. The output buffer is
 * buf_store (caps_str[32] of the caller) with a guard after buf_len (poisoned by the runner).
 *
 * gen 1 builds an HT Capabilities element (16 + extra bytes: capabilities info LE in bytes 0-1, A-MPDU byte 2,
 * the 4 rx MCS bitmask bytes in bytes 3-6, byte 15 = Tx MCS Set flags) and the expected output from a
 * reference encoder written from the layout the function documents: rx_nss = highest rx MCS byte (3..6) that
 * is not 0 (1 when none); tx_nss = rx_nss unless byte 15 has bit 0 (Tx MCS Set Defined) and bit 1 (Tx Rx MCS
 * Set Not Equal), then ((byte15 >> 2) & 3) + 1; one byte (tx_nss-1)<<6 | (rx_nss-1)<<4 | SGI20<<3 (cap bit
 * 5) | SGI40<<2 (cap bit 6) | HT40<<1 (cap bit 1), base64 encoded (4 characters, "xx=="). Rejected input
 * (NULL, empty, odd length, shorter than 32 or longer than 64 hex digits) gives "".
 *
 * Cases marked [spec] are wrong behaviour (no abort): characters that are not hex digits are accepted
 * (unhex() does not validate), so the output is built from garbage instead of being rejected. The case
 * crash_* ABORTS on the original function: an ht_cap of 128 non-NUL bytes (strlen() reads past the array).
 * It runs last and UNFORKED so a plain make stops with the ASan report (FORK_CRASH=1 forks it).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "get_sta_ht_caps_str.h"

namespace gsh {

alignas(16) char buf_store[GSH_BUF_SZ + GSH_GUARD];
sta_ht_t g_sta;
char g_hexbuf[GSH_HT_SZ + 1];
char g_expect[32];
const char *g_in = NULL;

#define B GSH_BUF_SZ
#define M(a, b, c, d) ((unsigned)(a) | ((unsigned)(b) << 8) | ((unsigned)(c) << 16) | ((unsigned)(d) << 24))
/* {name, gen, hex, cap, mcs, b15, extra, upper, buf_len, expect, crash} */
#define G(n, cap, mcs, b15) {n, 1, NULL, cap, mcs, b15, 0, false, B, NULL, false}
#define GE(n, cap, mcs, b15, ex) {n, 1, NULL, cap, mcs, b15, ex, false, B, NULL, false}
#define H(n, hex, exp) {n, 0, hex, 0, 0, 0, 0, false, B, exp, false}

test_case_t suite[] = {
 /* ---- rx spatial streams from the MCS set bytes 3..6 ---- */
 G("ok_rx_nss1", 0, M(0xff, 0, 0, 0), 0), G("ok_rx_nss2", 0, M(0xff, 0xff, 0, 0), 0), G("ok_rx_nss3", 0, M(0xff, 0xff, 0xff, 0), 0),
 G("ok_rx_nss4", 0, M(0xff, 0xff, 0xff, 0xff), 0), G("ok_rx_none_is_1", 0, M(0, 0, 0, 0), 0),
 G("ok_rx_only_stream2_byte", 0, M(0, 0xff, 0, 0), 0), G("ok_rx_gap_stream3", 0, M(0, 0, 0xff, 0), 0), G("ok_rx_only_stream4_byte", 0, M(0, 0, 0, 0x01), 0),
 G("ok_rx_partial_mask", 0, M(0x01, 0x80, 0, 0), 0),
 /* ---- tx spatial streams from byte 15 (Tx MCS Set Defined = bit 0, Tx Rx MCS Set Not Equal = bit 1) ---- */
 G("ok_tx_equal_defined", 0, M(0xff, 0xff, 0, 0), 0x01), G("ok_tx_not_defined", 0, M(0xff, 0xff, 0, 0), 0x02), G("ok_tx_flags_zero", 0, M(0xff, 0xff, 0, 0), 0x00),
 G("ok_tx_explicit_1", 0, M(0xff, 0xff, 0xff, 0xff), 0x03), G("ok_tx_explicit_2", 0, M(0xff, 0xff, 0xff, 0xff), 0x07),
 G("ok_tx_explicit_3", 0, M(0xff, 0xff, 0xff, 0xff), 0x0b), G("ok_tx_explicit_4", 0, M(0xff, 0, 0, 0), 0x0f),
 G("ok_tx_all_bits_set", 0, M(0xff, 0xff, 0, 0), 0xff), G("ok_tx_other_bits_ignored", 0, M(0xff, 0xff, 0, 0), 0xf1),
 /* ---- capability bits ---- */
 G("ok_sgi20", 1u << 5, M(0xff, 0, 0, 0), 0), G("ok_sgi40", 1u << 6, M(0xff, 0, 0, 0), 0), G("ok_ht40", 1u << 1, M(0xff, 0, 0, 0), 0),
 G("ok_all_cap_bits", 0xffff, M(0xff, 0xff, 0xff, 0xff), 0x0f), G("ok_no_cap_bits", 0, M(0xff, 0, 0, 0), 0),
 G("ok_other_cap_bits_ignored", 0xff9d, M(0xff, 0, 0, 0), 0), G("ok_sgi20_ht40", (1u << 5) | (1u << 1), M(0xff, 0xff, 0, 0), 0x01),
 /* ---- element length: 16 bytes (32 digits) up to 32 bytes (64 digits) are accepted ---- */
 GE("ok_len_16_bytes", 0x20, M(0xff, 0, 0, 0), 0, 0), GE("ok_len_26_bytes", 0x20, M(0xff, 0xff, 0, 0), 0x01, 10), GE("ok_len_32_bytes", 0x20, M(0xff, 0, 0, 0), 0, 16),
 {"ok_uppercase_hex", 1, NULL, 0x0062, M(0xff, 0xff, 0xff, 0), 0x0b, 0, true, B, NULL, false},
 /* ---- rejected input ---- */
 {"rej_null_input", 2, NULL, 0, 0, 0, 0, false, B, "", false},
 H("rej_empty", "", ""),
 H("rej_30_digits", "000000000000000000000000000000", ""),
 H("rej_31_digits_odd", "0000000000000000000000000000000", ""),
 H("rej_33_digits_odd", "000000000000000000000000000000000", ""),
 H("rej_single_digit", "0", ""),
 GE("rej_33_bytes", 0x20, M(0xff, 0, 0, 0), 0, 17),
 /* ---- output buffer length (4 characters + NUL = 5) ---- */
 {"ok_buf_len_5", 1, NULL, 0x20, M(0xff, 0, 0, 0), 0, 0, false, 5, NULL, false},
 {"ok_buf_len_3_truncated", 1, NULL, 0x20, M(0xff, 0, 0, 0), 0, 0, false, 3, NULL, false},
 {"ok_buf_len_1", 1, NULL, 0x20, M(0xff, 0, 0, 0), 0, 0, false, 1, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort (non-hex characters are not rejected) ---- */
 H("rej_non_hex_letters [spec]", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", ""),
 H("rej_spaces [spec]", "                                ", ""),
 H("rej_hex_prefix [spec]", "0x000000000000000000000000000000", ""),
 /* ---- CRASH case on the original function (rejected, "" after the fix) ---- */
 {"crash_ht_cap_128_no_nul", 3, NULL, 0, 0, 0, 0, false, B, "", true},

 { NULL, 0, NULL, 0, 0, 0, 0, false, 0, NULL, false }  /* sentinel */
};

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* reference encoder: expected output for an HT element built from cap / mcs / b15 (independent of the function under test) */
static void reference(unsigned int cap, unsigned int mcs, unsigned int b15, char *out)
{
    int rxn = 1;
    for (int i = 0; i < 4; i++)
        if (((mcs >> (8 * i)) & 0xff) != 0) rxn = i + 1;
    int txn = rxn;
    if ((b15 & 1) && (b15 & 2)) txn = (int)((b15 >> 2) & 3) + 1;
    uint8_t d = (uint8_t)(((txn - 1) << 6) | ((rxn - 1) << 4) | (((cap >> 5) & 1) << 3) | (((cap >> 6) & 1) << 2) | (((cap >> 1) & 1) << 1));
    uint32_t v = (uint32_t)d << 16;
    out[0] = b64t[v >> 18]; out[1] = b64t[(v >> 12) & 63]; out[2] = '='; out[3] = '='; out[4] = '\0';
}

void construct_input(const test_case_t *tc)
{
    memset(&g_sta, 0, sizeof(g_sta)); memset(buf_store, 'X', sizeof(buf_store));
    g_expect[0] = '\0';
    g_in = g_sta.ht_cap;
    if (tc->gen == 2) { g_in = NULL; return; }
    if (tc->gen == 3) { memset(g_sta.ht_cap, 'a', sizeof(g_sta.ht_cap)); return; }
    if (tc->gen == 0) { snprintf(g_sta.ht_cap, sizeof(g_sta.ht_cap), "%s", tc->hex); snprintf(g_expect, sizeof(g_expect), "%s", tc->expect); return; }
    uint8_t e[40] = {0};
    e[0] = (uint8_t)(tc->cap & 0xff); e[1] = (uint8_t)((tc->cap >> 8) & 0xff);
    for (int i = 0; i < 4; i++) e[3 + i] = (uint8_t)((tc->mcs >> (8 * i)) & 0xff);
    e[15] = (uint8_t)tc->b15;
    int nb = 16 + tc->extra;
    for (int i = 0; i < nb; i++) snprintf(g_sta.ht_cap + 2 * i, 3, tc->upper ? "%02X" : "%02x", e[i]);
    if (tc->extra > 16) return;                       /* over the 32 byte limit: rejected, expected "" */
    char full[8]; reference(tc->cap, tc->mcs, tc->b15, full);
    snprintf(g_expect, sizeof(g_expect), "%.*s", (int)(tc->buf_len ? tc->buf_len - 1 : 0), tc->expect ? tc->expect : full);
}

void teardown(void) {}

} /* namespace gsh */
