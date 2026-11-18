/*
 * TEST CASES / CONSTRUCTOR: construct_get_sta_vht_caps_str
 *
 * The input string lives in gsv::g_sta.vht_cap (em_long_string_t[128], as in em_sta_info_t) with guard
 * arrays before and after it (the runner poisons them); NULL input passes NULL. The output buffer is
 * buf_store (caps_str[32] of the caller) with a guard after buf_len (poisoned by the runner).
 *
 * gen 1 builds a VHT Capabilities element (12 bytes: capabilities info LE, rx MCS map LE, rx highest
 * rate, tx MCS map LE, tx highest rate, plus 0..5 extra bytes) and the expected output from a reference
 * encoder written from the layout the function documents: byte 0-1 tx map (big endian), 2-3 rx map,
 * byte 4 = (tx_nss-1)<<5 | (rx_nss-1)<<2 | SGI80<<1 | SGI160 (cap bits 5, 6), byte 5 = 80+80<<7 |
 * 160<<6 | SU beamformer<<5 | MU beamformer<<4 (cap bits 11, 19, supported channel width set cap bits
 * 2-3), nss = highest stream whose 2-bit map value is not 3 (1 when none), base64 of the 6 bytes.
 * Rejected input (NULL, empty, odd length, shorter than 24 or longer than 32 hex digits) gives "".
 *
 * Cases marked [spec] are wrong behaviour (no abort): characters that are not hex digits are accepted
 * (unhex() does not validate), so the output is built from garbage instead of being rejected. The case
 * rej_vht_cap_128_no_nul ABORTED on the original function (a vht_cap of 128 non-NUL bytes: strlen() reads
 * past the array); with fix 1 (bounded strnlen) it is rejected (""). A case flagged crash=true would run
 * last and UNFORKED (FORK_CRASH=1 forks it).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "get_sta_vht_caps_str.h"

namespace gsv {

alignas(16) char buf_store[GSV_BUF_SZ + GSV_GUARD];
sta_vht_t g_sta;
char g_hexbuf[GSV_VHT_SZ + 1];
char g_expect[32];
const char *g_in = NULL;

#define B GSV_BUF_SZ
/* {name, gen, hex, cap, rx, tx, extra, upper, buf_len, expect, crash} */
#define G(n, cap, rx, tx) {n, 1, NULL, cap, rx, tx, 0, false, B, NULL, false}
#define GE(n, cap, rx, tx, ex) {n, 1, NULL, cap, rx, tx, ex, false, B, NULL, false}
#define H(n, hex, exp) {n, 0, hex, 0, 0, 0, 0, false, B, exp, false}
#define ZEROS12 "000000000000000000000000"

test_case_t suite[] = {
 /* ---- MCS / NSS maps: rx and tx stream count 1..8 ---- */
 G("ok_nss1", 0, 0xfffe, 0xfffe), G("ok_nss2", 0, 0xfffa, 0xfffa), G("ok_nss3", 0, 0xffea, 0xffea), G("ok_nss4", 0, 0xffaa, 0xffaa),
 G("ok_nss5", 0, 0xfeaa, 0xfeaa), G("ok_nss6", 0, 0xfaaa, 0xfaaa), G("ok_nss7", 0, 0xeaaa, 0xeaaa), G("ok_nss8", 0, 0xaaaa, 0xaaaa),
 G("ok_rx2_tx1", 0, 0xfffa, 0xfffe), G("ok_rx4_tx2", 0, 0xffaa, 0xfffa), G("ok_rx1_tx8", 0, 0xfffe, 0xaaaa),
 G("ok_no_stream_supported", 0, 0xffff, 0xffff), G("ok_maps_zero", 0, 0x0000, 0x0000),
 G("ok_mcs_9_value", 0, 0xfffe, 0xfffe), G("ok_gap_in_streams", 0, 0xfffa, 0xffbf),
 /* ---- capability bits ---- */
 G("ok_sgi80", 1u << 5, 0xfffa, 0xfffa), G("ok_sgi160", 1u << 6, 0xfffa, 0xfffa), G("ok_sgi80_160", (1u << 5) | (1u << 6), 0xfffa, 0xfffa),
 G("ok_su_beamformer", 1u << 11, 0xfffa, 0xfffa), G("ok_mu_beamformer", 1u << 19, 0xfffa, 0xfffa),
 G("ok_cw_set_0", 0, 0xfffa, 0xfffa), G("ok_cw_set_1_160", 1u << 2, 0xfffa, 0xfffa), G("ok_cw_set_2_80p80", 2u << 2, 0xfffa, 0xfffa),
 G("ok_all_cap_bits", 0xffffffffu, 0xaaaa, 0xaaaa), G("ok_other_cap_bits_ignored", 0x0000f81bu, 0xfffa, 0xfffa),
 G("ok_cap_bit_31", 1u << 31, 0xfffa, 0xfffa),
 /* ---- element length: 12 bytes (24 digits) up to 16 bytes (32 digits) are accepted ---- */
 GE("ok_len_12_bytes", 0x20, 0xfffa, 0xfffa, 0), GE("ok_len_14_bytes", 0x20, 0xfffa, 0xfffa, 2), GE("ok_len_16_bytes", 0x20, 0xfffa, 0xfffa, 4),
 {"ok_uppercase_hex", 1, NULL, 0x00000820, 0xffea, 0xfffa, 0, true, B, NULL, false},
 /* ---- rejected input ---- */
 {"rej_null_input", 2, NULL, 0, 0, 0, 0, false, B, "", false},
 H("rej_empty", "", ""),
 H("rej_22_digits", "0000000000000000000000", ""),
 H("rej_23_digits_odd", "00000000000000000000000", ""),
 H("rej_25_digits_odd", "0000000000000000000000000", ""),
 H("rej_33_digits_odd", "000000000000000000000000000000000", ""),
 GE("rej_17_bytes", 0x20, 0xfffa, 0xfffa, 5),
 H("rej_single_digit", "0", ""),
 /* ---- output buffer length ---- */
 {"ok_buf_len_9", 1, NULL, 0x20, 0xfffa, 0xfffa, 0, false, 9, NULL, false},
 {"ok_buf_len_5_truncated", 1, NULL, 0x20, 0xfffa, 0xfffa, 0, false, 5, NULL, false},
 {"ok_buf_len_1", 1, NULL, 0x20, 0xfffa, 0xfffa, 0, false, 1, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort (non-hex characters are not rejected) ---- */
 H("rej_non_hex_letters [spec]", "zzzzzzzzzzzzzzzzzzzzzzzz", ""),
 H("rej_spaces [spec]", "                        ", ""),
 H("rej_hex_prefix [spec]", "0x0000000000000000000000", ""),
 /* ---- was the CRASH case on the original function (rejected after the fix) ---- */
 {"rej_vht_cap_128_no_nul", 3, NULL, 0, 0, 0, 0, false, B, "", false},

 { NULL, 0, NULL, 0, 0, 0, 0, false, 0, NULL, false }  /* sentinel */
};

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* reference encoder: expected output for a VHT element built from cap / rx / tx (independent of the function under test) */
static void reference(unsigned int cap, unsigned int rx, unsigned int tx, char *out)
{
    int rxn = 1, txn = 1;
    for (int i = 0; i < 8; i++) {
        if (((rx >> (2 * i)) & 3) != 3) rxn = i + 1;
        if (((tx >> (2 * i)) & 3) != 3) txn = i + 1;
    }
    unsigned cw = (cap >> 2) & 3;
    uint8_t d[6];
    d[0] = (uint8_t)((tx >> 8) & 0xff); d[1] = (uint8_t)(tx & 0xff);
    d[2] = (uint8_t)((rx >> 8) & 0xff); d[3] = (uint8_t)(rx & 0xff);
    d[4] = (uint8_t)(((txn - 1) << 5) | ((rxn - 1) << 2) | (((cap >> 5) & 1) << 1) | ((cap >> 6) & 1));
    d[5] = (uint8_t)(((cw == 2) << 7) | ((cw >= 1) << 6) | (((cap >> 11) & 1) << 5) | (((cap >> 19) & 1) << 4));
    for (int i = 0; i < 2; i++) {
        uint32_t v = (uint32_t)(d[3 * i] << 16) | (uint32_t)(d[3 * i + 1] << 8) | d[3 * i + 2];
        out[4 * i] = b64t[v >> 18]; out[4 * i + 1] = b64t[(v >> 12) & 63]; out[4 * i + 2] = b64t[(v >> 6) & 63]; out[4 * i + 3] = b64t[v & 63];
    }
    out[8] = '\0';
}

void construct_input(const test_case_t *tc)
{
    memset(&g_sta, 0, sizeof(g_sta)); memset(buf_store, 'X', sizeof(buf_store));
    g_expect[0] = '\0';
    g_in = g_sta.vht_cap;
    if (tc->gen == 2) { g_in = NULL; return; }
    if (tc->gen == 3) { memset(g_sta.vht_cap, 'a', sizeof(g_sta.vht_cap)); return; }
    if (tc->gen == 0) { snprintf(g_sta.vht_cap, sizeof(g_sta.vht_cap), "%s", tc->hex); snprintf(g_expect, sizeof(g_expect), "%s", tc->expect); return; }
    uint8_t e[16] = {0};
    e[0] = (uint8_t)(tc->cap & 0xff); e[1] = (uint8_t)((tc->cap >> 8) & 0xff); e[2] = (uint8_t)((tc->cap >> 16) & 0xff); e[3] = (uint8_t)((tc->cap >> 24) & 0xff);
    e[4] = (uint8_t)(tc->rx & 0xff); e[5] = (uint8_t)((tc->rx >> 8) & 0xff);
    e[8] = (uint8_t)(tc->tx & 0xff); e[9] = (uint8_t)((tc->tx >> 8) & 0xff);
    int nb = 12 + tc->extra;
    for (int i = 0; i < nb; i++) snprintf(g_sta.vht_cap + 2 * i, 3, tc->upper ? "%02X" : "%02x", e[i < 16 ? i : 15]);
    if (tc->extra > 4) { g_expect[0] = '\0'; return; }
    char full[16]; reference(tc->cap, tc->rx, tc->tx, full);
    snprintf(g_expect, sizeof(g_expect), "%.*s", (int)(tc->buf_len ? tc->buf_len - 1 : 0), tc->expect ? tc->expect : full);
}

void teardown(void) {}

} /* namespace gsv */
