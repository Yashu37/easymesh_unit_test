/*
 * TEST CASES / CONSTRUCTOR: construct_sta_compare_db
 *
 * Scripted StaList rows (22 columns): 1 MAC aa:bb:cc:dd:ee:01, 2 BSSID ..02, 3 radio MAC ..03, 4 associated 1, 5-8 rates 10/20/30/40,
 * 9 last_conn_time 50, 10 retrans 60, 11 signal -55, 12 rcpi 70, 13-20 util/pkts/bytes/errors (13 util_tx 1, 14 util_rx 2, 15 pkts_tx = case value,
 * 16 3, 17 4, 18 5, 19 6, 20 7), 21 frame_body_len, 22 frame body hex. The station handed to compare_db is built from the same values
 * (sta_matches) so a faithful compare returns true; sta_matches false changes its rcpi.
 * Cases that ABORTED on the original code are named clamp_* (fix 1 skips the row when a MAC column does not fit mac[18]): a MAC column of 18+
 * characters overflows mac[18] (get_string has no size). Frame body columns of any length are safe since #857 (the body is a vector, a column
 * longer than EM_MAX_FRAME_BODY_LEN * 2 characters is rejected before it is read): those cases are plain ok_ cases.
 * [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sta_compare_db.h"

namespace scd {
/* {name, mac, fb, nrows, sta_matches, pkts_tx, variant, expect_ret, crash, big_col, skip_row, null_col} */
test_case_t suite[] = {
 {"ok_no_rows",                          "aa:bb:cc:dd:ee:01", "0102ab", 0, true, 9, 0, false, false},
 {"ok_matching_row_returns_true",        "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 9, 0, true, false},
 {"ok_row_differs_returns_false",        "aa:bb:cc:dd:ee:01", "0102ab", 1, false, 9, 0, false, false},
 {"ok_second_row_matches",               "aa:bb:cc:dd:ee:01", "0102ab", 2, true, 9, 0, true, false},
 {"ok_empty_frame_body",                 "aa:bb:cc:dd:ee:01", "", 1, true, 9, 0, true, false},
 {"ok_one_byte_frame_body",              "aa:bb:cc:dd:ee:01", "7f", 1, true, 9, 0, true, false},
 {"ok_compact_mac",                      "aabbccddee01", "0102ab", 1, true, 9, 0, true, false},
 {"ok_mac_17_chars_fits_buffer",         "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 9, 0, true, false},
 {"ok_frame_body_1022_chars",            "aa:bb:cc:dd:ee:01", "#1022", 1, false, 9, 0, false, false},
 {"ok_frame_body_1023_chars_fits",       "aa:bb:cc:dd:ee:01", "#1023", 1, false, 9, 0, false, false},
 {"ok_frame_body_odd_length",            "aa:bb:cc:dd:ee:01", "0102a", 1, false, 9, 0, false, false},
 {"ok_null_mac_column",                  NULL, "0102ab", 1, false, 9, 0, false, false},
 {"ok_null_frame_body_column",            "aa:bb:cc:dd:ee:01", NULL, 1, true, 9, 0, true, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"ok_uppercase_hex_body", "aa:bb:cc:dd:ee:01", "0102AB", 1, true, 9, 0, true, false},
 {"spec_pkts_tx_1000_must_match [spec]", "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 1000, 0, true, false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_mac_18_chars",                  "aa:bb:cc:dd:ee:01x", "0102ab", 1, false, 9, 0, false, false},
 {"clamp_mac_200_chars",                 "#200", "0102ab", 1, false, 9, 0, false, false},
 {"ok_frame_body_1024_chars_at_limit",   "aa:bb:cc:dd:ee:01", "#1024", 1, false, 9, 0, false, false},
 {"ok_frame_body_1026_chars_rejected",   "aa:bb:cc:dd:ee:01", "#1026", 1, false, 9, 0, false, false},
 {"ok_frame_body_4000_chars_rejected",   "aa:bb:cc:dd:ee:01", "#4000", 1, false, 9, 0, false, false},
 /* ---- the row with a MAC column that does not fit mac[18] is skipped as a whole (all other columns match) ---- */
 {"skip_row_mac_18_chars",               "aa:bb:cc:dd:ee:01x", "0102ab", 1, true, 9, 0, false, false, 0, true},
 {"skip_row_mac_200_chars",              "#200", "0102ab", 1, true, 9, 0, false, false, 0, true},
 {"skip_row_bssid_200_chars",            "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 9, 0, false, false, 2, true},
 {"skip_row_radio_mac_200_chars",        "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 9, 0, false, false, 3, true},
 {"ok_oversized_first_row_second_matches", "aa:bb:cc:dd:ee:01x", "0102ab", 2, true, 9, 0, true, false},
 {"ok_oversized_bssid_first_row_second_matches", "aa:bb:cc:dd:ee:01", "0102ab", 2, true, 9, 0, true, false, 2},
 /* ---- SQL NULL MAC column: the row is skipped, a stale mac[] must not be used (the station carries the stale MAC) ---- */
 {"skip_row_null_bssid_not_stale_mac",   "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 9, 0, false, false, 0, false, 2},
 {"skip_row_null_radio_mac_not_stale_mac", "aa:bb:cc:dd:ee:01", "0102ab", 1, true, 9, 0, false, false, 0, false, 3},
 {"ok_null_bssid_first_row_second_matches", "aa:bb:cc:dd:ee:01", "0102ab", 2, true, 9, 0, true, false, 0, false, 2},
 {NULL, NULL, NULL, 0, false, 0, 0, false, false}
};

static void set_str(cell_t *c, const char *s) { c->kind = 1; snprintf(c->s, sizeof(c->s), "%s", s); }
static void set_num(cell_t *c, int n) { c->kind = 2; c->num = n; }
static void fill_row(row_t *r, const test_case_t *tc, int idx)
{
    memset(r, 0, sizeof(*r));
    if (tc->mac && idx > 0) set_str(&r->c[0], "aa:bb:cc:dd:ee:01");      /* only the first row carries the case's MAC column */
    else if (tc->mac) {
        if (tc->mac[0] == '#') { char *b = (char *)calloc(1, 4096); memset(b, 'a', (size_t)atoi(tc->mac + 1)); set_str(&r->c[0], b); free(b); }
        else set_str(&r->c[0], tc->mac);
    }
    set_str(&r->c[1], "aa:bb:cc:dd:ee:02"); set_str(&r->c[2], "aa:bb:cc:dd:ee:03");
    if (idx == 0 && tc->null_col >= 2) r->c[tc->null_col - 1].kind = 0;
    if (idx == 0 && tc->big_col >= 2) { char b[256]; memset(b, 'b', 200); b[200] = 0; set_str(&r->c[tc->big_col - 1], b); }
    set_num(&r->c[3], 1); set_num(&r->c[4], 10); set_num(&r->c[5], 20); set_num(&r->c[6], 30); set_num(&r->c[7], 40);
    set_num(&r->c[8], 50); set_num(&r->c[9], 60); set_num(&r->c[10], -55); set_num(&r->c[11], 70);
    set_num(&r->c[12], 1); set_num(&r->c[13], 2); set_num(&r->c[14], tc->pkts_tx); set_num(&r->c[15], 3); set_num(&r->c[16], 4);
    set_num(&r->c[17], 5); set_num(&r->c[18], 6); set_num(&r->c[19], 7);
    if (tc->fb) {
        char *b = (char *)calloc(1, 8192);
        if (tc->fb[0] == '#') memset(b, '1', (size_t)atoi(tc->fb + 1)); else snprintf(b, 8192, "%s", tc->fb);
        if (strlen(b) >= SCD_CELL_SZ) b[SCD_CELL_SZ - 1] = 0;
        set_str(&r->c[21], b); set_num(&r->c[20], (int)(strlen(b) / 2)); free(b);
    }
}
static unsigned char g_sta_body[EM_MAX_FRAME_BODY_LEN];   /* the station's frame body (the pointer member points here) */
static void build_sta(const test_case_t *tc)
{
    em_sta_info_t *s = &g_sta.m_sta_info; memset(s, 0, sizeof(*s));
    unsigned char m1[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01}, m2[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x02}, m3[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x03};
    memcpy(s->id, m1, 6); memcpy(s->bssid, m2, 6); memcpy(s->radiomac, m3, 6);
    s->associated = true; s->last_ul_rate = 10; s->last_dl_rate = 20; s->est_ul_rate = 30; s->est_dl_rate = 40; s->last_conn_time = 50;
    s->retrans_count = 60; s->signal_strength = -55; s->rcpi = tc->sta_matches ? 70 : 71;
    s->util_tx = 1; s->util_rx = 2; s->pkts_tx = (unsigned)tc->pkts_tx; s->pkts_rx = 3; s->bytes_tx = 4; s->bytes_rx = 5; s->errors_tx = 6; s->errors_rx = 7;
    if (tc->fb && tc->fb[0] != '#') {
        size_t n = strlen(tc->fb) / 2; if (n > EM_MAX_FRAME_BODY_LEN) n = EM_MAX_FRAME_BODY_LEN; s->frame_body_len = (unsigned)n;
        for (size_t i = 0; i < n; i++) { unsigned v = 0; char h[3] = { tc->fb[2*i], tc->fb[2*i+1], 0 }; sscanf(h, "%x", &v); g_sta_body[i] = (unsigned char)v; }
        if (n > 0) s->frame_body = g_sta_body;
    }
    if (tc->null_col == 2 && tc->nrows == 1) memcpy(s->bssid, m1, 6);        /* what a stale mac[] would give: the previous column's MAC */
    if (tc->null_col == 3 && tc->nrows == 1) memcpy(s->radiomac, m2, 6);
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows)); g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc, i);
    if (tc->nrows >= 2) { g_rows[0].c[11].num = 99; }   /* the first of two rows differs (rcpi), the second one matches */
    build_sta(tc);
}
void teardown(void) {}
} /* namespace scd */
