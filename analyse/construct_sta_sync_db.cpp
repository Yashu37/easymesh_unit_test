/*
 * TEST CASES / CONSTRUCTOR: construct_sta_sync_db
 *
 * Scripted StaList rows (22 columns): 1 MAC, 2 BSSID, 3 RUID, 4 associated 1, 5-20 numbers, 21 frame_body_len, 22 frame body hex.
 * "#N" in a MAC column means N characters 'a', in the frame body column N characters '1'. Row 2 (nrows 2) repeats row 0 (variant 0),
 * has NULL MAC columns (variant 1) or a NULL frame body (variant 2). Each string cell lives between poisoned guards (runner). PASS =
 * recorded stations, station MAC, first frame body byte and, for the second row, MAC / first byte.
 * Cases named crash_* ABORT on the original code: a MAC column of 18+ characters overflows mac[18], a frame body column of 1024+
 * characters overflows frame_body[1024] (get_string has no size). They run last and UNFORKED so a plain `make` stops with the
 * report; FORK_CRASH=1 forks each one. A NULL frame body column on the first row leaves frame_body uninitialised (strlen on stack
 * garbage); ASan's fake stack hands out zeroed frames, so that abort could not be reproduced. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sta_sync_db.h"

namespace ssd {
#define M1 "aa:bb:cc:dd:ee:01"
#define M2 "aa:bb:cc:dd:ee:02"
#define M3 "aa:bb:cc:dd:ee:03"
/* {name, mac1, mac2, mac3, fb, nrows, row2_variant, updates, expect_id, b0, row2_id_zero, row2_b0, crash} */
test_case_t suite[] = {
 {"ok_no_rows",                         M1, M2, M3, "0102ab", 0, 0, 0, NULL, -1, 0, -1, false},
 {"ok_one_row",                         M1, M2, M3, "0102ab", 1, 0, 1, M1, 0x01, 0, -1, false},
 {"ok_compact_macs",                    "aabbccddee01", "aabbccddee02", "aabbccddee03", "0102ab", 1, 0, 1, M1, 0x01, 0, -1, false},
 {"ok_empty_frame_body",                M1, M2, M3, "", 1, 0, 1, M1, 0, 0, -1, false},
 {"ok_one_byte_frame_body",             M1, M2, M3, "7f", 1, 0, 1, M1, 0x7f, 0, -1, false},
 {"ok_uppercase_frame_body",            M1, M2, M3, "AB12", 1, 0, 1, M1, 0xab, 0, -1, false},
 {"ok_mac_17_chars_fits_buffer",        M1, M2, M3, "0102ab", 1, 0, 1, M1, 0x01, 0, -1, false},
 {"ok_frame_body_1022_chars",           M1, M2, M3, "#1022", 1, 0, 1, M1, 0x11, 0, -1, false},
 {"ok_frame_body_1023_chars_fits",      M1, M2, M3, "#1023", 1, 0, 1, M1, 0x11, 0, -1, false},
 {"ok_frame_body_odd_length",           M1, M2, M3, "0102a", 1, 0, 1, M1, 0x01, 0, -1, false},
 {"ok_two_identical_rows",              M1, M2, M3, "0102ab", 2, 0, 2, M1, 0x01, 0, 0x01, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_null_mac_columns_must_not_keep_previous_row [spec]", M1, M2, M3, "0102ab", 2, 1, 2, M1, 0x01, 1, -1, false},
 {"spec_null_frame_body_must_not_keep_previous_row [spec]",  M1, M2, M3, "0102ab", 2, 2, 2, M1, 0x01, 0, 0, false},
 /* ---- CRASH cases on the original code: run last, unforked ---- */
 {"crash_mac_18_chars",                 "aa:bb:cc:dd:ee:01x", M2, M3, "0102ab", 1, 0, 1, NULL, -1, 0, -1, true},
 {"crash_mac_200_chars",                "#200", M2, M3, "0102ab", 1, 0, 1, NULL, -1, 0, -1, true},
 {"crash_bssid_18_chars",               M1, "aa:bb:cc:dd:ee:02x", M3, "0102ab", 1, 0, 1, NULL, -1, 0, -1, true},
 {"crash_radio_mac_18_chars",           M1, M2, "aa:bb:cc:dd:ee:03x", "0102ab", 1, 0, 1, NULL, -1, 0, -1, true},
 {"crash_frame_body_1024_chars",        M1, M2, M3, "#1024", 1, 0, 1, NULL, -1, 0, -1, true},
 {"crash_frame_body_4000_chars",        M1, M2, M3, "#4000", 1, 0, 1, NULL, -1, 0, -1, true},
 {NULL, NULL, NULL, NULL, NULL, 0, 0, 0, NULL, 0, 0, 0, false}
};

static void set_str(cell_t *c, const char *v, char fill)
{
    c->kind = 1;
    if (v[0] == '#') { size_t n = (size_t)atoi(v + 1); if (n >= SSD_CELL_SZ) n = SSD_CELL_SZ - 1; memset(c->s, fill, n); c->s[n] = 0; }
    else snprintf(c->s, sizeof(c->s), "%s", v);
}
static void fill_row(row_t *r, const test_case_t *tc)
{
    memset(r, 0, sizeof(*r));
    if (tc->mac1) set_str(&r->c[0], tc->mac1, 'a'); if (tc->mac2) set_str(&r->c[1], tc->mac2, 'a'); if (tc->mac3) set_str(&r->c[2], tc->mac3, 'a');
    for (int i = 3; i < 20; i++) { r->c[i].kind = 2; r->c[i].num = i; }
    if (tc->fb) { set_str(&r->c[21], tc->fb, '1'); r->c[20].kind = 2; r->c[20].num = (int)(strlen(r->c[21].s) / 2); }
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows)); g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc);
    if (tc->nrows >= 2) {
        if (tc->row2_variant == 1) { g_rows[1].c[0].kind = 0; g_rows[1].c[1].kind = 0; g_rows[1].c[2].kind = 0; }
        if (tc->row2_variant == 2) g_rows[1].c[21].kind = 0;
    }
    dm_sta_list_t::g_updates.clear();
}
void teardown(void) { dm_sta_list_t::g_updates.clear(); }
} /* namespace ssd */
