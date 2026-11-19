/*
 * TEST CASES / CONSTRUCTOR: construct_policy_sync_db
 *
 * Scripted PolicyList rows (18 columns, SQL order): 1 ID "OneWifiMesh@02:00:00:00:00:01@02:00:00:00:00:02@1", 2 PolicyType 2,
 * 3 APMetricsInterval 5, 4 STAList (the case's sta_list), 5 SteeringPolicyType 1, 6 RepInterval 7, 7 RCPI threshold 60, 8 hysteresis 5,
 * 9 util threshold 70, 10..12 flags 1/1/0, 13 ManagedClientMarker "mm", 14 independent scan 1, 15/16 profile flags 0/1, 17 vid 100, 18 pcp 3.
 * sta_list shorthand: "@N" = N MACs aa:bb:cc:dd:ee:01.. separated by commas, "$N" = N compact MACs 0200000000nn, "#N" = N characters 'A' (no comma), "%N" = one token of N
 * characters. get_strings_by_token() copies the list into a 256 byte buffer, so colon MACs (18 characters each) are cut after about 14 entries.
 * Row 2 (nrows 2) repeats row 0 (variant 0), has a NULL STAList (variant 1) or a NULL ID (variant 2).
 * Each string cell lives between poisoned guards (runner). [spec] cases: no abort. Cases named crash_* ABORT on the original code
 * (assert in get_strings_by_token / stack overflow in get_string): they run last and UNFORKED so a plain `make` stops with the report;
 * FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy_sync_db.h"

namespace spl {
/* {name, sta_list, nrows, row2_variant, expect_updates, expect_num_sta, expect_mac0, expect_interval, expect_num_sta2, crash} */
test_case_t suite[] = {
 {"ok_two_stas",                         "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02", 1, 0, 1, 2, "aa:bb:cc:dd:ee:01", -1, -1, false},
 {"ok_one_sta",                          "aa:bb:cc:dd:ee:01", 1, 0, 1, 1, "aa:bb:cc:dd:ee:01", -1, -1, false},
 {"ok_empty_sta_list",                   "", 1, 0, 1, 0, NULL, -1, -1, false},
 {"ok_null_sta_list_first_row",          NULL, 1, 0, 1, 0, NULL, -1, -1, false},
 {"ok_no_rows",                          "aa:bb:cc:dd:ee:01", 0, 0, 0, -1, NULL, -1, -1, false},
 {"ok_two_rows_same_list",               "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02", 2, 0, 2, 2, NULL, -1, 2, false},
 {"ok_15_stas",                          "@15", 1, 0, 1, 15, "aa:bb:cc:dd:ee:01", -1, -1, false},
 {"ok_16_stas_compact_largest_valid",     "$16", 1, 0, 1, 16, "02:00:00:00:00:01", -1, -1, false},
 {"ok_compact_mac_tokens",               "0200000000aa,0200000000bb", 1, 0, 1, 2, "02:00:00:00:00:aa", -1, -1, false},
 {"ok_token_longer_than_63_truncated",   "%100", 1, 0, 1, 1, NULL, -1, -1, false},
 {"ok_list_of_1000_chars_fits_buffer",   "#1000", 1, 0, 1, 1, NULL, -1, -1, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_16_colon_stas_cut_at_255_chars [spec]", "@16", 1, 0, 1, 16, "aa:bb:cc:dd:ee:01", -1, -1, false},
 {"spec_interval_must_be_ap_metrics_column [spec]", "aa:bb:cc:dd:ee:01", 1, 0, 1, 1, NULL, 5, -1, false},
 {"spec_null_sta_list_must_not_keep_previous_row [spec]", "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02", 2, 1, 2, 2, NULL, -1, 0, false},
 /* ---- CRASH cases on the original code: run last, unforked ---- */
 {"crash_sta_list_17_entries_assert",    "$17", 1, 0, 1, 16, "02:00:00:00:00:01", -1, -1, true},
 {"crash_sta_list_40_entries_assert",    "$40", 1, 0, 1, 16, "02:00:00:00:00:01", -1, -1, true},
 {"crash_sta_list_1100_chars_overflow",  "#1100", 1, 0, 1, 1, NULL, -1, -1, true},
 {"crash_sta_list_2000_chars_overflow",  "#2000", 1, 0, 1, 1, NULL, -1, -1, true},
 {NULL, NULL, 0, 0, 0, 0, NULL, 0, 0, false}
};

static void set_str(cell_t *c, const char *s) { c->kind = 1; snprintf(c->s, sizeof(c->s), "%s", s); }
static void set_num(cell_t *c, int n) { c->kind = 2; c->num = n; }
static void fill_row(row_t *r, const char *sta_list)
{
    memset(r, 0, sizeof(*r));
    set_str(&r->c[0], "OneWifiMesh@02:00:00:00:00:01@02:00:00:00:00:02@1");
    set_num(&r->c[1], 2); set_num(&r->c[2], 5);
    if (sta_list) {
        char *buf = (char *)calloc(1, 4096);
        if (sta_list[0] == '@') { int n = atoi(sta_list + 1); for (int i = 1; i <= n; i++) { char m[24]; snprintf(m, sizeof(m), "%saa:bb:cc:dd:ee:%02x", i > 1 ? "," : "", i); strcat(buf, m); } }
        else if (sta_list[0] == '$') { int n = atoi(sta_list + 1); for (int i = 1; i <= n; i++) { char m[24]; snprintf(m, sizeof(m), "%s02000000%04x", i > 1 ? "," : "", i); strcat(buf, m); } }
        else if (sta_list[0] == '#') { int n = atoi(sta_list + 1); memset(buf, 'A', (size_t)n); }
        else if (sta_list[0] == '%') { int n = atoi(sta_list + 1); memset(buf, 'B', (size_t)n); }
        else snprintf(buf, 4096, "%s", sta_list);
        if (strlen(buf) >= SPL_CELL_SZ) buf[SPL_CELL_SZ - 1] = 0;
        set_str(&r->c[3], buf); free(buf);
    }
    set_num(&r->c[4], 1); set_num(&r->c[5], 7); set_num(&r->c[6], 60); set_num(&r->c[7], 5); set_num(&r->c[8], 70);
    set_num(&r->c[9], 1); set_num(&r->c[10], 1); set_num(&r->c[11], 0); set_str(&r->c[12], "mm"); set_num(&r->c[13], 1);
    set_num(&r->c[14], 0); set_num(&r->c[15], 1); set_num(&r->c[16], 100); set_num(&r->c[17], 3);
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows));
    g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc->sta_list);
    if (tc->nrows >= 2) {
        if (tc->row2_variant == 1) g_rows[1].c[3].kind = 0;
        if (tc->row2_variant == 2) g_rows[1].c[0].kind = 0;
    }
    dm_policy_list_t::g_updates.clear();
}
void teardown(void) { dm_policy_list_t::g_updates.clear(); }
} /* namespace spl */
