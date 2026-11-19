/*
 * TEST CASES / CONSTRUCTOR: construct_network_sync_db
 *
 * Scripted NetworkList rows (4 columns): 1 ID, 2 ControllerID MAC, 3 ColocatedAgentID MAC, 4 Media 3. "#N" in a string column means N
 * characters. Row 2 (nrows 2) repeats row 0 (variant 0) or has NULL ID and MACs (variant 1). Each string cell lives between poisoned
 * guards (runner). PASS = number of recorded networks, controller / colocated MAC, timestamp intact.
 * Cases that crashed (or corrupted the struct) on the original code are named clamp_*, fix 1 bounds the get_string copies: a MAC column of 18+ characters overflows mac[18], an ID column of
 * about 1000+ characters runs out of the local info (get_string has no size).
 * [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_sync_db.h"

namespace nsd {
#define M1 "aa:bb:cc:dd:ee:01"
#define M2 "aa:bb:cc:dd:ee:02"
/* {name, id, ctrl_mac, colo_mac, nrows, row2_variant, expect_updates, expect_ctrl, expect_colo, expect_ts_intact, expect_row2_ctrl_zero, crash} */
test_case_t suite[] = {
 {"ok_no_rows",                         "net", M1, M2, 0, 0, 0, NULL, NULL, 0, 0, false},
 {"ok_one_row",                         "net", M1, M2, 1, 0, 1, M1, M2, 1, 0, false},
 {"ok_compact_macs",                    "net", "aabbccddee01", "aabbccddee02", 1, 0, 1, M1, M2, 1, 0, false},
 {"ok_id_127_chars_fits",               "#127", M1, M2, 1, 0, 1, M1, M2, 1, 0, false},
 {"ok_empty_id",                        "", M1, M2, 1, 0, 1, M1, M2, 1, 0, false},
 {"ok_mac_17_chars_fits_buffer",        "net", M1, M2, 1, 0, 1, M1, M2, 1, 0, false},
 {"ok_null_id_column",                  NULL, M1, M2, 1, 0, 1, M1, M2, 1, 0, false},
 {"ok_two_identical_rows",              "net", M1, M2, 2, 0, 2, M1, M2, 1, 0, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"clamp_id_200_chars_must_not_corrupt_timestamp", "#200", M1, M2, 1, 0, 1, M1, M2, 1, 0, false},
 {"spec_null_row_must_not_keep_previous_macs [spec]",    "net", M1, M2, 2, 1, 2, M1, M2, 1, 1, false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_ctrl_mac_18_chars",            "net", "aa:bb:cc:dd:ee:01x", M2, 1, 0, 1, NULL, NULL, 0, 0, false},
 {"clamp_ctrl_mac_200_chars",           "net", "#200", M2, 1, 0, 1, NULL, NULL, 0, 0, false},
 {"clamp_colocated_mac_18_chars",       "net", M1, "aa:bb:cc:dd:ee:02x", 1, 0, 1, NULL, NULL, 0, 0, false},
 {"clamp_colocated_mac_200_chars",      "net", M1, "#200", 1, 0, 1, NULL, NULL, 0, 0, false},
 {"clamp_id_1500_chars_overflows_info", "#1500", M1, M2, 1, 0, 1, NULL, NULL, 0, 0, false},
 {"clamp_id_4000_chars_overflows_info", "#4000", M1, M2, 1, 0, 1, NULL, NULL, 0, 0, false},
 {NULL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL, 0, 0, false}
};

static void set_str(cell_t *c, const char *s, char fill)
{
    c->kind = 1;
    if (s[0] == '#') { size_t n = (size_t)atoi(s + 1); if (n >= NSD_CELL_SZ) n = NSD_CELL_SZ - 1; memset(c->s, fill, n); c->s[n] = 0; }
    else snprintf(c->s, sizeof(c->s), "%s", s);
}
static void fill_row(row_t *r, const test_case_t *tc)
{
    memset(r, 0, sizeof(*r));
    if (tc->id) set_str(&r->c[0], tc->id, 'I');
    if (tc->ctrl_mac) set_str(&r->c[1], tc->ctrl_mac, 'a');
    if (tc->colo_mac) set_str(&r->c[2], tc->colo_mac, 'a');
    r->c[3].kind = 2; r->c[3].num = 3;
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows)); g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc);
    if (tc->nrows >= 2 && tc->row2_variant == 1) { g_rows[1].c[0].kind = 0; g_rows[1].c[1].kind = 0; g_rows[1].c[2].kind = 0; }
    dm_network_list_t::g_updates.clear();
}
void teardown(void) { dm_network_list_t::g_updates.clear(); }
} /* namespace nsd */
