/*
 * TEST CASES / CONSTRUCTOR: construct_opclass_sync_db
 *
 * Scripted OperatingClassList rows (11 columns): 1 ID "02:00:00:00:00:01@<type>@<op class>", 2 OpClass 115, 3 Channel (case value),
 * 4 channel list, 5 preference list, 6 PrefValid 1, 7 TxPower 20, 8 MaxTxPower 30, 9-11 CAC values 1/2/3. Column shorthand: "=" default,
 * "@N" N entries (channels 1..N), "#N" N characters, NULL = SQL NULL. Each string cell lives between poisoned guards (runner). PASS =
 * recorded op classes, num_channels, first / last channel, first preference, channel column and second row channel count.
 * Cases named clamp_* ABORTED on the original code (assert in get_strings_by_token for 65+ list entries, stack overflow in get_string
 * for an ID longer than 127 / a list longer than 255 characters): fix 1 bounds the get_string copies, fix 2 ignores surplus entries.
 * [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opclass_sync_db.h"

namespace ocs {
#define D "="
/* {name, id, chans, prefs, type, channel, nrows, row2_chans_null, updates, nch, pref0, chan0, chan_last, channel, row2_nch, crash} */
test_case_t suite[] = {
 {"ok_no_rows",                          D, D, D, 1, 36, 0, 0, 0, -1, -1, -1, -1, -1, -1, false},
 {"ok_current_three_channels",           D, "36,40,44", D, 1, 36, 1, 0, 1, 3, -1, 36, 44, 36, -1, false},
 {"ok_empty_channel_list",               D, "", D, 1, 36, 1, 0, 1, 0, -1, -1, -1, 36, -1, false},
 {"ok_64_channels_max",                  D, "@64", D, 1, 36, 1, 0, 1, 64, -1, 1, 64, 36, -1, false},
 {"ok_preference_type_reads_prefs",      D, "36,40", "10,20", 6, 36, 1, 0, 1, 2, 10, 36, 40, 36, -1, false},
 {"ok_anticipated_type_reads_prefs",     D, "36,40", "5,6", 7, 36, 1, 0, 1, 2, 5, 36, 40, 36, -1, false},
 {"ok_other_type_ignores_prefs",         D, "36,40", "10,20", 1, 36, 1, 0, 1, 2, 0, 36, 40, 36, -1, false},
 {"ok_pref_count_mismatch_no_abort",     D, "36,40,44", "10,20", 6, 36, 1, 0, 1, 3, 10, 36, 44, 36, -1, false},
 {"ok_64_channels_64_prefs",             D, "@64", "@64", 6, 36, 1, 0, 1, 64, 1, 1, 64, 36, -1, false},
 {"ok_id_127_chars",                     "#127", "36", D, 1, 36, 1, 0, 1, 1, -1, 36, 36, 36, -1, false},
 {"ok_channel_list_255_chars",           D, "#255", D, 1, 36, 1, 0, 1, 1, -1, 0, 0, 36, -1, false},
 {"ok_channel_149",                      D, "149", D, 1, 149, 1, 0, 1, 1, -1, 149, 149, 149, -1, false},
 {"ok_two_rows",                         D, "36,40", D, 1, 36, 2, 0, 2, 2, -1, 36, 40, 36, 2, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_channel_70000_must_not_truncate [spec]",            D, "36", D, 1, 70000, 1, 0, 1, 1, -1, 36, 36, 70000, -1, false},
 {"spec_null_channel_list_must_not_keep_previous_row [spec]", D, "36,40,44", D, 1, 36, 2, 1, 2, 3, -1, 36, 44, 36, 0, false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_65_channels_assert",            D, "@65", D, 1, 36, 1, 0, 1, 64, -1, 1, 64, 36, -1, false},
 {"clamp_65_prefs_assert",               D, "36", "@65", 6, 36, 1, 0, 1, 1, 1, 36, 36, 36, -1, false},
 {"clamp_channel_list_300_chars",        D, "#300", D, 1, 36, 1, 0, 1, 1, -1, 0, 0, 36, -1, false},
 {"clamp_pref_list_300_chars",           D, "36", "#300", 6, 36, 1, 0, 1, 1, 0, 36, 36, 36, -1, false},
 {"clamp_id_200_chars",                  "#200", "36", D, 1, 36, 1, 0, 1, 1, -1, 36, 36, 36, -1, false},
 {"clamp_id_4000_chars",                 "#4000", "36", D, 1, 36, 1, 0, 1, 1, -1, 36, 36, 36, -1, false},
 {NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false}
};

static void set_list(cell_t *c, const char *v, const char *def)
{
    c->kind = 1;
    if (!strcmp(v, "=")) { snprintf(c->s, sizeof(c->s), "%s", def); return; }
    if (v[0] == '#') { size_t n = (size_t)atoi(v + 1); if (n >= OCS_CELL_SZ) n = OCS_CELL_SZ - 1; memset(c->s, 'x', n); c->s[n] = 0; return; }
    if (v[0] == '@') {
        int n = atoi(v + 1); c->s[0] = 0;
        for (int i = 1; i <= n; i++) { char e[16]; snprintf(e, sizeof(e), "%s%d", i > 1 ? "," : "", i); strcat(c->s, e); }
        return;
    }
    snprintf(c->s, sizeof(c->s), "%s", v);
}
static void fill_row(row_t *r, const test_case_t *tc)
{
    memset(r, 0, sizeof(*r));
    if (!strcmp(tc->id, "=")) snprintf(r->c[0].s, sizeof(r->c[0].s), "02:00:00:00:00:01@%d@115", tc->type); else set_list(&r->c[0], tc->id, "");
    r->c[0].kind = 1;
    r->c[1].kind = 2; r->c[1].num = 115; r->c[2].kind = 2; r->c[2].num = tc->channel;
    set_list(&r->c[3], tc->chans, ""); set_list(&r->c[4], tc->prefs, "");
    r->c[5].kind = 2; r->c[5].num = 1; r->c[6].kind = 2; r->c[6].num = 20; r->c[7].kind = 2; r->c[7].num = 30;
    r->c[8].kind = 2; r->c[8].num = 1; r->c[9].kind = 2; r->c[9].num = 2; r->c[10].kind = 2; r->c[10].num = 3;
}
void construct_input(const test_case_t *tc)
{
    memset(g_rows, 0, sizeof(g_rows)); g_nrows = tc->nrows;
    for (int i = 0; i < tc->nrows; i++) fill_row(&g_rows[i], tc);
    if (tc->nrows >= 2 && tc->row2_chans_null) g_rows[1].c[3].kind = 0;
    dm_op_class_list_t::g_updates.clear();
}
void teardown(void) { dm_op_class_list_t::g_updates.clear(); }
} /* namespace ocs */
