/*
 * TEST CASES / CONSTRUCTOR: construct_opclass_update_db
 *
 * One op class info per case on the heap, between poisoned guards: ruid 02:00:00:00:00:01, op_class 115, type from the case,
 * num_channels from the case, channels[i] = 36 + 4i (fill 0), 100 + i (fill 1) or channels[0] = 12345678 (fill 2), channel_pref[i] = i + 1.
 * The row functions are stand-ins that record the id, the channel list and the preference list update_db hands them. PASS = return
 * value, number of row calls, channel entry count, first / last channel and preference string match. Cases that ABORTED on the original
 * code are named clamp_* / rej_*: num_channels above 64 reads past channels[64] / channel_pref[64], a NULL data pointer dereferences
 * info->id. They run last and UNFORKED; FORK_CRASH=1 forks each one. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opclass_update_db.h"

namespace oud {
/* {name, op, type, num_channels, fill, null_data, expect_ret, expect_calls, expect_entries, first, last, pref, crash} */
test_case_t suite[] = {
 {"ok_insert_three_channels",          1, 1, 3, 0, false, 0, 1, 3, "36", "44", "", false},
 {"ok_insert_preference_type",         1, 6, 3, 0, false, 0, 1, 3, "36", "44", "1,2,3", false},
 {"ok_insert_anticipated_type",        1, 7, 3, 0, false, 0, 1, 3, "36", "44", "1,2,3", false},
 {"ok_update_three_channels",          2, 1, 3, 0, false, 0, 1, 3, "36", "44", "", false},
 {"ok_delete_row",                     3, 1, 5, 0, false, 0, 1, -1, NULL, NULL, NULL, false},
 {"ok_unknown_op_does_nothing",        0, 1, 3, 0, false, 0, 0, -1, NULL, NULL, NULL, false},
 {"ok_zero_channels",                  1, 1, 0, 0, false, 0, 1, 0, NULL, NULL, "", false},
 {"ok_one_channel",                    1, 1, 1, 0, false, 0, 1, 1, "36", "36", "", false},
 {"ok_64_channels_max",                1, 1, 64, 0, false, 0, 1, 64, "36", "288", "", false},
 {"ok_64_channels_64_prefs",           1, 6, 64, 0, false, 0, 1, 64, "36", "288", NULL, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_64_three_digit_channels_last_entry_cut [spec]", 1, 1, 64, 1, false, 0, 1, 64, "100", "163", "", false},
 {"spec_eight_digit_channel_cut_by_tmp [spec]",         1, 1, 1, 2, false, 0, 1, 1, "12345678", "12345678", "", false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_num_channels_65",             1, 1, 65, 0, false, 0, 1, 64, "36", "288", "", true},
 {"clamp_num_channels_65_pref_type",   1, 6, 65, 0, false, 0, 1, 64, "36", "288", NULL, true},
 {"clamp_num_channels_100_update",     2, 1, 100, 0, false, 0, 1, 64, "36", "288", "", true},
 {"clamp_num_channels_1000000",        1, 1, 1000000, 0, false, 0, 1, 64, "36", "288", "", true},
 {"clamp_num_channels_ffffffff",       1, 1, 0xffffffffu, 0, false, 0, 1, 64, "36", "288", "", true},
 {"rej_null_data_insert",              1, 1, 0, 0, true, -1, 0, -1, NULL, NULL, NULL, true},
 {"rej_null_data_delete",              3, 1, 0, 0, true, -1, 0, -1, NULL, NULL, NULL, true},
 {NULL, 0, 0, 0, 0, false, 0, 0, 0, NULL, NULL, NULL, false}
};

void construct_input(const test_case_t *tc)
{
    g_box = (info_box_t *)calloc(1, sizeof(info_box_t));
    em_op_class_info_t *p = &g_box->info;
    unsigned char r[6] = {2,0,0,0,0,1}; memcpy(p->id.ruid, r, 6);
    p->id.type = (em_op_class_type_t)tc->type; p->id.op_class = 115; p->op_class = 115; p->channel = 36;
    p->num_channels = tc->num_channels;
    for (int i = 0; i < EM_MAX_CHANNELS_IN_LIST; i++) {
        p->channels[i] = tc->fill == 1 ? (unsigned)(100 + i) : (unsigned)(36 + 4 * i);
        p->channel_pref[i] = (unsigned char)(i + 1);
    }
    if (tc->fill == 2) p->channels[0] = 12345678;
    g_calls = 0; g_id[0] = 0; g_channels[0] = 0; g_pref[0] = 0;
}
void teardown(void) { free(g_box); g_box = NULL; }
} /* namespace oud */
