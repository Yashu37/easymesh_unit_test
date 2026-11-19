/*
 * TEST CASES / CONSTRUCTOR: construct_policy_update_db
 *
 * One policy object per case (heap, between poisoned guards): net_id from the case, dev MAC 02:00:00:00:00:01, radio MAC
 * 02:00:00:00:00:02, type 1, sta_mac[i] = 02:00:00:00:00:(i+1) for the first 16 entries, num_sta from the case. The row functions are
 * stand-ins that record the key and the STA list update_db hands them. PASS = return value, number of row calls, number of STA entries
 * in the list and the key match. Cases that ABORTED on the original code are named clamp_* / rej_*: num_sta above 16 reads past
 * sta_mac[16] (fix 1 clamps it), a NULL data pointer dereferenced policy->id (fix 2 returns -1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy_update_db.h"

namespace pud {
#define K1 "OneWifiMesh@02:00:00:00:00:01@02:00:00:00:00:02@1"
/* {name, op, num_sta, null_data, net_id, expect_ret, expect_calls, expect_entries, expect_key, crash} */
test_case_t suite[] = {
 {"ok_insert_no_sta",                 1, 0, false, "OneWifiMesh", 0, 1, 0, K1, false},
 {"ok_insert_one_sta",                1, 1, false, "OneWifiMesh", 0, 1, 1, K1, false},
 {"ok_insert_two_sta",                1, 2, false, "OneWifiMesh", 0, 1, 2, K1, false},
 {"ok_insert_16_sta_largest_valid",   1, 16, false, "OneWifiMesh", 0, 1, 16, K1, false},
 {"ok_update_three_sta",              2, 3, false, "OneWifiMesh", 0, 1, 3, K1, false},
 {"ok_update_16_sta",                 2, 16, false, "OneWifiMesh", 0, 1, 16, K1, false},
 {"ok_delete_row",                    3, 5, false, "OneWifiMesh", 0, 1, -1, K1, false},
 {"ok_unknown_op_does_nothing",       0, 2, false, "OneWifiMesh", 0, 0, -1, NULL, false},
 {"ok_empty_net_id",                  1, 1, false, "", 0, 1, 1, "@02:00:00:00:00:01@02:00:00:00:00:02@1", false},
 {"ok_net_id_127_chars",              1, 1, false, "#127", 0, 1, 1, NULL, false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_num_sta_17",                 1, 17, false, "OneWifiMesh", 0, 1, 16, K1, false},
 {"clamp_num_sta_40_update",          2, 40, false, "OneWifiMesh", 0, 1, 16, K1, false},
 {"clamp_num_sta_1000000",            1, 1000000, false, "OneWifiMesh", 0, 1, 16, K1, false},
 {"clamp_num_sta_ffffffff",           1, 0xffffffffu, false, "OneWifiMesh", 0, 1, 16, K1, false},
 {"rej_null_data_insert",             1, 0, true, "OneWifiMesh", -1, 0, -1, NULL, false},
 {"rej_null_data_delete",             3, 0, true, "OneWifiMesh", -1, 0, -1, NULL, false},
 {NULL, 0, 0, false, NULL, 0, 0, 0, NULL, false}
};


void construct_input(const test_case_t *tc)
{
    g_box = (policy_box_t *)calloc(1, sizeof(policy_box_t));
    em_policy_t *p = &g_box->p;
    if (tc->net_id[0] == '#') memset(p->id.net_id, 'N', (size_t)atoi(tc->net_id + 1)); else snprintf(p->id.net_id, sizeof(p->id.net_id), "%s", tc->net_id);
    unsigned char d[6] = {2,0,0,0,0,1}, r[6] = {2,0,0,0,0,2}; memcpy(p->id.dev_mac, d, 6); memcpy(p->id.radio_mac, r, 6);
    p->id.type = 1; p->num_sta = tc->num_sta;
    for (int i = 0; i < EM_MAX_STA_PER_STEER_POLICY; i++) { unsigned char m[6] = {2,0,0,0,0,(unsigned char)(i + 1)}; memcpy(p->sta_mac[i], m, 6); }
    snprintf(p->managed_sta_marker, sizeof(p->managed_sta_marker), "mm");
    p->interval = 7;
    g_calls = 0; g_key[0] = 0; g_list[0] = 0;
}
void teardown(void) { free(g_box); g_box = NULL; }
} /* namespace pud */
