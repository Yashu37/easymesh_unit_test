/*
 * TEST CASES / CONSTRUCTOR: construct_set_bus_csi_sta_maclist
 * csi_info at sbm_info_buf (poison past the struct); bus_handle at sbm_bh_buf.
 * Cases: success, bus failure (RETURN_ERR), large session index, empty mac.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   sbm_slot[SBM_NAME_SZ + SBM_PAD];
size_t sbm_name_len;
char   sbm_name_seen[256], sbm_val_seen[512];
int    sbm_set_calls, sbm_fail;
alignas(16) char sbm_info_buf[sizeof(csi_analytics_info_t) + SBM_PAD];
alignas(16) char sbm_bh_buf[16 + SBM_PAD];

set_bus_csi_sta_maclist_test_case_t set_bus_csi_sta_maclist_suite[] = {
    /* name          session  mac                  fail  expect_ret */
    { "success",       1,     "aa:bb:cc:dd:ee:ff",  0,    0  },
    { "bus_fail",      2,     "aa:bb:cc:dd:ee:ff",  1,    -1 },
    { "big_session",   999999,"10:11:12:13:14:15",  0,    0  },
    { "empty_mac",     3,     "",                   0,    0  },
    { NULL, 0, NULL, 0, 0 }
};

void construct_set_bus_csi_sta_maclist_input(const set_bus_csi_sta_maclist_test_case_t *tc)
{
    memset(sbm_info_buf, 0, sizeof(sbm_info_buf));
    memset(sbm_bh_buf, 0, sizeof(sbm_bh_buf));
    csi_analytics_info_t *ci = (csi_analytics_info_t *)sbm_info_buf;
    ci->csi_session_index = tc->session;
    snprintf(ci->sta_mac, MAX_MACLIST_SIZE, "%s", tc->mac);
    sbm_fail = tc->fail;
    sbm_name_len = 0; sbm_name_seen[0] = sbm_val_seen[0] = 0; sbm_set_calls = 0;
}
