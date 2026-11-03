/*
 * TEST CASES / CONSTRUCTOR: construct_process_instant_msmt_monitor
 *
 * g_harvester_module holds the instant-measurement state (count/maxCount,
 * inst_msmt.sta_mac). provider_response (at pim_resp_buf) carries the sta_data
 * array at pim_stats_buf; the runner poisons past both. The target sta_mac is
 * 30:31:..:35 so a matching entry triggers the (stubbed) upload.
 *
 * Cases: threshold (count>=maxCount -> stop, no upload), match (matching mac ->
 * upload), no_match (no upload), count_nonzero (skip radio alloc, still match).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

harvester_ctx_t g_harvester_module;
alignas(16) char pim_resp_buf[sizeof(wifi_provider_response_t) + PIM_PAD];
alignas(16) char pim_stats_buf[PIM_STATS_SZ];
int pim_num_radios, pim_devstats_fail, pim_stop_calls, pim_upload_calls;

em_pim_test_case_t process_instant_msmt_monitor_suite[] = {
    /* name           count maxCount nstats match want_stop want_upload */
    { "threshold",      5,   5,       0,     0,    1,        0 },
    { "match",          0,   5,       3,     1,    0,        1 },
    { "no_match",       0,   5,       3,     0,    0,        0 },
    { "count_nonzero",  2,   5,       3,     1,    0,        1 },
    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_process_instant_msmt_monitor_input(const em_pim_test_case_t *tc)
{
    memset(&g_harvester_module, 0, sizeof(g_harvester_module));
    memset(pim_resp_buf, 0, sizeof(pim_resp_buf));
    memset(pim_stats_buf, 0, sizeof(pim_stats_buf));

    g_harvester_module.count = tc->count;
    g_harvester_module.maxCount = tc->maxCount;
    unsigned char tmac[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    memcpy(g_harvester_module.inst_msmt.sta_mac, tmac, 6);
    g_harvester_module.inst_msmt.ap_index = 1;

    pim_num_radios = 2;
    pim_devstats_fail = 0;
    pim_stop_calls = 0;
    pim_upload_calls = 0;

    /* build the sta_data array; put the target mac at the last slot when matching */
    sta_data_t *arr = (sta_data_t *)pim_stats_buf;
    int n = tc->nstats;
    for (int i = 0; i < n; i++) {
        arr[i].sta_mac[0] = 0x90; arr[i].sta_mac[5] = (unsigned char)i;   /* non-matching */
    }
    if (tc->match && n > 0) memcpy(arr[n - 1].sta_mac, tmac, 6);

    wifi_provider_response_t *resp = (wifi_provider_response_t *)pim_resp_buf;
    resp->stat_pointer = pim_stats_buf;
    resp->stat_array_size = (unsigned int)n;
}
