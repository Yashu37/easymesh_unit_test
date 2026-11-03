/*
 * TEST CASES / CONSTRUCTOR: construct_process_instant_msmt_start
 *
 * Seeds g_harvester_module (instantDefOverrideTTL / instantPollPeriod /
 * instntMsmtenable). The function always builds event_buff and pushes. pist_sink
 * captures the bytes pushed to the ctrl queue; the runner poisons its tail past 16.
 *
 * Cases: normal (TTL 600 / poll 5 -> maxCount 120, pushes), zero_ttl
 * (TTL 0 -> maxCount 0, still pushes).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int  pist_cfg_push, pist_ctrl_push, pist_ctrl_len, pist_mon_push;
char pist_sink[PIST_SINK_SZ];

em_pist_test_case_t process_instant_msmt_start_suite[] = {
    /* name       ttl  poll want_maxcount */
    { "normal",   600, 5,   120 },
    { "zero_ttl", 0,   5,   0   },
    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_process_instant_msmt_start_input(const em_pist_test_case_t *tc)
{
    memset(&g_harvester_module, 0, sizeof(g_harvester_module));
    memset(pist_sink, 0, sizeof(pist_sink));
    pist_cfg_push = pist_ctrl_push = pist_ctrl_len = pist_mon_push = 0;

    g_harvester_module.instantDefOverrideTTL = tc->ttl;
    g_harvester_module.instantPollPeriod = tc->poll;
    g_harvester_module.instntMsmtenable = true;
    g_harvester_module.inst_msmt_id = 0;
}
