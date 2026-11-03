/*
 * TEST CASES / CONSTRUCTOR: construct_process_instant_msmt_stop
 *
 * Drives g_harvester_module.inst_msmt_id (the gate for the event-push branch)
 * and seeds radio_data allocations for the free loop. pims_sink captures the
 * bytes pushed to the ctrl queue; the runner poisons its tail past 16.
 *
 * Cases: active (inst_msmt_id != 0 -> builds event_buff, pushes, frees),
 * inactive (inst_msmt_id == 0 -> no push).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int  pims_num_radios, pims_cfg_push, pims_ctrl_push, pims_ctrl_len, pims_mon_push;
char pims_sink[16 + PIMS_PAD];

em_pims_test_case_t process_instant_msmt_stop_suite[] = {
    /* name        inst_msmt_id want_ctrl_push */
    { "active",     1,          1 },
    { "inactive",   0,          0 },
    { NULL, 0, 0 }  /* sentinel */
};

void construct_process_instant_msmt_stop_input(const em_pims_test_case_t *tc)
{
    memset(&g_harvester_module, 0, sizeof(g_harvester_module));
    memset(pims_sink, 0, sizeof(pims_sink));
    pims_num_radios = 2;
    pims_cfg_push = pims_ctrl_push = pims_ctrl_len = pims_mon_push = 0;

    g_harvester_module.inst_msmt_id = tc->inst_msmt_id;
    /* seed radio_data so the free loop runs (active case) */
    for (int r = 0; r < pims_num_radios; r++)
        g_harvester_module.radio_data[r] = calloc(1, sizeof(radio_data_t));
}
