/*
 * TEST CASES / CONSTRUCTOR: construct_sample_blaster
 *
 * Stand-ins: wifi_ctrl (sb_wctrl_buf, apps_mgr+network_mode), wifi_mgr
 * (sb_wmgr_buf), g_active_msmt (sb_mgr_buf), and a wifi_app (sb_app_buf)
 * whose data.u.blaster.frameCountSample + g_active_msmt->active_msmt_data
 * point to SB_SAMPLES-entry arrays. provider_response is at sb_resp_buf.
 *
 * Cases: ext "disconnected" (radio valid, no provider match -> msg[256]),
 * offline (radio_index == RETURN_ERR -> Operating_standard "NULL"), and
 * get_app_by_inst NULL (early return).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   sb_slot_msg[SB_MSG_SZ + SB_PAD];
char   sb_slot_oper[SB_OPER_SZ + SB_PAD];
size_t sb_msg_len;
char   sb_last_err[256];
int    sb_statusdesc_calls, sb_done_notify, sb_radio_err, sb_calc_throughput;
unsigned int sb_num_samples, sb_sample_count;
alignas(16) char sb_wctrl_buf[sizeof(wifi_ctrl_t) + SB_PAD];
alignas(16) char sb_wmgr_buf[sizeof(wifi_mgr_t) + SB_PAD];
alignas(16) char sb_mgr_buf[sizeof(wifi_actvie_msmt_t) + SB_PAD];
alignas(16) char sb_app_buf[sizeof(wifi_app_t) + SB_PAD];
alignas(16) char sb_fcs_buf[SB_SAMPLES * sizeof(pktGenFrameCountSamples) + SB_PAD];
alignas(16) char sb_amd_buf[SB_SAMPLES * sizeof(active_msmt_data_t) + SB_PAD];
alignas(16) char sb_resp_buf[sizeof(wifi_provider_response_t) + SB_PAD];
alignas(16) char sb_stats_buf[4 * sizeof(sta_data_t) + SB_PAD];
wifi_app_t *sb_app;

sample_blaster_test_case_t sample_blaster_suite[] = {
    /* name              app_null radio_err ext  want_msg_sub          */
    { "ext_disconnected",  0,      0,        1,   "The MAC is disconnected" },
    { "offline_radio_err", 0,      1,        0,   ""                        },
    { "app_null",          1,      0,        1,   ""                        },

    { NULL, 0, 0, 0, NULL }  /* sentinel */
};

void construct_sample_blaster_input(const sample_blaster_test_case_t *tc)
{
    memset(sb_wctrl_buf, 0, sizeof(sb_wctrl_buf));
    memset(sb_wmgr_buf, 0, sizeof(sb_wmgr_buf));
    memset(sb_mgr_buf, 0, sizeof(sb_mgr_buf));
    memset(sb_app_buf, 0, sizeof(sb_app_buf));
    memset(sb_fcs_buf, 0, sizeof(sb_fcs_buf));
    memset(sb_amd_buf, 0, sizeof(sb_amd_buf));
    memset(sb_resp_buf, 0, sizeof(sb_resp_buf));
    memset(sb_stats_buf, 0, sizeof(sb_stats_buf));

    wifi_ctrl_t *c = (wifi_ctrl_t *)sb_wctrl_buf;
    c->network_mode = tc->ext ? 1 : 0;

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)sb_mgr_buf;
    pthread_mutex_init(&g->lock, NULL);
    unsigned char mac[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    memcpy(g->curStepData.DestMac, mac, 6);
    g->curStepData.ApIndex = 7;
    g->curStepData.isMLO = false;
    for (int i = 0; i < MAX_NUM_RADIOS - 1; i++) g->curStepData.mldApIndex[i] = -1;
    g->active_msmt_data = (active_msmt_data_t *)sb_amd_buf;

    wifi_app_t *app = (wifi_app_t *)sb_app_buf;
    app->data.u.blaster.frameCountSample = (struct _pktGenFrameCountSamples *)sb_fcs_buf;
    sb_app = tc->app_null ? NULL : app;

    wifi_provider_response_t *r = (wifi_provider_response_t *)sb_resp_buf;
    r->stat_pointer = sb_stats_buf;
    r->stat_array_size = 0;            /* no provider entries -> no bmac match */
    r->args.vap_index = 7;

    sb_num_samples = 10;
    sb_sample_count = 0;
    sb_radio_err = tc->radio_err;
    sb_msg_len = 0;
    sb_last_err[0] = 0;
    sb_statusdesc_calls = sb_done_notify = 0;
}
