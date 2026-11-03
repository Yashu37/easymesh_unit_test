/*
 * TEST CASES / CONSTRUCTOR: construct_radio_chan_stats_response
 *
 * provider_response lives at rcs_resp_buf; its stat_pointer points at a fresh
 * malloc of stat_array_size radio_chan_data_t entries. rcs_radio is the radio
 * config (vaps.num_vaps vaps). The wifi_prop maps radio_index 0 -> "wlan0".
 * em_ap_metrics_report_cache / em_chan_survey_prev are shared globals (the
 * cache is defined in construct_em_client_stats_store.cpp; the survey array
 * here).
 *
 * Cases: ok_1chan (1 channel, 2 vaps), ok_delta (second sample -> delta path),
 * ok_full_vaps (8 vaps), bad_radio (radio_index >= MAX_NUM_RADIOS),
 * zero_count, radio_null (find_radio_config_by_index -> NULL).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char rcs_mgr_buf[sizeof(wifi_mgr_t) + RCS_PAD];
alignas(16) char rcs_resp_buf[sizeof(wifi_provider_response_t) + RCS_PAD];
void *rcs_stat_pointer;
rdk_wifi_radio_t rcs_radio;
int  rcs_radio_null;
em_chan_survey_prev_t em_chan_survey_prev[MAX_NUM_RADIOS];

em_rcs_test_case_t radio_chan_stats_response_suite[] = {
    /* name          radio stat_sz num_vaps radio_null want_ret */
    { "ok_1chan",       0,   1,      2,       0,        0 },
    { "ok_delta",       0,   2,      2,       0,        0 },
    { "ok_full_vaps",   0,   1,      8,       0,        0 },
    { "bad_radio",      9,   1,      2,       0,       -1 },
    { "zero_count",     0,   0,      2,       0,       -1 },
    { "radio_null",     0,   1,      2,       1,       -1 },
    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_radio_chan_stats_response_input(const em_rcs_test_case_t *tc)
{
    memset(rcs_mgr_buf, 0, sizeof(rcs_mgr_buf));
    memset(rcs_resp_buf, 0, sizeof(rcs_resp_buf));
    memset(&rcs_radio, 0, sizeof(rcs_radio));
    memset(em_chan_survey_prev, 0, sizeof(em_chan_survey_prev));
    memset(&em_ap_metrics_report_cache, 0, sizeof(em_ap_metrics_report_cache));

    /* wifi_prop: radio_index 0 -> wlan0 */
    wifi_mgr_t *m = (wifi_mgr_t *)rcs_mgr_buf;
    wifi_platform_property_t *wp = &m->hal_cap.wifi_prop;
    for (int k = 0; k < 8; k++) wp->radio_interface_map[k].radio_index = -1;
    snprintf(wp->radio_interface_map[0].interface_name, 32, "wlan0"); wp->radio_interface_map[0].radio_index = 0;

    /* radio config: num_vaps vaps, each with a vap_index + bssid */
    int nv = tc->num_vaps; if (nv > 8) nv = 8;
    rcs_radio.vaps.num_vaps = nv;
    rcs_radio.vaps.vap_map.num_vaps = nv;
    for (int j = 0; j < nv; j++) {
        rcs_radio.vaps.vap_map.vap_array[j].vap_index = j;
        unsigned char *b = rcs_radio.vaps.vap_map.vap_array[j].u.bss_info.bssid;
        b[0] = 0x60; b[1] = 0x61; b[2] = 0x62; b[3] = 0x63; b[4] = 0x64; b[5] = (unsigned char)j;
    }
    /* seed the cache ap_data vap_index so the "matching" branch is taken */
    if (tc->radio_index >= 0 && tc->radio_index < MAX_NUM_RADIOS) {
        for (int j = 0; j < nv; j++)
            em_ap_metrics_report_cache.radio_report[tc->radio_index].ap_data[j].vap_index = j;
    }

    rcs_radio_null = tc->radio_null;

    /* source channel stats */
    if (rcs_stat_pointer) { free(rcs_stat_pointer); rcs_stat_pointer = NULL; }
    int n = tc->stat_array_size > 0 ? tc->stat_array_size : 1;
    radio_chan_data_t *cs = (radio_chan_data_t *)calloc((size_t)n, sizeof(radio_chan_data_t));
    rcs_stat_pointer = cs;
    for (int c = 0; c < tc->stat_array_size; c++) {
        cs[c].ch_number = 36;
        cs[c].ch_noise = -90;
        cs[c].ch_utilization_total     = 1000 + c * 500;
        cs[c].ch_utilization_busy      = 400 + c * 200;
        cs[c].ch_utilization_busy_tx   = 100 + c * 50;
        cs[c].ch_utilization_busy_self = 50 + c * 25;
        cs[c].ch_utilization_busy_rx   = 150 + c * 60;
        cs[c].ch_utilization_busy_ext  = 10;
    }

    wifi_provider_response_t *resp = (wifi_provider_response_t *)rcs_resp_buf;
    resp->args.radio_index = tc->radio_index;
    resp->stat_array_size  = tc->stat_array_size;
    resp->stat_pointer     = rcs_stat_pointer;
}
