/*
 * TEST CASES / CONSTRUCTOR: construct_em_handle_disassoc_device
 *
 * arg (assoc_dev_data_t) lives at hdd_arg_buf; the wifi_mgr/wifi_ctrl stand-ins
 * at hdd_mgr_buf/hdd_ctrl_buf. The shared em_ap_metrics_report_cache is seeded
 * so ap_data[2].vap_index == the event's ap_index (102). The hdd_* globals
 * steer get_radio_index_for_vap_index / getVapInfo / the two hash_map_remove
 * lookups.
 *
 * Cases: success (all present -> 0, frees client-type entry), radio_not_found
 * (-> 0), vap_not_in_cache (-> RETURN_ERR), getvap_null (-> RETURN_ERR),
 * stats_absent (-> 0), clitype_absent (-> 0).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char hdd_ctrl_buf[sizeof(wifi_ctrl_t) + HDD_PAD];
alignas(16) char hdd_mgr_buf[sizeof(wifi_mgr_t) + HDD_PAD];
alignas(16) char hdd_arg_buf[sizeof(assoc_dev_data_t) + HDD_PAD];
int hdd_radio_index, hdd_vap_null, hdd_stats_present, hdd_clitype_present;

em_hdd_test_case_t em_handle_disassoc_device_suite[] = {
    /* name            radio_idx vap_null stats_present clitype_present vap_in_cache want_ret */
    { "success",          0,      0,       1,            1,              1,           0 },
    { "radio_not_found", -1,      0,       1,            1,              1,           0 },
    { "vap_not_in_cache", 0,      0,       1,            1,              0,          -1 },
    { "getvap_null",      0,      1,       1,            1,              1,          -1 },
    { "stats_absent",     0,      0,       0,            1,              1,           0 },
    { "clitype_absent",   0,      0,       1,            0,              1,           0 },
    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_handle_disassoc_device_input(const em_hdd_test_case_t *tc)
{
    memset(hdd_ctrl_buf, 0, sizeof(hdd_ctrl_buf));
    memset(hdd_mgr_buf, 0, sizeof(hdd_mgr_buf));
    memset(hdd_arg_buf, 0, sizeof(hdd_arg_buf));
    memset(&em_ap_metrics_report_cache, 0, sizeof(em_ap_metrics_report_cache));

    assoc_dev_data_t *ad = (assoc_dev_data_t *)hdd_arg_buf;
    ad->ap_index = 102;
    unsigned char s[6] = {0x20,0x21,0x22,0x23,0x24,0x25};
    memcpy(ad->dev_stats.cli_MACAddress, s, 6);

    /* seed the cache: ap_data[2].vap_index == 102 (matches) when vap_in_cache */
    int r = (tc->radio_index >= 0 && tc->radio_index < MAX_NUM_RADIOS) ? tc->radio_index : 0;
    for (int k = 0; k < MAX_NUM_VAP_PER_RADIO; k++)
        em_ap_metrics_report_cache.radio_report[r].ap_data[k].vap_index = -1;
    if (tc->vap_in_cache) {
        em_ap_metrics_report_cache.radio_report[r].ap_data[2].vap_index = 102;
        em_ap_metrics_report_cache.radio_report[r].ap_data[2].client_stats_map = (void *)0x57; /* non-NULL -> stats path */
    }

    hdd_radio_index     = tc->radio_index;
    hdd_vap_null        = tc->vap_null;
    hdd_stats_present   = tc->stats_present;
    hdd_clitype_present = tc->clitype_present;
}
