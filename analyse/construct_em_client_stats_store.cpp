/*
 * TEST CASES / CONSTRUCTOR: construct_em_client_stats_store
 *
 * The global cache's radio_report[r].ap_data[k].vap_index are seeded as
 * 100+k, so vap_index 102 maps to arr_vap_index 2. getVapInfo returns a vap
 * with bssid 90:91:..:95; dev3->cli_MACAddress is a0:a1:..:a5, so the key the
 * handler builds is "90:91:92:93:94:95@a0:a1:a2:a3:a4:a5". dev3 lives at
 * ecs_dev3_buf (runner poisons past it).
 *
 * Cases: add_new (fresh entry -> RETURN_OK), update_existing (pre-populated ->
 * update path -> RETURN_OK), dev3_null, bad_radio (>= MAX_NUM_RADIOS),
 * vap_not_in_cache (no matching vap_index), getvap_null.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

em_ap_metrics_report_cache_t em_ap_metrics_report_cache;
alignas(16) char ecs_dev3_buf[sizeof(wifi_associated_dev3_t) + ECS_PAD];
int ecs_getvap_null;
int ecs_prepopulate;

em_css_test_case_t em_client_stats_store_suite[] = {
    /* name              radio vap  sta dev3_null getvap_null prepop want_ret */
    { "add_new",            0, 102,  4,  0,       0,          0,      0 },
    { "update_existing",    0, 102,  7,  0,       0,          1,      0 },
    { "dev3_null",          0, 102,  4,  1,       0,          0,     -1 },
    { "bad_radio",          5, 102,  4,  0,       0,          0,     -1 },
    { "vap_not_in_cache",   0, 999,  4,  0,       0,          0,     -1 },
    { "getvap_null",        0, 102,  4,  0,       1,          0,     -1 },
    { NULL, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_client_stats_store_input(const em_css_test_case_t *tc)
{
    /* seed the cache: ap_data[k].vap_index = 100+k across all radios */
    memset(&em_ap_metrics_report_cache, 0, sizeof(em_ap_metrics_report_cache));
    for (int r = 0; r < MAX_NUM_RADIOS; r++)
        for (int k = 0; k < MAX_NUM_VAP_PER_RADIO; k++)
            em_ap_metrics_report_cache.radio_report[r].ap_data[k].vap_index = 100 + k;

    memset(ecs_dev3_buf, 0, sizeof(ecs_dev3_buf));
    wifi_associated_dev3_t *dev3 = (wifi_associated_dev3_t *)ecs_dev3_buf;
    unsigned char mac[6] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
    memcpy(dev3->cli_MACAddress, mac, 6);

    ecs_getvap_null = tc->getvap_null;
    ecs_prepopulate = tc->prepopulate;

    ecs_store_reset();
    if (tc->prepopulate)
        ecs_store_prepopulate("90:91:92:93:94:95@a0:a1:a2:a3:a4:a5");
}
