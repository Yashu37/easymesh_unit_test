/*
 * TEST CASES / CONSTRUCTOR: construct_prepare_sta_lins_metrics_data
 *
 * data (per_sta_metrics_t) is the OUTPUT at psl_data_buf; stats
 * (wifi_associated_dev3_timestamp_t) is the input at psl_stats_buf. The runner
 * poisons past both structs. getVapInfo returns a vap (bssid 70:..:75) unless
 * psl_getvap_null; the client-type map returns an entry iff psl_has_clitype.
 *
 * Cases: ok_no_clitype (fills metrics -> RETURN_OK), ok_with_clitype (copies
 * client_type), ok_last_update (non-zero last_update_time -> delta path),
 * data_null, stats_null, getvap_null (all -> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"

alignas(16) char psl_data_buf[sizeof(per_sta_metrics_t) + PSL_PAD];
alignas(16) char psl_stats_buf[sizeof(wifi_associated_dev3_timestamp_t) + PSL_PAD];
int psl_getvap_null, psl_has_clitype;

em_psl_test_case_t prepare_sta_lins_metrics_data_suite[] = {
    /* name             data_null stats_null getvap_null has_clitype last_update_nz want_ret */
    { "ok_no_clitype",    0,       0,         0,          0,          0,             0 },
    { "ok_with_clitype",  0,       0,         0,          1,          0,             0 },
    { "ok_last_update",   0,       0,         0,          0,          1,             0 },
    { "data_null",        1,       0,         0,          0,          0,            -1 },
    { "stats_null",       0,       1,         0,          0,          0,            -1 },
    { "getvap_null",      0,       0,         1,          0,          0,            -1 },
    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_prepare_sta_lins_metrics_data_input(const em_psl_test_case_t *tc)
{
    memset(psl_data_buf, 0, sizeof(psl_data_buf));
    memset(psl_stats_buf, 0, sizeof(psl_stats_buf));

    wifi_associated_dev3_timestamp_t *stats = (wifi_associated_dev3_timestamp_t *)psl_stats_buf;
    unsigned char mac[6] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5};
    memcpy(stats->associated_dev3.cli_MACAddress, mac, 6);
    stats->associated_dev3.cli_RSSI = -55;
    stats->associated_dev3.cli_LastDataDownlinkRate = 866000;
    stats->associated_dev3.cli_LastDataUplinkRate = 433000;
    stats->last_update_time.tv_sec  = tc->last_update_nonzero ? 100 : 0;
    stats->last_update_time.tv_nsec = tc->last_update_nonzero ? 500000000L : 0;

    psl_getvap_null = tc->getvap_null;
    psl_has_clitype = tc->has_clitype;
    if (tc->has_clitype) psl_set_clitype("Smartphone");
}
