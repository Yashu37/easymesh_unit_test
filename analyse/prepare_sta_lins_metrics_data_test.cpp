/*
 * TEST RUNNER: prepare_sta_lins_metrics_data
 *
 * Poisoned around the call:
 *   - the caller's output data (psl_data_buf): bytes past sizeof(per_sta_metrics_t);
 *   - the input stats (psl_stats_buf): bytes past sizeof(wifi_associated_dev3_timestamp_t).
 * key (char[18]) is an internal stack array guarded by ASan redzones.
 *
 * PASS = the returned code matches the expected path, and on the OK paths the
 * output carries num_bssid==1, the sta_mac copied from stats, the vap bssid in
 * slot 0, and (when a client-type entry exists) the client_type string.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int prepare_sta_lins_metrics_data(per_sta_metrics_t *data, wifi_associated_dev3_timestamp_t *stats,
    unsigned int vap_index);

int test_prepare_sta_lins_metrics_data(const em_psl_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&psl_data_buf[sizeof(per_sta_metrics_t)], PSL_PAD);
    __asan_poison_memory_region(&psl_stats_buf[sizeof(wifi_associated_dev3_timestamp_t)], PSL_PAD);

    per_sta_metrics_t *data = tc->data_null ? NULL : (per_sta_metrics_t *)psl_data_buf;
    wifi_associated_dev3_timestamp_t *stats = tc->stats_null ? NULL : (wifi_associated_dev3_timestamp_t *)psl_stats_buf;
    int ret = prepare_sta_lins_metrics_data(data, stats, 0);

    /* UNPOISON */
    __asan_unpoison_memory_region(&psl_stats_buf[sizeof(wifi_associated_dev3_timestamp_t)], PSL_PAD);
    __asan_unpoison_memory_region(&psl_data_buf[sizeof(per_sta_metrics_t)], PSL_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0) {
        per_sta_metrics_t *d = (per_sta_metrics_t *)psl_data_buf;
        unsigned char exp_mac[6] = {0xb0,0xb1,0xb2,0xb3,0xb4,0xb5};
        unsigned char exp_bss[6] = {0x70,0x71,0x72,0x73,0x74,0x75};
        ok = (d->assoc_sta_link_metrics.num_bssid == 1) &&
             (memcmp(d->sta_mac, exp_mac, 6) == 0) &&
             (memcmp(d->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].bssid, exp_bss, 6) == 0);
        if (tc->has_clitype) ok = ok && (strcmp((char *)d->client_type, "Smartphone") == 0);
        printf("    ret=%d num_bssid=%d client_type=\"%s\" rcpi=%u td=%u\n", ret,
               d->assoc_sta_link_metrics.num_bssid, (char *)d->client_type,
               d->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].rcpi,
               d->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].time_delta);
    } else {
        printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    }
    return ok;
}

void run_all_tests_prepare_sta_lins_metrics_data(void)
{
    for (int i = 0; prepare_sta_lins_metrics_data_suite[i].test_name != NULL; i++) {
        em_psl_test_case_t *test = &prepare_sta_lins_metrics_data_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_prepare_sta_lins_metrics_data_input(test);
        int pass = test_prepare_sta_lins_metrics_data(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
