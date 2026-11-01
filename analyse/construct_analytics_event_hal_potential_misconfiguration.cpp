/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_hal_potential_misconfiguration
 *
 * arg is a packed probe_ttl_data_t at the start of apm_arg_buf (bytes past
 * its size poisoned by the runner, right after mac_str).
 *
 * Cases: normal MAC, empty mac_str, upper-case MAC, count 0, and the
 * longest line (full 17-char MAC + count 0x80000000 printed as INT_MIN).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   apm_slot[APM_SLOT_SZ + APM_PAD];
size_t apm_len;
alignas(16) char apm_arg_buf[sizeof(probe_ttl_data_t) + APM_PAD];

analytics_event_hal_potential_misconfiguration_test_case_t analytics_event_hal_potential_misconfiguration_suite[] = {
    /* name             mac_str               count         len */
    { "normal",         "10:11:12:13:14:15",  6,            76 },
    { "empty_mac",      "",                   6,            59 },
    { "upper_mac",      "AA:BB:CC:DD:EE:FF",  100,          78 },
    { "count_zero",     "10:11:12:13:14:15",  0,            76 },
    { "longest_line",   "aa:bb:cc:dd:ee:ff",  0x80000000u,  86 },

    { NULL, NULL, 0, 0 }  /* sentinel */
};

void construct_analytics_event_hal_potential_misconfiguration_input(const analytics_event_hal_potential_misconfiguration_test_case_t *tc)
{
    memset(apm_arg_buf, 0, sizeof(apm_arg_buf));
    probe_ttl_data_t *t = (probe_ttl_data_t *)apm_arg_buf;
    t->max_probe_ttl_cnt = tc->count;
    snprintf(t->mac_str, sizeof(t->mac_str), "%s", tc->mac_str);   /* as levl update_probe_map does */
    apm_len = 0;
}
