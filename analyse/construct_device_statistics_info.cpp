/*
 * TEST CASES / CONSTRUCTOR: construct_device_statistics_info
 *
 * data (analytics_data_t) sits at the start of ds_data_buf (bytes past its
 * size poisoned by the runner). minutes_alive % 60 == 0 selects the "utc:"
 * line with get_formatted_time(tm_str). Each station is an
 * analytics_sta_info_t in its own pool slot (tail poisoned by the runner);
 * get_stats_for_sta returns the matching ds_sta_data[] entry.
 *
 * Cases: minutes 5 (no time), minutes 60 (time of day), 0 radios,
 * 3 radios one failing, 63-char bandwidth, 0 stations, 4 stations, a
 * station without stats, extreme RSSI / counters (INT_MIN, UINT_MAX), and
 * a huge CPU-time delta (user/system floats very large).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

char   ds_slot_tm[DS_TM_SZ + DS_PAD];
char   ds_slot_mac[DS_MAC_SZ + DS_PAD];
char   ds_slot_128[DS_TMP_SZ + DS_PAD];
char   ds_slot_256[DS_STA_SZ + DS_PAD];
size_t ds_tm_len, ds_mac_len, ds_tmp_len, ds_sta_len;
int    ds_num_radios, ds_radio_fail_idx, ds_radio_calls, ds_nsta, ds_iter;
char   ds_bw[64];
sta_data_t ds_sta_data[DS_MAX_STA];
alignas(16) unsigned char ds_sta_pool[DS_MAX_STA][sizeof(analytics_sta_info_t) + DS_PAD];
alignas(16) char ds_data_buf[sizeof(analytics_data_t) + DS_PAD];

device_statistics_info_test_case_t device_statistics_info_suite[] = {
    /* name              minutes radios fail bw_len nsta no_stats extreme big_cpu */
    { "minutes_5",          5,     2,   -1,    4,    1,     0,      0,      0 },
    { "minutes_60_time",   60,     2,   -1,    4,    1,     0,      0,      0 },
    { "zero_radios",        5,     0,   -1,    4,    1,     0,      0,      0 },
    { "radio_1_fails",      5,     3,    1,    4,    1,     0,      0,      0 },
    { "bw_63_chars",        5,     2,   -1,   63,    1,     0,      0,      0 },
    { "zero_stations",      5,     2,   -1,    4,    0,     0,      0,      0 },
    { "four_stations",      5,     2,   -1,    4,    4,     0,      0,      0 },
    { "station_no_stats",   5,     2,   -1,    4,    2,     1,      0,      0 },
    { "extreme_counters",  60,     2,   -1,    4,    2,     0,      1,      0 },
    { "huge_cpu_delta",    60,     2,   -1,   63,    2,     0,      1,      1 },

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_device_statistics_info_input(const device_statistics_info_test_case_t *tc)
{
    memset(ds_data_buf, 0, sizeof(ds_data_buf));
    analytics_data_t *d = (analytics_data_t *)ds_data_buf;
    d->minutes_alive = (unsigned int)tc->minutes;
    d->sta_map = (void *)0x1;   /* only passed to the stubbed iterator */
    if (tc->big_cpu) {          /* last_usage far in the "future" -> huge negative delta */
        d->last_usage.ru_utime.tv_sec = LONG_MAX / 2;
        d->last_usage.ru_stime.tv_sec = -(LONG_MAX / 2);
    }

    ds_num_radios = tc->radios;
    ds_radio_fail_idx = tc->fail_idx;
    memset(ds_bw, 0, sizeof(ds_bw));
    memset(ds_bw, 'b', (size_t)tc->bw_len);

    memset(ds_sta_data, 0, sizeof(ds_sta_data));
    memset(ds_sta_pool, 0, sizeof(ds_sta_pool));
    ds_nsta = tc->nsta;
    for (int i = 0; i < ds_nsta; i++) {
        analytics_sta_info_t *s = (analytics_sta_info_t *)ds_sta_pool[i];
        s->ap_index = (tc->no_stats && i == 1) ? DS_NO_STATS_AP : (unsigned int)i;
        for (int b = 0; b < 6; b++) s->sta_mac[b] = (unsigned char)(0xa0 + i * 16 + b);
        if (tc->extreme) s->ap_index = (unsigned int)i;   /* keep valid stats */
        sta_data_t *sd = &ds_sta_data[i];
        sd->dev_stats.cli_RSSI = tc->extreme ? INT_MIN : -40 - i;
        sd->good_rssi_time = tc->extreme ? UINT_MAX : 10;
        sd->bad_rssi_time  = tc->extreme ? UINT_MAX : 2;
        sd->rapid_reconnects = tc->extreme ? UINT_MAX : 0;
    }
    if (tc->extreme) ((analytics_sta_info_t *)ds_sta_pool[1])->ap_index = UINT_MAX - 1;  /* "vap index:4294967294" */

    ds_tm_len = ds_mac_len = ds_tmp_len = ds_sta_len = 0;
    ds_radio_calls = 0;
    ds_iter = 0;
}
