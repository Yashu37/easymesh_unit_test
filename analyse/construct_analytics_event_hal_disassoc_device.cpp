/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_hal_disassoc_device
 *
 * arg is an assoc_dev_data_t at the start of add_arg_buf; apps is a
 * wifi_app_t at the start of add_apps_buf (bytes past each struct poisoned
 * by the runner). One station may be in sta_map under its lower-case MAC.
 *
 * Cases: known station (removed + freed), unknown station (nothing
 * removed), remove returning NULL, upper-case hex MAC (lowered before the
 * lookup), and the LONGEST temp_str: ap_index INT_MIN + reason INT_MIN
 * (60 chars + NUL = 61 of 64), plus INT_MAX / INT_MAX.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

char   add_slot_mac[ADD_MAC_SZ + ADD_PAD];
char   add_slot_tmp[ADD_TMP_SZ + ADD_PAD];
size_t add_tmp_len;
void  *add_entry, *add_freed;
char   add_entry_key[32];
char   add_key_seen[64];
int    add_remove_calls, add_remove_null;
alignas(16) char add_arg_buf[sizeof(assoc_dev_data_t) + ADD_PAD];
alignas(16) char add_apps_buf[sizeof(wifi_app_t) + ADD_PAD];
static analytics_sta_info_t add_known;

analytics_event_hal_disassoc_device_test_case_t analytics_event_hal_disassoc_device_suite[] = {
    /* name                 ap_index reason   known rm_null mac_hi removes freed tmp_len */
    { "known_station",         1,       3,      1,    0,     0,      1,     1,    40 },
    { "unknown_station",       1,       3,      0,    0,     0,      0,     0,    40 },
    { "remove_returns_null",   1,       3,      1,    1,     0,      1,     0,    40 },
    { "mac_upper_hex",         2,       8,      1,    0,     1,      1,     1,    40 },
    { "int_min_int_min",    INT_MIN, INT_MIN,   1,    0,     1,      1,     1,    60 },
    { "int_max_int_max",    INT_MAX, INT_MAX,   1,    0,     1,      1,     1,    58 },

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_analytics_event_hal_disassoc_device_input(const analytics_event_hal_disassoc_device_test_case_t *tc)
{
    memset(add_arg_buf, 0, sizeof(add_arg_buf));
    memset(add_apps_buf, 0, sizeof(add_apps_buf));
    assoc_dev_data_t *a = (assoc_dev_data_t *)add_arg_buf;
    a->ap_index = tc->ap_index;
    a->reason = tc->reason;
    for (int b = 0; b < 6; b++)
        a->dev_stats.cli_MACAddress[b] = tc->mac_hi ? (unsigned char)(0xAA + b) : (unsigned char)(0x10 + b);
    ((wifi_app_t *)add_apps_buf)->data.u.analytics.sta_map = (void *)0x1;   /* only passed to the stubs */

    memset(&add_known, 0, sizeof(add_known));
    add_entry = tc->known ? &add_known : NULL;
    snprintf(add_entry_key, sizeof(add_entry_key), "%s", tc->mac_hi ? "aa:ab:ac:ad:ae:af" : "10:11:12:13:14:15");
    add_remove_null = tc->rm_null;
    add_remove_calls = 0;
    add_freed = NULL;
    add_tmp_len = 0;
    add_key_seen[0] = 0;
}
