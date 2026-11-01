/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_hal_assoc_device
 *
 * arg is an assoc_dev_data_t at the start of aad_arg_buf; apps is a
 * wifi_app_t at the start of aad_apps_buf (bytes past each struct poisoned
 * by the runner). An "existing" station can be pre-registered under the
 * lower-case MAC key.
 *
 * Cases: new station, station already known (updated in place), upper-case
 * hex in the MAC (lowered), ap_index INT_MIN / INT_MAX (longest temp_str =
 * 41 chars), and malloc returning NULL (crashed before the fix; now
 * returns RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

char   aad_slot_mac[AAD_MAC_SZ + AAD_PAD];
char   aad_slot_tmp[AAD_TMP_SZ + AAD_PAD];
size_t aad_tmp_len;
alignas(16) unsigned char aad_pool[AAD_POOL_SLOTS][sizeof(analytics_sta_info_t) + AAD_PAD];
int    aad_pool_used, aad_malloc_fail, aad_get_calls;
void  *aad_existing;
char   aad_existing_key[32];
char   aad_put_key[64];
void  *aad_put_data;
alignas(16) char aad_arg_buf[sizeof(assoc_dev_data_t) + AAD_PAD];
alignas(16) char aad_apps_buf[sizeof(wifi_app_t) + AAD_PAD];
static analytics_sta_info_t aad_known;

analytics_event_hal_assoc_device_test_case_t analytics_event_hal_assoc_device_suite[] = {
    /* name              ap_index existing malloc_fail mac_hi put tmp_len */
    { "new_station",          1,     0,       0,         0,    1,   31 },
    { "known_station",        2,     1,       0,         0,    0,   31 },
    { "mac_upper_hex",        3,     0,       0,         1,    1,   31 },
    { "ap_index_int_min",  INT_MIN,  0,       0,         1,    1,   41 },
    { "ap_index_int_max",  INT_MAX,  0,       0,         1,    1,   40 },
    { "malloc_fails",         4,     0,       1,         0,    0,   31 },   /* RETURN_ERR after the fix */

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_analytics_event_hal_assoc_device_input(const analytics_event_hal_assoc_device_test_case_t *tc)
{
    memset(aad_arg_buf, 0, sizeof(aad_arg_buf));
    memset(aad_apps_buf, 0, sizeof(aad_apps_buf));
    memset(aad_pool, 0xAB, sizeof(aad_pool));
    assoc_dev_data_t *a = (assoc_dev_data_t *)aad_arg_buf;
    a->ap_index = tc->ap_index;
    for (int b = 0; b < 6; b++)
        a->dev_stats.cli_MACAddress[b] = tc->mac_hi ? (unsigned char)(0xAA + b) : (unsigned char)(0x10 + b);
    ((wifi_app_t *)aad_apps_buf)->data.u.analytics.sta_map = (void *)0x1;   /* only passed to the stubs */

    aad_existing = NULL;
    snprintf(aad_existing_key, sizeof(aad_existing_key), "10:11:12:13:14:15");
    if (tc->existing) { memset(&aad_known, 0, sizeof(aad_known)); aad_existing = &aad_known; }

    aad_pool_used = 0;
    aad_malloc_fail = tc->malloc_fail;
    aad_get_calls = 0;
    aad_tmp_len = 0;
    aad_put_key[0] = 0;
    aad_put_data = NULL;
}
