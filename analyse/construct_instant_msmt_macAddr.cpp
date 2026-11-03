/*
 * TEST CASES / CONSTRUCTOR: construct_instant_msmt_macAddr
 * mac string lives in iam_mac_buf (runner poisons past its NUL). wifi_mgr
 * stand-in has radio_presence[0]=true. iam_found_vap = vap where the stubbed
 * is_harvester_device_associated returns true (-1 = never).
 * Cases: found_colon, found_plain, notfound.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char iam_mgr_buf[sizeof(wifi_mgr_t) + IAM_PAD];
char iam_mac_buf[IAM_MAC_SZ];
int iam_num_vaps, iam_found_vap, iam_assoc_checks;

harv_iam_test_case_t instant_msmt_macAddr_suite[] = {
    /* name          mac                  found_vap want_ap want_found want_mac */
    { "found_colon", "aa:bb:cc:dd:ee:ff",  2,        2,      1, {0xaa,0xbb,0xcc,0xdd,0xee,0xff} },
    { "found_plain", "112233445566",       0,        0,      1, {0x11,0x22,0x33,0x44,0x55,0x66} },
    { "notfound",    "aa:bb:cc:dd:ee:ff", -1,       -7,      0, {0,0,0,0,0,0} },
    { NULL, NULL, 0, 0, 0, {0} }  /* sentinel */
};

void construct_instant_msmt_macAddr_input(const harv_iam_test_case_t *tc)
{
    memset(&g_harvester_module, 0, sizeof(g_harvester_module));
    pthread_mutex_init(&g_harvester_module.queue_lock, NULL);
    pthread_cond_init(&g_harvester_module.cond, NULL);
    g_harvester_module.inst_msmt.ap_index = -7;
    memset(iam_mgr_buf, 0, sizeof(iam_mgr_buf));
    ((wifi_mgr_t *)iam_mgr_buf)->hal_cap.wifi_prop.radio_presence[0] = true;
    memset(iam_mac_buf, 0, sizeof(iam_mac_buf));
    snprintf(iam_mac_buf, 64, "%s", tc->mac);
    iam_num_vaps = 3;
    iam_found_vap = tc->found_vap;
    iam_assoc_checks = 0;
}
