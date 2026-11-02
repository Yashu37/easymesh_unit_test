/*
 * TEST CASES / CONSTRUCTOR: construct_cac_event_hal_disassoc_device
 * arg is an assoc_dev_data_t at cdd_arg_buf; apps at cdd_apps_buf with
 * data.u.cac.sta_map set. Cases: station found (removed+freed), not found,
 * hex-letter MAC. temp_str includes ap_index+1 and reason.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   cdd_slot_mac[CDD_MAC_SZ + CDD_PAD];
char   cdd_slot_tmp[CDD_TMP_SZ + CDD_PAD];
size_t cdd_tmp_len;
char   cdd_key_seen[64], cdd_existing_key[32];
int    cdd_existing, cdd_remove_calls;
alignas(16) char cdd_arg_buf[sizeof(assoc_dev_data_t) + CDD_PAD];
alignas(16) char cdd_apps_buf[sizeof(wifi_app_t) + CDD_PAD];

cac_event_hal_disassoc_device_test_case_t cac_event_hal_disassoc_device_suite[] = {
    /* name          existing mac0  reason expect_remove */
    { "found",         1,      0x10, 3,     1 },
    { "not_found",     0,      0x10, 3,     0 },
    { "mac_hex",       1,      0xaa, 7,     1 },
    { NULL, 0, 0, 0, 0 }
};

void construct_cac_event_hal_disassoc_device_input(const cac_event_hal_disassoc_device_test_case_t *tc)
{
    memset(cdd_arg_buf, 0, sizeof(cdd_arg_buf));
    memset(cdd_apps_buf, 0, sizeof(cdd_apps_buf));
    assoc_dev_data_t *a = (assoc_dev_data_t *)cdd_arg_buf;
    a->ap_index = 2; a->reason = tc->reason;
    for (int b = 0; b < 6; b++) a->dev_stats.cli_MACAddress[b] = (unsigned char)(tc->mac0 + b);
    ((wifi_app_t *)cdd_apps_buf)->data.u.cac.sta_map = (void *)0x1;
    cdd_existing = tc->existing;
    snprintf(cdd_existing_key, sizeof(cdd_existing_key), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)tc->mac0,(unsigned char)(tc->mac0+1),(unsigned char)(tc->mac0+2),
             (unsigned char)(tc->mac0+3),(unsigned char)(tc->mac0+4),(unsigned char)(tc->mac0+5));
    cdd_tmp_len = 0; cdd_key_seen[0] = 0; cdd_remove_calls = 0;
}
