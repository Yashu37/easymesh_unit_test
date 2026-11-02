/*
 * TEST CASES / CONSTRUCTOR: construct_cac_event_hal_assoc_device
 *
 * arg is an assoc_dev_data_t at cad_arg_buf; apps at cad_apps_buf. A new or
 * existing station is keyed by the lower-case MAC. Cases exercise the
 * not-hotspot early return, vap-name/config failures, a new station (malloc),
 * an existing station (updated), and LAST a failing malloc (NULL deref).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#define RETURN_OK 0
#define NL_OK 0

char   cad_slot_mac[CAD_MAC_SZ + CAD_PAD];
char   cad_slot_tmp[CAD_TMP_SZ + CAD_PAD];
size_t cad_tmp_len;
char   cad_key_seen[64], cad_put_key[64], cad_existing_key[32];
void  *cad_existing, *cad_put_data;
int    cad_is_hotspot, cad_vap_fail, cad_cfg_fail, cad_malloc_fail, cad_pool_used;
alignas(16) unsigned char cad_pool[CAD_POOL][sizeof(cac_associated_devices_t) + CAD_PAD];
alignas(16) char cad_mgr_buf[sizeof(wifi_mgr_t) + CAD_PAD];
alignas(16) char cad_arg_buf[sizeof(assoc_dev_data_t) + CAD_PAD];
alignas(16) char cad_apps_buf[sizeof(wifi_app_t) + CAD_PAD];
static cac_associated_devices_t cad_known;

cac_event_hal_assoc_device_test_case_t cac_event_hal_assoc_device_suite[] = {
    /* name           hotspot vapfail cfgfail existing mallocfail mac0  ret       put */
    { "not_hotspot",    0,     0,      0,      0,       0,         0x10, RETURN_OK, 0 },
    { "vap_name_fail",  1,     1,      0,      0,       0,         0x10, NL_OK,     0 },
    { "cfg_fail",       1,     0,      1,      0,       0,         0x10, NL_OK,     0 },
    { "new_station",    1,     0,      0,      0,       0,         0x10, RETURN_OK, 1 },
    { "existing_sta",   1,     0,      0,      1,       0,         0x10, RETURN_OK, 0 },
    { "mac_hex",        1,     0,      0,      0,       0,         0xaa, RETURN_OK, 1 },
    { "malloc_fails",   1,     0,      0,      0,       1,         0x10, RETURN_OK, 0 },  /* NULL deref expected */

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_cac_event_hal_assoc_device_input(const cac_event_hal_assoc_device_test_case_t *tc)
{
    memset(cad_mgr_buf, 0, sizeof(cad_mgr_buf));
    memset(cad_arg_buf, 0, sizeof(cad_arg_buf));
    memset(cad_apps_buf, 0, sizeof(cad_apps_buf));
    memset(cad_pool, 0xAB, sizeof(cad_pool));

    assoc_dev_data_t *a = (assoc_dev_data_t *)cad_arg_buf;
    a->ap_index = 3;
    for (int b = 0; b < 6; b++) a->dev_stats.cli_MACAddress[b] = (unsigned char)(tc->mac0 + b);
    a->dev_stats.cli_RSSI = -50; a->dev_stats.cli_SNR = 30; a->dev_stats.cli_LastDataUplinkRate = 100;
    ((wifi_app_t *)cad_apps_buf)->data.u.cac.sta_map = (void *)0x1;

    memset(&cad_known, 0, sizeof(cad_known));
    cad_existing = tc->existing ? &cad_known : NULL;
    snprintf(cad_existing_key, sizeof(cad_existing_key), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)tc->mac0,(unsigned char)(tc->mac0+1),(unsigned char)(tc->mac0+2),
             (unsigned char)(tc->mac0+3),(unsigned char)(tc->mac0+4),(unsigned char)(tc->mac0+5));

    cad_is_hotspot = tc->hotspot; cad_vap_fail = tc->vapfail; cad_cfg_fail = tc->cfgfail;
    cad_malloc_fail = tc->mallocfail; cad_pool_used = 0;
    cad_tmp_len = 0; cad_key_seen[0] = cad_put_key[0] = 0; cad_put_data = NULL;
}
