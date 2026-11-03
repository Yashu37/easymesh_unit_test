/*
 * TEST CASES / CONSTRUCTOR: construct_is_harvester_device_associated
 *
 * The query MAC lives in ihd_mac_buf (runner poisons past its 6 bytes). ihd_vap
 * is the rdk_vap_info (with a real lock + a non-NULL map pointer); ihd_sta is
 * the station the map returns when the key matches ihd_sta_key. The handler's
 * to_sta_key writes into ihd_slot_key (runner poisons its tail).
 *
 * Cases: associated (key matches -> true), not_associated (map miss -> false),
 * vap_null (no rdk_vap_info -> false), map_null (NULL map -> false).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"

rdk_wifi_vap_info_t *ihd_vap;
int   ihd_vap_lookups, ihd_lookup_index, ihd_key_len;
assoc_dev_data_t *ihd_sta;
char  ihd_sta_key[64];
char  ihd_key_seen[64];
char  ihd_slot_key[IHD_KEY_SZ + IHD_PAD];
unsigned char ihd_mac_buf[6 + IHD_PAD];

static rdk_wifi_vap_info_t ihd_vap_store;
static assoc_dev_data_t    ihd_sta_store;
static pthread_mutex_t     ihd_lock = PTHREAD_MUTEX_INITIALIZER;

harv_ihd_test_case_t is_harvester_device_associated_suite[] = {
    /* name            vap_null map_null sta_present want */
    { "associated",       0,    0,       1,          true  },
    { "not_associated",   0,    0,       0,          false },
    { "vap_null",         1,    0,       0,          false },
    { "map_null",         0,    1,       0,          false },
    { NULL, 0, 0, 0, false }  /* sentinel */
};

void construct_is_harvester_device_associated_input(const harv_ihd_test_case_t *tc)
{
    memset(ihd_mac_buf, 0, sizeof(ihd_mac_buf));
    memset(&ihd_vap_store, 0, sizeof(ihd_vap_store));
    memset(&ihd_sta_store, 0, sizeof(ihd_sta_store));
    ihd_vap_lookups = 0; ihd_lookup_index = 0; ihd_key_len = 0;
    ihd_key_seen[0] = 0;

    unsigned char mac[6] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    memcpy(ihd_mac_buf, mac, 6);
    snprintf(ihd_sta_key, sizeof(ihd_sta_key), "30:31:32:33:34:35");

    ihd_vap_store.vap_index = 1;
    ihd_vap_store.associated_devices_lock = &ihd_lock;
    ihd_vap_store.associated_devices_map = tc->map_null ? NULL : (void *)0x1;

    ihd_vap = tc->vap_null ? NULL : &ihd_vap_store;
    ihd_sta = tc->sta_present ? &ihd_sta_store : NULL;
}
