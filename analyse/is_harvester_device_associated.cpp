/*
 * HANDLER: is_harvester_device_associated
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c. Local
 * array:
 *   - sta_key_t sta_key (char[STA_KEY_LEN]) : written by to_sta_key()
 *     (snprintf of a mac -> 17 chars + NUL, within STA_KEY_LEN=18).
 * No array can be overrun -> SAFE. (Same pattern as is_blaster_device_associated.)
 *
 * Scaffolding (NOT under test): get_wifidb_rdk_vap_info / hash_map_get are
 * stubbed; to_sta_key is #define-redirected to write into a runner-owned slot
 * of the same size (whose tail the runner poisons) before copying back.
 * Driven by the ihd_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

#define WIFI_HARVESTER 0
static void wifi_util_error_print(int module, const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; (void)module;
    va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}

static rdk_wifi_vap_info_t *get_wifidb_rdk_vap_info(int ap_index)
{
    ihd_vap_lookups++;
    ihd_lookup_index = ap_index;
    return ihd_vap;
}

static void *ihd_hash_map_get(void *map, const char *key)
{
    (void)map;
    snprintf(ihd_key_seen, sizeof(ihd_key_seen), "%s", key);
    return (ihd_sta && !strcmp(key, ihd_sta_key)) ? ihd_sta : NULL;
}
#define hash_map_get(m, k)  ihd_hash_map_get((m), (k))

/* verbatim from source/apps/harvester/wifi_harvester.c */
static inline char *to_sta_key(mac_address_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

/* redirect: write into the runner slot of the same size as sta_key */
static char *ihd_to_sta_key(unsigned char *mac, char *key)
{
    memset(ihd_slot_key, 0, IHD_KEY_SZ);
    to_sta_key(mac, ihd_slot_key);
    memcpy(key, ihd_slot_key, IHD_KEY_SZ);
    ihd_key_len = strnlen(ihd_slot_key, IHD_KEY_SZ);
    return key;
}
#define to_sta_key(m, k)  ihd_to_sta_key((m), (k))

/* ================= VERBATIM from wifi_harvester.c ================= */
bool is_harvester_device_associated(int ap_index, mac_address_t sta_mac)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *sta = NULL;
    sta_key_t sta_key;

    rdk_vap_info = get_wifidb_rdk_vap_info(ap_index);
    if(rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_HARVESTER, "%s: Failed to get rdk_vap_info from vap index %d\n", __func__, ap_index);
        return false;
    }

    pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
    if (rdk_vap_info->associated_devices_map == NULL) {
        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d NULL  associated_devices_map  pointer  for  %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
        return false;
    }

    wifi_util_error_print(WIFI_HARVESTER, "%s: sta_mac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);

    to_sta_key(sta_mac, sta_key);
    sta = (assoc_dev_data_t *) hash_map_get(rdk_vap_info->associated_devices_map, sta_key);
    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
    if (sta == NULL) {
        wifi_util_error_print(WIFI_HARVESTER, "%s: Failed to get sta from vap index %d\n", __func__, ap_index);
        return false;
    }
    else {
        return true;
    }

    return false;
}
