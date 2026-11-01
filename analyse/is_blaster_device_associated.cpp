/*
 * HANDLER: is_blaster_device_associated
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local array sta_key (sta_key_t = char[STA_KEY_LEN], and
 * STA_KEY_LEN = 2*MAC_ADDR_LEN + 6 = 18) is filled by the file's static
 * to_sta_key(): snprintf(key, STA_KEY_LEN, "%02x:..")  -> 17 chars + NUL,
 * i.e. exactly 18 bytes.
 *
 * Redirect: to_sta_key() -> bib_to_sta_key(): the verbatim to_sta_key on the
 * runner slot bib_slot_key (SAME size, 18), then copied into sta_key.
 * The RUNNER poisons bib_slot_key past 18, the caller's sta_mac past
 * MAC_ADDR_LEN, the caller's is_mlo past sizeof(bool), and the vap-info and
 * station structs past their sizes. sta_key is also guarded by ASan stack
 * redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - get_wifidb_rdk_vap_info(): returns the runner's vap info (or NULL).
 *   - hash_map_get(): returns the runner's station when the key matches.
 *   - wifi_util_error_print(): really formats its arguments.
 *   - rdk_wifi_vap_info_t: subset in common.h (vap_index, lock, map).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0

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
    bib_vap_lookups++;
    bib_lookup_index = ap_index;
    return bib_vap;
}

static void *bib_hash_map_get(void *map, const char *key)
{
    (void)map;
    snprintf(bib_key_seen, sizeof(bib_key_seen), "%s", key);
    return (bib_sta && !strcmp(key, bib_sta_key)) ? bib_sta : NULL;
}
#define hash_map_get(m, k)  bib_hash_map_get((m), (k))

/* verbatim from source/apps/blaster/wifi_blaster.c */
static inline char *to_sta_key    (mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

/* redirect: write into the runner slot of the same size as sta_key */
static char *bib_to_sta_key(unsigned char *mac, char *key)
{
    memset(bib_slot_key, 0, BIB_KEY_SZ);
    to_sta_key(mac, bib_slot_key);
    memcpy(key, bib_slot_key, BIB_KEY_SZ);
    bib_key_len = strnlen(bib_slot_key, BIB_KEY_SZ);
    return key;
}
#define to_sta_key(m, k)  bib_to_sta_key((m), (k))

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c --- */
bool is_blaster_device_associated(int ap_index, mac_address_t sta_mac, bool *is_mlo)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *sta = NULL;
    sta_key_t sta_key;

    rdk_vap_info = get_wifidb_rdk_vap_info(ap_index);
    if(rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get rdk_vap_info from vap index %d\n", __func__, ap_index);
        return false;
    }

    pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
    if (rdk_vap_info->associated_devices_map == NULL) {
        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
        wifi_util_error_print(WIFI_BLASTER,"%s:%d NULL  associated_devices_map  pointer  for  %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
        return false;
    }

    wifi_util_error_print(WIFI_BLASTER, "%s: sta_mac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);

    to_sta_key(sta_mac, sta_key);
    sta = (assoc_dev_data_t *) hash_map_get(rdk_vap_info->associated_devices_map, sta_key);
    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
    if (sta == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get sta from vap index %d\n", __func__, ap_index);
        return false;
    }
    else {
        if (is_mlo && !(*is_mlo))
            *is_mlo = sta->dev_stats.cli_MLDEnable;
        return true;
    }

    return false;
}
