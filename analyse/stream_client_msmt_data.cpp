/*
 * HANDLER: stream_client_msmt_data
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_single_client_msmt.c.
 * No fixes. Local sta_key_t sta_key (char[STA_KEY_LEN]=18) is filled by
 * to_sta_key(curStepData.DestMac, sta_key)  (snprintf(key, 18, ..) -> 17+NUL).
 *
 * Redirect: to_sta_key() -> scm_to_sta_key(): the file's static to_sta_key on
 * the runner slot scm_slot_key (SAME size, 18), then copied into sta_key. The
 * RUNNER poisons scm_slot_key past 18 and the mgr/ctrl stand-ins past their
 * sizes. sta_key is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): the upload functions are
 * file-local no-ops (the real gw path leads to the avro serializer, skipped);
 * hash_map_get is a tiny runner stub; active_msmt_status_to_str is a stub.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define rdk_dev_mode_type_gw  0
#define rdk_dev_mode_type_ext 1

static void scm_print(int module, const char *fmt, ...)
{ char sc[512]; va_list ap; (void)module; va_start(ap, fmt); vsnprintf(sc, sizeof(sc), fmt, ap); va_end(ap); }
#define wifi_util_error_print  scm_print
#define wifi_util_info_print   scm_print

static void *get_wifictrl_obj(void) { return scm_wctrl_buf; }
static void *get_wifi_blaster(void) { return scm_mgr_null ? NULL : scm_mgr_buf; }
static char *active_msmt_status_to_str(active_msmt_status_t s) { (void)s; return (char *)"SUCCEED"; }
static void upload_single_client_active_msmt_data(blaster_hashmap_t *sta) { (void)sta; scm_upload_calls++; }
static void pod_upload_single_client_active_msmt_data(blaster_hashmap_t *sta) { (void)sta; scm_pod_calls++; }

static void *scm_hash_map_get(void *map, const char *key)
{
    (void)map;
    snprintf(scm_key_seen, sizeof(scm_key_seen), "%s", key);
    return (scm_existing && !strcmp(key, scm_existing_key)) ? scm_existing : NULL;
}
#define hash_map_get(m, k)  scm_hash_map_get((m), (k))

/* verbatim to_sta_key from source/apps/blaster/wifi_single_client_msmt.c */
static inline char *to_sta_key(mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static char *scm_to_sta_key(unsigned char *mac, char *key)
{
    memset(scm_slot_key, 0, SCM_KEY_SZ);
    to_sta_key(mac, scm_slot_key);
    memcpy(key, scm_slot_key, SCM_KEY_SZ);
    scm_key_len = strnlen(scm_slot_key, SCM_KEY_SZ);
    return key;
}
#define to_sta_key(m, k)  scm_to_sta_key((m), (k))

/* --- copied verbatim from source/apps/blaster/wifi_single_client_msmt.c --- */
void stream_client_msmt_data(bool ActiveMsmtFlag)
{
    if (ActiveMsmtFlag)
    {
        wifi_actvie_msmt_t *act_monitor;
        wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
        blaster_hashmap_t *sta = NULL;
        hash_map_t *blaster_map = NULL;
        sta_key_t sta_key;

        act_monitor = (wifi_actvie_msmt_t *)get_wifi_blaster();
        if(act_monitor == NULL) {
            wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get act_monitor\n", __func__);
            return;
        }

        blaster_map = act_monitor->active_msmt_map;
        if (blaster_map == NULL) {
            wifi_util_error_print(WIFI_BLASTER,"%s:%d NULL active_blaster-data map\n", __func__, __LINE__);
            return;
        }

        to_sta_key(act_monitor->curStepData.DestMac, sta_key);
        sta = (blaster_hashmap_t *) hash_map_get(blaster_map, sta_key);

        if (sta == NULL) {
            wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get hash_map\n", __func__);
            return;
        }

	    wifi_util_info_print(WIFI_BLASTER,"%s:%d status of blaster: %s\n", __func__, __LINE__,  active_msmt_status_to_str(act_monitor->status));

        if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            upload_single_client_active_msmt_data(sta);
        } else if (ctrl->network_mode == rdk_dev_mode_type_ext) {
            pod_upload_single_client_active_msmt_data(sta);
        }
    }
}
