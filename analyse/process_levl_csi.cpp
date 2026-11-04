/*
 * HANDLER: process_levl_csi
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes) together
 * with its helper levl_check_timeout (static). Local arrays:
 *   - mac_address_t mac_addr : memcpy of the 6-byte csi_data->sta_mac;
 *   - mac_addr_str_t mac_str : to_mac_str (17 chars + NUL).
 * Both bounded -> SAFE.
 *
 * Scaffolding (NOT under test): hash_map_get is #define-redirected to a
 * one-slot model over a heap levl_sched_data_t; levl_csi_publish is a
 * recording stub (it can drop the slot to exercise the "entry gone" path);
 * to_mac_str is local.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#define MIN_CSI_INTERVAL 100

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static levl_sched_data_t *lpc_slot;
static char lpc_slot_key[32];
static struct timeval lpc_slot_initial;
static void *lpc_get(void *m, const char *key) { (void)m; return (lpc_slot && strcmp(key, lpc_slot_key) == 0) ? lpc_slot : NULL; }
static void levl_csi_publish(unsigned char *mac, wifi_csi_dev_t *d)
{
    (void)mac; (void)d;
    lpc_pub_calls++;
    if (lpc_drop_on_publish && lpc_slot) { free(lpc_slot); lpc_slot = NULL; }
}
#define hash_map_get(m, k)   lpc_get((m), (k))
#define levl_csi_publish(m, d)  levl_csi_publish((unsigned char *)(m), (d))

/* ================= VERBATIM from wifi_levl.c ================= */
static bool levl_check_timeout(levl_sched_data_t *sched_data, struct timeval *t_now)
{
    struct timeval interval;
    int  interval_ms_margin;
    struct timeval timeout;

    if (sched_data == NULL || t_now == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s: Invalid arguments. sched_data %p and t_now %p\n", __func__, sched_data, t_now);
        return FALSE;
    }

    interval_ms_margin = sched_data->interval - (MIN_CSI_INTERVAL/2);

    interval.tv_sec = (interval_ms_margin / 1000);
    interval.tv_usec = (interval_ms_margin % 1000) * 1000;

    timeradd(&sched_data->last_time_publish, &interval, &timeout);

    if (timercmp(t_now, &timeout, >)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

int process_levl_csi(wifi_app_t *app, wifi_csi_dev_t *csi_data)
{
    mac_address_t mac_addr;
    mac_addr_str_t mac_str = { 0 };
    struct timeval t_now = {0};
    memset(mac_addr, 0, sizeof(mac_address_t));
    memcpy(mac_addr, csi_data->sta_mac, sizeof(mac_address_t));

    to_mac_str((unsigned char *)mac_addr, mac_str);
    pthread_mutex_lock(&app->data.u.levl.lock);
    if (app->data.u.levl.curr_sounding_mac_map != NULL) {
        if (hash_map_get(app->data.u.levl.curr_sounding_mac_map, mac_str) == NULL) {
            //Not subscribed by Levl app
            pthread_mutex_unlock(&app->data.u.levl.lock);
            return RETURN_OK;
        }
    }
    wifi_util_dbg_print(WIFI_APPS, "%s: Levl CSI data received - MAC  %02x:%02x:%02x:%02x:%02x:%02x\n",__func__, mac_addr[0], mac_addr[1],
                                                        mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    //publish only when interval reaches apps->data.u.levl.publish_interval
    levl_sched_data_t *levl_sc_data = NULL;
    to_mac_str(mac_addr, mac_str);
    levl_sc_data = (levl_sched_data_t *)hash_map_get(app->data.u.levl.curr_sounding_mac_map, mac_str);

    if (levl_sc_data == NULL) {
        pthread_mutex_unlock(&app->data.u.levl.lock);
        return RETURN_ERR;
    }
    levl_sched_data_t sc_copy = *levl_sc_data;
    wifi_util_dbg_print(WIFI_APPS,
        "CSI snapshot mac:%02x..%02x interval:%d\n",
        mac_addr[0], mac_addr[5], sc_copy.interval);
    //calculate timeout with current time and last time publish
    gettimeofday(&t_now, NULL);
    pthread_mutex_unlock(&app->data.u.levl.lock);
    if ((sc_copy.interval == 0) || levl_check_timeout(&sc_copy, &t_now)) {
        levl_csi_publish(mac_addr, csi_data);
        pthread_mutex_lock(&app->data.u.levl.lock);
        levl_sc_data = (levl_sched_data_t *)hash_map_get(app->data.u.levl.curr_sounding_mac_map, mac_str);
        if (levl_sc_data != NULL) {
            levl_sc_data->last_time_publish = t_now;
        } else {
            wifi_util_dbg_print(WIFI_APPS, "%s:%d entry gone before last_time_publish update\n", __func__, __LINE__);
        }
        pthread_mutex_unlock(&app->data.u.levl.lock);
    }
    return RETURN_OK;
}

/* ================= harness helpers ================= */
void lpc_free_slot(void) { if (lpc_slot) { free(lpc_slot); lpc_slot = NULL; } }
/* last_pub_offset_secs: last_time_publish = now + offset (negative = long ago) */
void lpc_set_slot(const unsigned char *mac, int interval, long last_pub_offset_secs)
{
    lpc_free_slot();
    if (!mac) return;
    lpc_slot = (levl_sched_data_t *)calloc(1, sizeof(levl_sched_data_t));
    memcpy(lpc_slot->mac_addr, mac, 6);
    lpc_slot->interval = interval;
    gettimeofday(&lpc_slot->last_time_publish, NULL);
    lpc_slot->last_time_publish.tv_sec += last_pub_offset_secs;
    lpc_slot_initial = lpc_slot->last_time_publish;
    mac_addr_str_t k;
    to_mac_str(lpc_slot->mac_addr, k);
    snprintf(lpc_slot_key, sizeof(lpc_slot_key), "%s", k);
}
int lpc_slot_updated(void)
{
    return lpc_slot && timercmp(&lpc_slot->last_time_publish, &lpc_slot_initial, !=);
}
