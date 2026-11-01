/*
 * HANDLER: process_active_msmt_diagnostics
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local array sta_key_t sta_key (char[STA_KEY_LEN] = 18) is filled
 * by to_sta_key(curStepData.DestMac, sta_key)  (snprintf(key, 18, ..) -> 17
 * chars + NUL) then str_tolower(sta_key) in place.
 *
 * Redirect: to_sta_key() -> pad_to_sta_key(): the file's static to_sta_key
 * run on the runner slot pad_slot_key (SAME size, 18), then copied into
 * sta_key. The RUNNER poisons pad_slot_key past 18, the g_active_msmt
 * stand-in past its size, and the source sample array past its real count.
 * sta_key is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - get_wifi_blaster(): returns the runner's stand-in.
 *   - str_tolower(): verbatim from lib/common/util.c.
 *   - hash_map_get/put(): tiny runner table (put frees the strdup'd key).
 *   - active_msmt_log_message(): static no-op recorder (file-local, so it
 *     does not collide with the other harness's global definition).
 *   - wifi_util_dbg_print / error_print: really format their arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <pthread.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define WIFI_APPS    0
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(arg) arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]

static void pad_print(int module, const char *fmt, ...)
{
    char scratch[2048]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print    pad_print
#define wifi_util_error_print  pad_print

static void active_msmt_log_message(int level, const char *fmt, ...) { (void)level; (void)fmt; pad_calls++; }

static void *get_wifi_blaster(void) { return pad_mgr_buf; }

/* verbatim from source/apps/blaster/wifi_blaster.c */
static inline char *to_sta_key    (mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

/* verbatim from lib/common/util.c */
static char *str_tolower(char *str)
{
    unsigned char *s = (unsigned char*)str;
    while (s && *s) { *s =(unsigned char) tolower(*s); s++; }
    return str;
}

static void *pad_hash_map_get(void *map, const char *key)
{
    (void)map;
    snprintf(pad_key_seen, sizeof(pad_key_seen), "%s", key);
    return (pad_existing && !strcmp(key, pad_existing_key)) ? pad_existing : NULL;
}
static int8_t pad_hash_map_put(void *map, char *key, void *data)
{
    (void)map;
    snprintf(pad_put_key, sizeof(pad_put_key), "%s", key);
    pad_put_data = data;
    free(key);
    return 0;
}
#define hash_map_get(m, k)     pad_hash_map_get((m), (k))
#define hash_map_put(m, k, d)  pad_hash_map_put((m), (k), (d))

/* redirect: write into the runner slot of the same size as sta_key */
static char *pad_to_sta_key(unsigned char *mac, char *key)
{
    memset(pad_slot_key, 0, PAD_KEY_SZ);
    to_sta_key(mac, pad_slot_key);
    memcpy(key, pad_slot_key, PAD_KEY_SZ);
    pad_key_len = strnlen(pad_slot_key, PAD_KEY_SZ);
    return key;
}
#define to_sta_key(m, k)  pad_to_sta_key((m), (k))

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c --- */
void process_active_msmt_diagnostics (int ap_index)
{
    hash_map_t *blaster_map = NULL;
    blaster_hashmap_t *sta = NULL;
    sta_key_t       sta_key;
    unsigned int count = 0;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d  apindex : %d \n",__func__,__LINE__,ap_index);

    blaster_map = g_active_msmt->active_msmt_map;
    if (blaster_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL active_blaster-data map\n", __func__, __LINE__);
        return;
    }

    to_sta_key(g_active_msmt->curStepData.DestMac, sta_key);
    str_tolower(sta_key);

    sta = (blaster_hashmap_t *)hash_map_get(blaster_map, sta_key);

    if (sta == NULL) {
        /* added the data in sta map for offline clients */
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d station info is null \n",__func__,__LINE__);
        sta = (blaster_hashmap_t *) malloc (sizeof(blaster_hashmap_t));
        if (sta == NULL) {
            return;
        }
        memset(sta, 0, sizeof(blaster_hashmap_t));
        pthread_mutex_lock(&g_active_msmt->lock);
        memcpy(&sta->sta_mac, g_active_msmt->curStepData.DestMac, sizeof(mac_addr_t));
        hash_map_put(blaster_map, strdup(sta_key), sta);

        if (ap_index == -1) {
            sta->sta_active_msmt_data = (active_msmt_data_t *) calloc (g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples,sizeof(active_msmt_data_t));
            if (sta->sta_active_msmt_data == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "%s : %d allocating sta_active_msmt_data failed for offline clients\n",__func__,__LINE__);
            }
            pthread_mutex_unlock(&g_active_msmt->lock);
            return;
        }
        pthread_mutex_unlock(&g_active_msmt->lock);

    } else {
          if (ap_index == -1) {
              if (sta->sta_active_msmt_data == NULL) {
                  sta->sta_active_msmt_data = (active_msmt_data_t*) calloc (g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples,sizeof(active_msmt_data_t));
                  if (sta->sta_active_msmt_data == NULL) {
                      wifi_util_error_print(WIFI_BLASTER, "%s : %d memory allocation failed for offline clients\n",__func__,__LINE__);
                      return;
                  }
              }
            return;
          }

        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d copying mac : " MAC_FMT " to station info\n", __func__, __LINE__,
                MAC_ARG(g_active_msmt->curStepData.DestMac));
        memcpy(&sta->sta_mac, g_active_msmt->curStepData.DestMac, sizeof(mac_addr_t));
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d allocating memory for sta_active_msmt_data \n",__func__,__LINE__);
    if (sta->sta_active_msmt_data == NULL) {
        sta->sta_active_msmt_data = calloc(g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples,
            sizeof(active_msmt_data_t));
    }

    if (sta->sta_active_msmt_data == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s : %d allocating memory for sta_active_msmt_data failed\n",__func__,__LINE__);
        /*CID: 146766 Dereference after null check*/
        return;
    }

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Number of sample %d for client [" MAC_FMT "]\n", __FUNCTION__, __LINE__,
         g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples, MAC_ARG(g_active_msmt->curStepData.DestMac));

    if (g_active_msmt->active_msmt_data != NULL) {
        for (count = 0; count < g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples; count++) {
            sta->sta_active_msmt_data[count].rssi = g_active_msmt->active_msmt_data[count].rssi;
            sta->sta_active_msmt_data[count].TxPhyRate = g_active_msmt->active_msmt_data[count].TxPhyRate;
            sta->sta_active_msmt_data[count].RxPhyRate = g_active_msmt->active_msmt_data[count].RxPhyRate;
            sta->sta_active_msmt_data[count].SNR = g_active_msmt->active_msmt_data[count].SNR;
            sta->sta_active_msmt_data[count].ReTransmission = g_active_msmt->active_msmt_data[count].ReTransmission;
            sta->sta_active_msmt_data[count].MaxRxRate = g_active_msmt->active_msmt_data[count].MaxRxRate;
            sta->sta_active_msmt_data[count].MaxTxRate = g_active_msmt->active_msmt_data[count].MaxTxRate;
            strncpy(sta->sta_active_msmt_data[count].Operating_standard, g_active_msmt->active_msmt_data[count].Operating_standard,OPER_BUFFER_LEN);
            strncpy(sta->sta_active_msmt_data[count].Operating_channelwidth, g_active_msmt->active_msmt_data[count].Operating_channelwidth,OPER_BUFFER_LEN);
            sta->sta_active_msmt_data[count].throughput = g_active_msmt->active_msmt_data[count].throughput;

            active_msmt_log_message(BLASTER_DEBUG_LOG, "count[%d] : standard[%s] chan_width[%s] Retransmission [%d]"
                "RSSI[%d] TxRate[%lu Mbps] RxRate[%lu Mbps] SNR[%d] throughput[%.5lf Mbps]"
                "MaxTxRate[%d] MaxRxRate[%d]\n",
                count, sta->sta_active_msmt_data[count].Operating_standard,
                sta->sta_active_msmt_data[count].Operating_channelwidth,
                sta->sta_active_msmt_data[count].ReTransmission,
                sta->sta_active_msmt_data[count].rssi, sta->sta_active_msmt_data[count].TxPhyRate,
                sta->sta_active_msmt_data[count].RxPhyRate, sta->sta_active_msmt_data[count].SNR,
                sta->sta_active_msmt_data[count].throughput,
                sta->sta_active_msmt_data[count].MaxTxRate,
                sta->sta_active_msmt_data[count].MaxRxRate);
        }
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d exiting the function\n",__func__,__LINE__);
}
