/*
 * HANDLER: levl_event_webconfig_set_data
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array:
 *   - mac_address_t null_mac[6] : only memcmp'd (6 bytes) against the 6-byte
 *     levl_config->clientMac -> bounded, SAFE.
 * The handler copies scalar config fields into apps->data.u.levl and calls
 * get_ap_index_from_clientmac / schedule_mac_for_sounding_locked.
 *
 * Scaffolding (NOT under test): get_ap_index_from_clientmac returns lse_ap_ret;
 * schedule_mac_for_sounding_locked is a recording stub; types are the minimal
 * subset in common.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define MAX_LEVL_CSI_CLIENTS 5
#define webconfig_subdoc_type_levl 5
typedef int wifi_event_subtype_t;

static int lse_get_ap(unsigned char *mac) { (void)mac; return lse_ap_ret; }
static int lse_schedule(int ap, unsigned char *mac, int dur, int interval)
{
    lse_sched_calls++; lse_sched_ap = ap; memcpy(lse_sched_mac, mac, 6); lse_sched_dur = dur; lse_sched_int = interval; return 0;
}
#define get_ap_index_from_clientmac(m)                       lse_get_ap((unsigned char *)(m))
#define schedule_mac_for_sounding_locked(a, m, d, i)         lse_schedule((a), (unsigned char *)(m), (d), (i))

/* ================= VERBATIM from wifi_levl.c ================= */
int levl_event_webconfig_set_data(wifi_app_t *apps, void *arg, wifi_event_subtype_t sub_type)
{
    int ap_index = 0;
    int max_value = 0;
    levl_config_t *levl_config = NULL;
    mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)arg;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Decoded data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    switch(doc->type) {
        case webconfig_subdoc_type_levl:
            levl_config = &decoded_params->levl;
            if (levl_config == NULL) {
                wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL pointer \n", __func__, __LINE__);
                return RETURN_ERR;
            }
            pthread_mutex_lock(&apps->data.u.levl.lock);
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Received config Client num %d, Client MAC %02x:... %02x publish interval %d sounding duration %d\n", __func__, __LINE__,
                    levl_config->max_num_csi_clients, levl_config->clientMac[0], levl_config->clientMac[5], levl_config->levl_publish_interval, levl_config->levl_sounding_duration);
            if (levl_config->max_num_csi_clients == 0) {
                max_value = MAX_LEVL_CSI_CLIENTS;
            } else {
                max_value = levl_config->max_num_csi_clients;
            }
            apps->data.u.levl.max_num_csi_clients = max_value;
            if (levl_config->levl_sounding_duration != apps->data.u.levl.sounding_duration) {
                apps->data.u.levl.sounding_duration = levl_config->levl_sounding_duration;
            }

            if (levl_config->levl_publish_interval != apps->data.u.levl.publish_interval) {
                apps->data.u.levl.publish_interval = levl_config->levl_publish_interval;
            }
            if (memcmp(null_mac, levl_config->clientMac, sizeof(mac_address_t)) != 0) {
                ap_index = get_ap_index_from_clientmac(levl_config->clientMac);
                if (ap_index < 0) {
                    wifi_util_dbg_print(WIFI_APPS,"%s:%d Client is not connected not pushing to queue\n", __func__, __LINE__);
                } else {
                    schedule_mac_for_sounding_locked(ap_index, levl_config->clientMac, levl_config->levl_sounding_duration, levl_config->levl_publish_interval);
                }
            }
            pthread_mutex_unlock(&apps->data.u.levl.lock);
            break;
        default:
            break;
    }

    return RETURN_OK;
}
