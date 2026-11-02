/*
 * HANDLER: csi_stop_fn
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi.c. No fixes.
 * Only local array is mac_str[18] (to_mac_str, bounded). Looks the station up
 * (directly, or by MLD match in the map) and disables/removes it.
 *
 * Redirect: to_mac_str()->csp slot(18); the RUNNER poisons that slot past 18
 * and the caller mac_addr past 6 and the app stand-in past its size. mac_str
 * is ASan-stack guarded. hash_map_remove returns malloc'd memory so the
 * handler's free() is valid.
 *
 * Scaffolding (NOT the function under test): hash_map_*, wifi_enableCSIEngine,
 * update_pinger_config are file-local stubs; csi_mac_data_t is shared (common.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#define FALSE 0
static pthread_mutex_t g_csi_map_lock = PTHREAD_MUTEX_INITIALIZER;
static void csp_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_dbg_print   csp_print
#define wifi_util_info_print  csp_print
#define wifi_util_error_print csp_print
static void *csp_hm_get(void*m,const char*k){(void)m;snprintf(csp_key_seen,sizeof(csp_key_seen),"%s",k);return csp_entry;}
static void *csp_hm_get_first(void*m){(void)m;return csp_first;}
static void *csp_hm_get_next(void*m,void*e){(void)m;(void)e;return NULL;}
static void *csp_hm_remove(void*m,const char*k){(void)m;(void)k;csp_remove_calls++;return malloc(sizeof(csi_mac_data_t));}
#define hash_map_get(m,k)      csp_hm_get((m),(k))
#define hash_map_get_first(m)  csp_hm_get_first((m))
#define hash_map_get_next(m,e) csp_hm_get_next((m),(e))
#define hash_map_remove(m,k)   csp_hm_remove((m),(k))
static void wifi_enableCSIEngine(unsigned int ap,unsigned char*mac,int en){(void)ap;(void)mac;(void)en;}
static void update_pinger_config(unsigned int ap,unsigned char*mac,int b){(void)ap;(void)mac;(void)b;}
static char *csp_to_mac_str(unsigned char*mac,char*key){memset(csp_slot_mac,0,CSP_MAC_SZ);snprintf(csp_slot_mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);memcpy(key,csp_slot_mac,CSP_MAC_SZ);return key;}
#define to_mac_str(m,k)  csp_to_mac_str((m),(k))

/* --- copied verbatim from source/apps/csi/wifi_csi.c --- */
int csi_stop_fn(void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    mac_addr_str_t mac_str = { 0 };

    wifi_app_t *app = (wifi_app_t *)csi_app;
    if (app == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    wifi_util_dbg_print(WIFI_APPS,
        "%s:%d stop ap:%u app:%d mac:%02x..%02x\n",
        __func__, __LINE__, ap_index, sounding_app, mac_addr[0], mac_addr[5]);

    to_mac_str((unsigned char *)mac_addr, mac_str);
    //Check if the MAC is there in the hash_map.
    if (app->data.u.csi.csi_sounding_mac_map == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    pthread_mutex_lock(&g_csi_map_lock);
    csi_mac_data_t *mac_data = (csi_mac_data_t *)hash_map_get(app->data.u.csi.csi_sounding_mac_map, mac_str);
    if (mac_data == NULL) {
        // We hash in MLO case by link address, so we need to
        // map this for MLO clients, since apps use MLD MAC
        mac_data = (csi_mac_data_t *)hash_map_get_first(app->data.u.csi.csi_sounding_mac_map);
        while(mac_data != NULL) {
            if (memcmp(mac_data->mac_addr, mac_addr, sizeof(mac_addr_t)) == 0) {
                to_mac_str((unsigned char *)mac_data->link_addr, mac_str);
                break;
            }
            mac_data = hash_map_get_next(app->data.u.csi.csi_sounding_mac_map, mac_data);
        }

        if (mac_data == NULL) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Rogue Disable Request from app %d\n", __func__, __LINE__, sounding_app);
            pthread_mutex_unlock(&g_csi_map_lock);
            return 0;
        }
    }

    //Check if the mac is currently sounding by more apps.
    if (mac_data->subscribed_apps & ~sounding_app) {
        wifi_util_info_print(WIFI_APPS, "%s:%d MAC is being sounded by more than one apps not disabling sounding\n", __func__, __LINE__);
        mac_data->subscribed_apps &= ~sounding_app;
        pthread_mutex_unlock(&g_csi_map_lock);
    } else {
        //Disable Sounding.
        wifi_util_info_print(WIFI_APPS, "%s:%d Disabling CSI for mac %02x..%02x\n", __func__, __LINE__, mac_data->mac_addr[0], mac_data->mac_addr[5]);
        wifi_enableCSIEngine(mac_data->ap_index, mac_data->mac_addr, FALSE);
        mac_data = (csi_mac_data_t *)hash_map_remove(app->data.u.csi.csi_sounding_mac_map, mac_str);
        if (mac_data == NULL) {
            wifi_util_error_print(WIFI_APPS, "%s:%d hash_map_remove returned NULL for mac_str %s\n", __func__, __LINE__, mac_str);
            pthread_mutex_unlock(&g_csi_map_lock);
            return -1;
        }
        if (app->data.u.csi.num_current_sounding > 0) {
            app->data.u.csi.num_current_sounding--;
        }
        pthread_mutex_unlock(&g_csi_map_lock);
        update_pinger_config(mac_data->ap_index, mac_data->mac_addr, true);
        free(mac_data);
    }
    return 0;
}
