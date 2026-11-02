/*
 * HANDLER: process_csi
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi.c. No fixes.
 * Local arrays: result_mac (mac_address_t, 6; memcpy of mac_size=6) and
 * mac_str (mac_addr_str_t, 18; to_mac_str) -- both bounded.
 *
 * Driven down the map-found path with create_wifi_event() returning NULL, so
 * result_mac + mac_str are written and the function returns RETURN_ERR before
 * the wifi_event struct work. Redirect: to_mac_str()->pcs slot(18). The RUNNER
 * poisons the mac_str slot past 18 and the caller mac_addr past 6. Internal
 * arrays are ASan-stack guarded.
 *
 * Scaffolding (NOT the function under test): get_wifictrl_obj, get_app_by_inst,
 * hash_map_get, create_wifi_event, apps_mgr_event, destroy_wifi_event are
 * file-local stubs; csi_mac_data_t is a local subset.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#define INT int
#define RETURN_ERR -1
#define wifi_app_inst_csi 0x10
#define wifi_event_type_csi 0
#define wifi_event_type_csi_data 0
typedef struct { bool is_mlo; unsigned char mac_addr[6]; } csi_mac_data_t;

static pthread_mutex_t g_csi_map_lock = PTHREAD_MUTEX_INITIALIZER;
static void pcs_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_dbg_print   pcs_print
#define wifi_util_error_print pcs_print
static wifi_ctrl_t *get_wifictrl_obj(void){return pcs_ctrl_null?NULL:(wifi_ctrl_t*)pcs_ctrl_buf;}
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t*m,int inst){(void)m;(void)inst;return pcs_app;}
static void *pcs_hm_get(void*m,const char*k){(void)m;snprintf(pcs_key_seen,sizeof(pcs_key_seen),"%s",k);return pcs_entry;}
#define hash_map_get(m,k)  pcs_hm_get((m),(k))
static void *create_wifi_event(size_t sz,int t,int st){(void)sz;(void)t;(void)st;return NULL;}  /* NULL -> early return after result_mac set */
static void apps_mgr_event(void*m,void*e){(void)m;(void)e;}
static void destroy_wifi_event(void*e){(void)e;}
static char *pcs_to_mac_str(unsigned char*mac,char*key){memset(pcs_slot_mac,0,PCS_MAC_SZ);snprintf(pcs_slot_mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);memcpy(key,pcs_slot_mac,PCS_MAC_SZ);return key;}
#define to_mac_str(m,k)  pcs_to_mac_str((m),(k))

/* --- copied verbatim from source/apps/csi/wifi_csi.c --- */
INT process_csi(mac_address_t mac_addr, wifi_csi_data_t  *csi_data)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    csi_mac_data_t *csi_map_entry = NULL;
    wifi_event_t *event = NULL;
    mac_address_t result_mac = { 0 };
    mac_addr_str_t mac_str = { 0 };
    const size_t mac_size = sizeof(mac_addr_t);

    wifi_util_dbg_print(WIFI_APPS, "%s: CSI data received - MAC  %02x:%02x:%02x:%02x:%02x:%02x\n",__func__, mac_addr[0], mac_addr[1],
                                                        mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d No wifi_ctrl present !\n", __func__, __LINE__);
        return -1;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    wifi_app_t *wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_csi);

    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL csi_app pointer\n", __func__, __LINE__);
        return -1;
    }

    to_mac_str((unsigned char *)mac_addr, mac_str);

    pthread_mutex_lock(&g_csi_map_lock);
    csi_map_entry = hash_map_get(wifi_app->data.u.csi.csi_sounding_mac_map, mac_str);
    if (csi_map_entry == NULL) {
        pthread_mutex_unlock(&g_csi_map_lock);
        wifi_util_error_print(WIFI_APPS, "%s:%d No entry in CSI map for MAC %s\n", __func__,
            __LINE__, mac_str);
        return -1;
    } else {
        if (csi_map_entry->is_mlo == true) {
            memcpy(result_mac, csi_map_entry->mac_addr, mac_size);
        } else {
            // non-MLO case
            memcpy(result_mac, mac_addr, mac_size);
        }
    }
    pthread_mutex_unlock(&g_csi_map_lock);

    event = create_wifi_event(sizeof(wifi_csi_dev_t), wifi_event_type_csi, wifi_event_type_csi_data); 
    if (event == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: memory allocation for event failed.\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memcpy(event->u.csi->sta_mac, result_mac, sizeof(mac_addr_t));
    memcpy(&(event->u.csi->csi), csi_data, sizeof(wifi_csi_data_t));
    apps_mgr_event(&ctrl->apps_mgr, event);

    destroy_wifi_event(event);
    return 0;
}
