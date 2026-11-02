/*
 * HANDLER: csi_start_fn
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi.c. No fixes.
 * Local arrays: mac_str[18], evicted_mac_str[18] (to_mac_str, bounded),
 * link_addr (mac_addr_t 6; memcpy of mac_size=6, bounded). The malloc of the
 * new csi_mac_data_t and the strdup/hash_map_put are all NULL-checked here.
 *
 * Redirect: to_mac_str()->csf slot(18) (shared by mac_str + evicted_mac_str);
 * the RUNNER poisons that slot past 18 and the caller mac_addr past 6, and the
 * rdk_vap / app stand-ins past their sizes. Internal arrays are ASan-stack
 * guarded. malloc/strdup/free/hash_map_* are real or file-local stubs.
 *
 * Scaffolding (NOT the function under test): get_wifidb_rdk_vap_info,
 * hash_map_*, wifi_enableCSIEngine, update_pinger_config are stubs;
 * csi_mac_data_t is a local subset.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#define TRUE 1
#define FALSE 0
#define MAX_NUM_CSI_SOUNDING 5
#define wifi_app_inst_motion 0x20

static pthread_mutex_t g_csi_map_lock = PTHREAD_MUTEX_INITIALIZER;
static void csf_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_dbg_print   csf_print
#define wifi_util_info_print  csf_print
#define wifi_util_error_print csf_print
static rdk_wifi_vap_info_t *get_wifidb_rdk_vap_info(unsigned int ap){(void)ap;return csf_vap;}
static void *csf_hm_get(void*m,const char*k){(void)k;if(m==(void*)0x2)return csf_assoc;return csf_csi_entry;}
static void *csf_hm_get_first(void*m){(void)m;return csf_victim;}
static void *csf_hm_get_next(void*m,void*e){(void)m;(void)e;return NULL;}
static void *csf_hm_remove(void*m,const char*k){(void)m;(void)k;csf_remove_calls++;return malloc(sizeof(csi_mac_data_t));}
static int8_t csf_hm_put(void*m,char*k,void*d){(void)m;snprintf(csf_put_key,sizeof(csf_put_key),"%s",k);csf_put_calls++;free(k);free(d);csf_put_data=(void*)1;return 0;}  /* fake map: free what real map would own */
#define hash_map_get(m,k)       csf_hm_get((m),(k))
#define hash_map_get_first(m)   csf_hm_get_first((m))
#define hash_map_get_next(m,e)  csf_hm_get_next((m),(e))
#define hash_map_remove(m,k)    csf_hm_remove((m),(k))
#define hash_map_put(m,k,d)     csf_hm_put((m),(k),(d))
static void wifi_enableCSIEngine(unsigned int ap,unsigned char*mac,int en){(void)ap;(void)mac;(void)en;}
static void update_pinger_config(unsigned int ap,unsigned char*mac,int b){(void)ap;(void)mac;(void)b;}
static char *csf_to_mac_str(unsigned char*mac,char*key){memset(csf_slot_mac,0,CSF_MAC_SZ);snprintf(csf_slot_mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);memcpy(key,csf_slot_mac,CSF_MAC_SZ);return key;}
#define to_mac_str(m,k)  csf_to_mac_str((m),(k))

/* --- copied verbatim from source/apps/csi/wifi_csi.c --- */
int csi_start_fn(void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    mac_addr_str_t mac_str = { 0 };
    mac_addr_str_t evicted_mac_str = { 0 };
    csi_mac_data_t *to_hash_map = NULL;
    char *map_key = NULL;
    bool enable_sounding = false;
    assoc_dev_data_t *assoc_dev_data = NULL;
    mac_addr_t link_addr = { 0 };
    rdk_wifi_vap_info_t *rdk_vap_info = get_wifidb_rdk_vap_info(ap_index);
    const size_t mac_size = sizeof(mac_addr_t);
    bool is_mlo = false;

    wifi_app_t *app = (wifi_app_t *)csi_app;
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }
    wifi_util_dbg_print(WIFI_APPS,
        "%s:%d start ap:%u app:%d mac:%02x..%02x\n",
        __func__, __LINE__, ap_index, sounding_app, mac_addr[0], mac_addr[5]);

    if (app->data.u.csi.csi_sounding_mac_map ==  NULL){
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Hash Map\n", __func__, __LINE__);
        return -1;
    }

    to_mac_str((unsigned char *)mac_addr, mac_str);

    pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
    if (rdk_vap_info->associated_devices_map != NULL) {
        assoc_dev_data = hash_map_get(rdk_vap_info->associated_devices_map, mac_str);

        if (assoc_dev_data != NULL && assoc_dev_data->dev_stats.cli_MLDEnable == true &&
            assoc_dev_data->association_link == true) {
            // Save it under link_mac as key, as CSI engine returns link
            // mac addresses
            memcpy(link_addr, assoc_dev_data->link_address, mac_size);
            to_mac_str((unsigned char *)link_addr, mac_str);
            is_mlo = true;
        }
    }
    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);

    pthread_mutex_lock(&g_csi_map_lock);
    to_hash_map = hash_map_get(app->data.u.csi.csi_sounding_mac_map, mac_str);
    if (to_hash_map != NULL) {
        if (to_hash_map->subscribed_apps & sounding_app) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Request from same APP not sounding\n", __func__, __LINE__);
            pthread_mutex_unlock(&g_csi_map_lock);
            return 0;
        } else {
            to_hash_map->subscribed_apps |= sounding_app;
        }
    } else {
        if (app->data.u.csi.num_current_sounding >= MAX_NUM_CSI_SOUNDING) {
            //Check if the requesting app is motion.
            if (sounding_app == wifi_app_inst_motion) {
                //Check if there are any slots available from low priority apps.
                to_hash_map = (csi_mac_data_t *)hash_map_get_first(app->data.u.csi.csi_sounding_mac_map);
                while(to_hash_map != NULL) {
                    if ((to_hash_map->subscribed_apps & ~wifi_app_inst_motion)){
                        wifi_util_info_print(WIFI_APPS, "%s:%d Disabling CSI for mac %02x..%02x\n", __func__, __LINE__, to_hash_map->mac_addr[0], to_hash_map->mac_addr[5]);
                        if (to_hash_map->is_mlo) {
                            to_mac_str((unsigned char *)to_hash_map->link_addr, evicted_mac_str);
                        } else {
                            to_mac_str((unsigned char *)to_hash_map->mac_addr, evicted_mac_str);
                        }
                        wifi_enableCSIEngine(to_hash_map->ap_index, to_hash_map->mac_addr, FALSE);
                        update_pinger_config(to_hash_map->ap_index, to_hash_map->mac_addr, true);
                        to_hash_map = (csi_mac_data_t *)hash_map_remove(app->data.u.csi.csi_sounding_mac_map, evicted_mac_str);
                        if (to_hash_map != NULL) {
                            free(to_hash_map);
                            if (app->data.u.csi.num_current_sounding > 0) {
                                app->data.u.csi.num_current_sounding--;
                            }
                            enable_sounding = true;
                        } else {
                            wifi_util_error_print(WIFI_APPS, "%s:%d CSI eviction remove failed for mac %s\n",
                                __func__, __LINE__, evicted_mac_str);
                        }
                        break;
                    }
                    to_hash_map = hash_map_get_next(app->data.u.csi.csi_sounding_mac_map, to_hash_map);
                }
            } else {
                //Ignore request for Low priority apps.
                wifi_util_info_print(WIFI_APPS, "%s:%d Not Enabling for Low priority Apps", __func__, __LINE__);
                pthread_mutex_unlock(&g_csi_map_lock);
                return -1;
            }
        } else {
            enable_sounding = true;
        }

        if (enable_sounding) {
            to_hash_map = (csi_mac_data_t *)malloc(sizeof(csi_mac_data_t));
            if (to_hash_map == NULL) {
                wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
                pthread_mutex_unlock(&g_csi_map_lock);
                return -1;
            }
            wifi_util_info_print(WIFI_APPS, "%s:%d Enabling CSI\n", __func__, __LINE__);
            memset(to_hash_map, 0, sizeof(csi_mac_data_t));
            to_hash_map->ap_index = ap_index;
            memcpy(to_hash_map->mac_addr, mac_addr, mac_size);
            memcpy(to_hash_map->link_addr, link_addr, mac_size);
            to_hash_map->is_mlo = is_mlo;
            to_hash_map->subscribed_apps |= sounding_app;
            wifi_util_info_print(WIFI_APPS, "%s:%d Enabling CSI for mac %02x..%02x\n", __func__, __LINE__, to_hash_map->mac_addr[0], to_hash_map->mac_addr[5]);
            wifi_enableCSIEngine(ap_index, (unsigned char *)mac_addr, TRUE);
            map_key = strdup(mac_str);
            if (map_key == NULL) {
                wifi_util_error_print(WIFI_APPS, "%s:%d CSI map key allocation failed for mac %s\n",
                    __func__, __LINE__, mac_str);
                wifi_enableCSIEngine(ap_index, (unsigned char *)mac_addr, FALSE);
                free(to_hash_map);
                pthread_mutex_unlock(&g_csi_map_lock);
                update_pinger_config(ap_index, mac_addr, true);
                return -1;
            }
            if (hash_map_put(app->data.u.csi.csi_sounding_mac_map, map_key, to_hash_map) != 0) {
                wifi_util_error_print(WIFI_APPS, "%s:%d CSI map insert failed for mac %s\n",
                    __func__, __LINE__, mac_str);
                wifi_enableCSIEngine(ap_index, (unsigned char *)mac_addr, FALSE);
                pthread_mutex_unlock(&g_csi_map_lock);
                update_pinger_config(ap_index, mac_addr, true);
                return -1;
            }
            app->data.u.csi.num_current_sounding++;
            pthread_mutex_unlock(&g_csi_map_lock);
            update_pinger_config(ap_index, mac_addr, false);
            return 0;
        } else {
            wifi_util_info_print(WIFI_APPS, "%s:%d Slots are FULL Not sounding\n", __func__, __LINE__);
        }
    }
    pthread_mutex_unlock(&g_csi_map_lock);
    return 0;
}
