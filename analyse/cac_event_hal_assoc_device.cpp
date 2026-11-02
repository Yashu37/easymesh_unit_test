/*
 * HANDLER: cac_event_hal_assoc_device
 *
 * Function from OneWifi source/apps/cac/wifi_cac.c with ONE FIX.
 * Local arrays: vap_name[32] (convert_vap_index_to_name), client_mac[32]
 * (to_mac_str + str_tolower), temp_str[64] (snprintf) -- all bounded.
 * FIX APPLIED: sta_info = malloc(...) now has a NULL check (if NULL return
 * RETURN_OK); previously it was dereferenced unchecked (NULL deref on OOM).
 *
 * Redirects: to_mac_str()->cad slot(32); snprintf()->cad slot(64); malloc()->
 * runner pool. The RUNNER poisons client_mac slot past 32, temp_str slot past
 * 64, each pool entry past sizeof(cac_associated_devices_t), and the caller
 * arg / apps past their sizes. Internal arrays are ASan-stack guarded.
 *
 * Scaffolding (NOT the function under test): is_vap_hotspot, get_wifimgr_obj,
 * convert_vap_index_to_name, wifidb_get_postassoc_ctrl_config, cac_print,
 * hash_map_get/put are file-local stubs; str_tolower verbatim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "common.h"

#define WIFI_APPS 0
#define RETURN_OK 0
#define NL_OK 0
typedef struct { char rssi_up_threshold[129]; char snr_threshold[129]; char cu_threshold[129]; char sampling_count[129]; char sampling_interval[129]; } wifi_postassoc_control_t;

static void cad_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_info_print  cad_print
#define wifi_util_error_print cad_print
static wifi_mgr_t *get_wifimgr_obj(void){return (wifi_mgr_t*)cad_mgr_buf;}
static int is_vap_hotspot(void*p,int ap){(void)p;(void)ap;return cad_is_hotspot;}
static int convert_vap_index_to_name(void*p,unsigned int idx,char*name){(void)p;if(cad_vap_fail)return -1;snprintf(name,32,"vap%u",idx);return RETURN_OK;}
static int wifidb_get_postassoc_ctrl_config(char*v,wifi_postassoc_control_t*c){(void)v;if(cad_cfg_fail)return -1;snprintf(c->sampling_interval,129,"1");snprintf(c->sampling_count,129,"5");return RETURN_OK;}
static char *str_tolower(char *str){unsigned char*s=(unsigned char*)str;while(s&&*s){*s=(unsigned char)tolower(*s);s++;}return str;}
static void cac_print(const char*f,...){(void)f;}
static void *cad_hm_get(void*m,const char*k){(void)m;snprintf(cad_key_seen,sizeof(cad_key_seen),"%s",k);return (cad_existing&&!strcmp(k,cad_existing_key))?cad_existing:NULL;}
static int8_t cad_hm_put(void*m,char*k,void*d){(void)m;snprintf(cad_put_key,sizeof(cad_put_key),"%s",k);cad_put_data=d;free(k);return 0;}
static void *cad_malloc(size_t sz){if(cad_malloc_fail||sz!=sizeof(cac_associated_devices_t)||cad_pool_used>=CAD_POOL)return NULL;return cad_pool[cad_pool_used++];}
#define hash_map_get(m,k)  cad_hm_get((m),(k))
#define hash_map_put(m,k,d) cad_hm_put((m),(k),(d))
#define malloc(s) cad_malloc(s)
static char *cad_to_mac_str(mac_address_t mac,char*key){memset(cad_slot_mac,0,CAD_MAC_SZ);snprintf(cad_slot_mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);memcpy(key,cad_slot_mac,CAD_MAC_SZ);return key;}
static int cad_snprintf(char*out,size_t sz,const char*fmt,...){int r;va_list ap;if(sz>CAD_TMP_SZ)sz=CAD_TMP_SZ;memset(cad_slot_tmp,0,sz);va_start(ap,fmt);r=vsnprintf(cad_slot_tmp,sz,fmt,ap);va_end(ap);memcpy(out,cad_slot_tmp,sz);cad_tmp_len=strnlen(cad_slot_tmp,sz);return r;}
#define to_mac_str(m,k)  cad_to_mac_str((m),(k))
#define snprintf(o,n,...) cad_snprintf((o),(n),__VA_ARGS__)

/* --- copied verbatim from source/apps/cac/wifi_cac.c --- */
int cac_event_hal_assoc_device(wifi_app_t *apps, void *arg)
{
    int ret = 0;
    char vap_name[32];
    char client_mac[32];
    char temp_str[64];
    hash_map_t           *sta_map;
    cac_associated_devices_t *sta_info;
    wifi_postassoc_control_t wifidb_postassoc_conf = { 0 };
    int sampling_interval_conf, sampling_count_conf;

    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    if (!is_vap_hotspot(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, assoc_data->ap_index)) {
        wifi_util_info_print(WIFI_APPS, "%s:%d cac postassoc is used for hotspot vap, ap_index = :%d \n", __func__, __LINE__, assoc_data->ap_index);
        return RETURN_OK;
    }

    ret = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, assoc_data->ap_index, vap_name);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d wrong ap index:%d \n", __func__, __LINE__, assoc_data->ap_index);
        return NL_OK; 
    }

    ret = wifidb_get_postassoc_ctrl_config(vap_name, &wifidb_postassoc_conf);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d config not found for ap index:%d \n", __func__, __LINE__, assoc_data->ap_index);
        return NL_OK;
    }

    sampling_interval_conf = atoi(wifidb_postassoc_conf.sampling_interval);
    sampling_count_conf = atoi(wifidb_postassoc_conf.sampling_count);

    to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);

    str_tolower(client_mac);

    snprintf(temp_str, sizeof(temp_str), "\"%s\" vap index:%d", client_mac, (assoc_data->ap_index + 1));

    cac_print("%s:%d connected %s\n", __func__, __LINE__, temp_str);

    sta_map = apps->data.u.cac.sta_map;

    if ((sta_info = (cac_associated_devices_t *)hash_map_get(sta_map, client_mac)) == NULL) {
        sta_info = malloc(sizeof(cac_associated_devices_t));
        if (sta_info == NULL) return RETURN_OK;   /* FIX: malloc result was used unchecked */
        sta_info->ap_index = assoc_data->ap_index;
        sta_info->sampling_count = sampling_count_conf;
        sta_info->sampling_interval = sampling_interval_conf;
        sta_info->rssi_avg = assoc_data->dev_stats.cli_RSSI;
        sta_info->snr_avg = assoc_data->dev_stats.cli_SNR;
        sta_info->uplink_rate_avg = assoc_data->dev_stats.cli_LastDataUplinkRate;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
        hash_map_put(sta_map, strdup(client_mac), sta_info);
    } else {
        sta_info->ap_index = assoc_data->ap_index;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
    }

    return RETURN_OK;
}
