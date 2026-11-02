/*
 * HANDLER: cac_mgmt_frame_hook
 *
 * Function copied VERBATIM from OneWifi source/apps/cac/wifi_cac.c. No fixes.
 * Only local array is vap_name[32], written by convert_vap_index_to_name
 * (bounded). Returns NL_OK / NL_SKIP based on preassoc config.
 *
 * Redirect: convert_vap_index_to_name writes into a runner slot of the SAME
 * size (32); the RUNNER poisons that slot past 32. vap_name is also ASan
 * stack guarded. (No caller-owned buffer: ap_index is int, type is an enum.)
 *
 * Scaffolding (NOT the function under test): is_vap_hotspot, get_wifimgr_obj,
 * wifidb_get_preassoc_ctrl_config are file-local stubs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

#define WIFI_APPS 0
#define RETURN_OK 0
#define NL_OK 0
#define NL_SKIP 1
typedef enum { WIFI_MGMT_FRAME_TYPE_PROBE_REQ=0, WIFI_MGMT_FRAME_TYPE_ASSOC_REQ=1, WIFI_MGMT_FRAME_TYPE_REASSOC_REQ=2, WIFI_MGMT_FRAME_TYPE_OTHER=99 } wifi_mgmtFrameType_t;
typedef struct { char rssi_up_threshold[129]; char snr_threshold[129]; char cu_threshold[129]; char basic_data_transmit_rates[129]; } wifi_preassoc_control_t;

static void cmh_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_dbg_print  cmh_print
#define wifi_util_info_print cmh_print
static wifi_mgr_t *get_wifimgr_obj(void){return (wifi_mgr_t*)cmh_mgr_buf;}
static int is_vap_hotspot(void*p,int ap){(void)p;(void)ap;return cmh_is_hotspot;}
static int wifidb_get_preassoc_ctrl_config(char*v,wifi_preassoc_control_t*c){(void)v;if(cmh_cfg_fail)return -1;snprintf(c->rssi_up_threshold,129,"%s",cmh_rssi);snprintf(c->snr_threshold,129,"disabled");snprintf(c->cu_threshold,129,"disabled");snprintf(c->basic_data_transmit_rates,129,"%s",cmh_rates);return RETURN_OK;}
static int cmh_cvi2n(void*p,int idx,char*name){(void)p;if(cmh_vap_fail)return -1;memset(cmh_slot_vap,0,CMH_VAP_SZ);snprintf(cmh_slot_vap,CMH_VAP_SZ,"vap%d",idx);memcpy(name,cmh_slot_vap,CMH_VAP_SZ);return RETURN_OK;}
#define convert_vap_index_to_name(p,i,n)  cmh_cvi2n((p),(i),(n))

/* --- copied verbatim from source/apps/cac/wifi_cac.c --- */
int cac_mgmt_frame_hook(int ap_index, wifi_mgmtFrameType_t type)
{
    int ret = 0;
    char vap_name[32];
    wifi_preassoc_control_t wifidb_preassoc_conf = { 0 };

    wifi_util_dbg_print(WIFI_APPS, "%s:%d received mgmt frame hook for ap index:%d type:%d \n", __func__, __LINE__, ap_index, type);

    if (!is_vap_hotspot(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, ap_index)) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d cac frame hook is used for hotspot vap, ap_index = :%d \n", __func__, __LINE__, ap_index);
        return NL_OK;
    }

    if (type != WIFI_MGMT_FRAME_TYPE_PROBE_REQ &&
        type != WIFI_MGMT_FRAME_TYPE_ASSOC_REQ &&
        type != WIFI_MGMT_FRAME_TYPE_REASSOC_REQ) {
        return NL_OK;
    }

    ret = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, ap_index, vap_name);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d wrong ap index:%d \n", __func__, __LINE__, ap_index);
        return NL_OK; 
    }

    ret = wifidb_get_preassoc_ctrl_config(vap_name, &wifidb_preassoc_conf);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d config not found for ap index:%d \n", __func__, __LINE__, ap_index);
        return NL_OK;
    }

    if((type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) && (strlen (wifidb_preassoc_conf.basic_data_transmit_rates) <= 0) && (strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled") == 0)) {
        return NL_OK;
    }

    if ((strcmp(wifidb_preassoc_conf.rssi_up_threshold, "disabled") != 0) ||
         (strcmp(wifidb_preassoc_conf.snr_threshold, "disabled") != 0) ||
         (strcmp(wifidb_preassoc_conf.cu_threshold, "disabled") != 0) ||
         ((strlen (wifidb_preassoc_conf.basic_data_transmit_rates) > 0) && (strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled") != 0))) {
        return NL_SKIP;
    }
    return NL_OK;
}
