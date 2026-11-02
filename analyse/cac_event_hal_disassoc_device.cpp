/*
 * HANDLER: cac_event_hal_disassoc_device
 *
 * Function copied VERBATIM from OneWifi source/apps/cac/wifi_cac.c. No fixes.
 * Local arrays: client_mac[32] (to_mac_str + str_tolower), temp_str[64]
 * (snprintf) -- both bounded. Looks the station up and removes/frees it.
 *
 * Redirects: to_mac_str()->cdd slot(32); snprintf()->cdd slot(64). The RUNNER
 * poisons client_mac slot past 32, temp_str slot past 64, and the caller arg
 * (assoc_dev_data_t) / apps past their sizes. Internal arrays are ASan-stack
 * guarded. hash_map_remove returns malloc'd memory so the handler's free() is
 * valid.
 *
 * Scaffolding (NOT the function under test): str_tolower verbatim; cac_print,
 * hash_map_get/remove are file-local stubs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "common.h"

#define WIFI_APPS 0
#define RETURN_OK 0

static char *str_tolower(char *str){unsigned char*s=(unsigned char*)str;while(s&&*s){*s=(unsigned char)tolower(*s);s++;}return str;}
static void cac_print(const char*f,...){(void)f;}
static void *cdd_hm_get(void*m,const char*k){(void)m;snprintf(cdd_key_seen,sizeof(cdd_key_seen),"%s",k);return (cdd_existing&&!strcmp(k,cdd_existing_key))?(void*)0x1:NULL;}
static void *cdd_hm_remove(void*m,const char*k){(void)m;(void)k;cdd_remove_calls++;return malloc(sizeof(cac_associated_devices_t));}
#define hash_map_get(m,k)     cdd_hm_get((m),(k))
#define hash_map_remove(m,k)  cdd_hm_remove((m),(k))
static char *cdd_to_mac_str(mac_address_t mac,char*key){memset(cdd_slot_mac,0,CDD_MAC_SZ);snprintf(cdd_slot_mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);memcpy(key,cdd_slot_mac,CDD_MAC_SZ);return key;}
static int cdd_snprintf(char*out,size_t sz,const char*fmt,...){int r;va_list ap;if(sz>CDD_TMP_SZ)sz=CDD_TMP_SZ;memset(cdd_slot_tmp,0,sz);va_start(ap,fmt);r=vsnprintf(cdd_slot_tmp,sz,fmt,ap);va_end(ap);memcpy(out,cdd_slot_tmp,sz);cdd_tmp_len=strnlen(cdd_slot_tmp,sz);return r;}
#define to_mac_str(m,k)  cdd_to_mac_str((m),(k))
#define snprintf(o,n,...) cdd_snprintf((o),(n),__VA_ARGS__)

/* --- copied verbatim from source/apps/cac/wifi_cac.c --- */
int cac_event_hal_disassoc_device(wifi_app_t *apps, void *arg)
{
    char client_mac[32];
    char temp_str[64];
    hash_map_t            *sta_map;
    cac_associated_devices_t  *sta_info;
    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    sta_map = apps->data.u.cac.sta_map;

    (char *)to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
    str_tolower(client_mac);
    snprintf(temp_str, sizeof(temp_str), "\"%s\" vap index:%d reason:%d", client_mac, (assoc_data->ap_index + 1), assoc_data->reason);
    cac_print("%s:%d disconnected %s\n", __func__, __LINE__, temp_str);

    sta_info = (cac_associated_devices_t *)hash_map_get(sta_map, client_mac);
    if (sta_info != NULL) {
        sta_info = hash_map_remove(sta_map, client_mac);
        if (sta_info != NULL) {
            free(sta_info);
        }
    }

    return RETURN_OK;
}
