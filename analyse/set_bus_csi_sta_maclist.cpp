/*
 * HANDLER: set_bus_csi_sta_maclist
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi_analytics.c.
 * No fixes. Only local array name[BUS_MAX_NAME_LENGTH=128], written by
 * snprintf(name, BUS_MAX_NAME_LENGTH, CSI_CLIENT_MACLIST, csi_session_index)
 * -- bounded. Then bus_set_string_fn(bus_handle, name, csi_info->sta_mac).
 *
 * Redirect: snprintf()->sbm slot(128); the RUNNER poisons that slot past 128
 * and the caller csi_info / bus_handle past their sizes. name is ASan-stack
 * guarded.
 *
 * Scaffolding (NOT the function under test): get_bus_descriptor + the
 * bus_set_string_fn are file-local stubs; csi_analytics_info_t is shared.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

#define WIFI_APPS 0
#define RETURN_ERR -1
#define BUS_MAX_NAME_LENGTH 128
#define CSI_CLIENT_MACLIST "Device.WiFi.X_RDK_CSI.%d.ClientMaclist"
typedef enum { bus_error_success = 0, bus_error_general = 1 } bus_error_t;
typedef struct { bus_error_t (*bus_set_string_fn)(bus_handle_t*, char*, char*); } wifi_bus_desc_t;

static void sbm_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_error_print sbm_print
#define wifi_util_info_print  sbm_print
static bus_error_t sbm_set_str(bus_handle_t*h,char*name,char*val){(void)h;snprintf(sbm_name_seen,sizeof(sbm_name_seen),"%s",name);snprintf(sbm_val_seen,sizeof(sbm_val_seen),"%s",val);sbm_set_calls++;return sbm_fail?bus_error_general:bus_error_success;}
static wifi_bus_desc_t sbm_desc = { sbm_set_str };
static wifi_bus_desc_t *get_bus_descriptor(void){return &sbm_desc;}
static int sbm_snprintf(char*out,size_t sz,const char*fmt,...){int r;va_list ap;if(sz>SBM_NAME_SZ)sz=SBM_NAME_SZ;memset(sbm_slot,0,sz);va_start(ap,fmt);r=vsnprintf(sbm_slot,sz,fmt,ap);va_end(ap);memcpy(out,sbm_slot,sz);sbm_name_len=strnlen(sbm_slot,sz);return r;}
#define snprintf(o,n,...) sbm_snprintf((o),(n),__VA_ARGS__)

/* --- copied verbatim from source/apps/csi/wifi_csi_analytics.c --- */
int set_bus_csi_sta_maclist(bus_handle_t *bus_handle, csi_analytics_info_t *csi_info)
{
    char name[BUS_MAX_NAME_LENGTH] = { 0 };
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc = bus_error_success;

    snprintf(name, BUS_MAX_NAME_LENGTH, CSI_CLIENT_MACLIST, csi_info->csi_session_index);

    rc = bus_desc->bus_set_string_fn(bus_handle, name, csi_info->sta_mac);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: bus:%s bus set string:%s Failed %d\n", __func__,
            __LINE__, name, csi_info->sta_mac, rc);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d: bus:%s bus set string:%s success\n", __func__,
            __LINE__, name, csi_info->sta_mac);
    }

    return rc;
}
