/*
 * HANDLER: set_bus_csi_sub_enable_status
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi_analytics.c.
 * No fixes. Only local array name[BUS_MAX_NAME_LENGTH=128], written by
 * snprintf(name, 128, CSI_ENABLE_NAME, csi_session_index) -- bounded. Then
 * bus_set_fn(bus_handle, name, &data).
 *
 * Redirect: snprintf()->ses slot(128); the RUNNER poisons that slot past 128
 * and the caller bus_handle past 16. name is ASan-stack guarded.
 *
 * Scaffolding (NOT the function under test): get_bus_descriptor + bus_set_fn
 * are file-local stubs; raw_data_t is a local subset.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "common.h"

#define WIFI_APPS 0
#define BUS_MAX_NAME_LENGTH 128
#define CSI_ENABLE_NAME "Device.WiFi.X_RDK_CSI.%d.Enable"
typedef enum { bus_error_success = 0, bus_error_general = 1 } bus_error_t;
typedef enum { bus_data_type_boolean = 0x500 } bus_data_type_t;
typedef union { bool b; unsigned int u32; void *bytes; } raw_data_format_t;
typedef struct raw_data { bus_data_type_t data_type; raw_data_format_t raw_data; unsigned int raw_data_len; } raw_data_t;
typedef struct { bus_error_t (*bus_set_fn)(bus_handle_t*, char*, raw_data_t*); } wifi_bus_desc_t;

static void ses_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_error_print ses_print
#define wifi_util_info_print  ses_print
static bus_error_t ses_set(bus_handle_t*h,char*name,raw_data_t*d){(void)h;snprintf(ses_name_seen,sizeof(ses_name_seen),"%s",name);ses_last_bool=d->raw_data.b;ses_set_calls++;return ses_fail?bus_error_general:bus_error_success;}
static wifi_bus_desc_t ses_desc = { ses_set };
static wifi_bus_desc_t *get_bus_descriptor(void){return &ses_desc;}
static int ses_snprintf(char*out,size_t sz,const char*fmt,...){int r;va_list ap;if(sz>SES_NAME_SZ)sz=SES_NAME_SZ;memset(ses_slot,0,sz);va_start(ap,fmt);r=vsnprintf(ses_slot,sz,fmt,ap);va_end(ap);memcpy(out,ses_slot,sz);ses_name_len=strnlen(ses_slot,sz);return r;}
#define snprintf(o,n,...) ses_snprintf((o),(n),__VA_ARGS__)

/* --- copied verbatim from source/apps/csi/wifi_csi_analytics.c --- */
bus_error_t set_bus_csi_sub_enable_status(bus_handle_t *bus_handle, uint32_t csi_session_index,
    bool status)
{
    raw_data_t data;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc = bus_error_success;
    char name[BUS_MAX_NAME_LENGTH] = { 0 };

    memset(&data, 0, sizeof(raw_data_t));
    data.data_type = bus_data_type_boolean;
    data.raw_data.b = status;
    data.raw_data_len = sizeof(status);

    snprintf(name, BUS_MAX_NAME_LENGTH, CSI_ENABLE_NAME, csi_session_index);

    rc = bus_desc->bus_set_fn(bus_handle, name, &data);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "bus: bus_set_fn error:%d name:%s value:%d\n", rc, name,
            status);
    } else {
        wifi_util_info_print(WIFI_APPS, "bus: set csi enable for %s state:%d\n", name, status);
    }
    return rc;
}
