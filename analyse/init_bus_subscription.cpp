/*
 * HANDLER: init_bus_subscription
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi_analytics.c.
 * No fixes. Local arrays: bus_events[1] (a bus_event_sub_t), and name
 * (bus_name_string_t = char[BUS_MAX_NAME_LENGTH=128]) written by
 * snprintf(name, 128, "...%d", csi_index) -- bounded exactly to the type size.
 *
 * Redirect: snprintf()->ibs slot(128); the RUNNER poisons that slot past 128
 * and the caller bus_handle / p_app past their sizes. name is ASan-stack
 * guarded.
 *
 * Scaffolding (NOT the function under test): the bus desc fns, do_nothing_handler,
 * csi_analytics_bus_subscription, run_csi_enable_timer are file-local stubs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "common.h"

#define WIFI_APPS 0
#define BUS_MAX_NAME_LENGTH 128
#define CSI_SUB_DATA "Device.WiFi.X_RDK_CSI.%d.data"
#define CSI_ANALYTICS_INTERVAL 300
typedef enum { bus_error_success = 0, bus_error_general = 1 } bus_error_t;
typedef char bus_name_string_t[BUS_MAX_NAME_LENGTH];
typedef struct bus_data_prop bus_data_prop_t;
typedef void (*bus_event_sub_ex_async_handler_t)(void);
typedef struct bus_event_sub { char const* event_name; void* filter; uint32_t interval; uint32_t duration; void* handler; void* user_data; void* handle; bus_event_sub_ex_async_handler_t async_handler; bool publish_on_sub; } bus_event_sub_t;
typedef struct { bus_error_t (*bus_open_fn)(bus_handle_t*, char*); bus_error_t (*bus_add_table_row_fn)(bus_handle_t*, const char*, const char*, uint32_t*); bus_error_t (*bus_close_fn)(bus_handle_t*); } wifi_bus_desc_t;

static void ibs_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_error_print ibs_print
#define wifi_util_info_print  ibs_print
static void do_nothing_handler(char*e,bus_data_prop_t*p,void*u){(void)e;(void)p;(void)u;}
static bus_error_t ibs_open(bus_handle_t*h,char*c){(void)h;(void)c;return ibs_open_fail?bus_error_general:bus_error_success;}
static bus_error_t ibs_add_row(bus_handle_t*h,const char*t,const char*a,uint32_t*idx){(void)h;(void)t;(void)a;*idx=ibs_added_index;return ibs_addrow_fail?bus_error_general:bus_error_success;}
static bus_error_t ibs_close(bus_handle_t*h){(void)h;ibs_close_calls++;return bus_error_success;}
static wifi_bus_desc_t ibs_desc = { ibs_open, ibs_add_row, ibs_close };
static wifi_bus_desc_t *get_bus_descriptor(void){return &ibs_desc;}
static bus_error_t csi_analytics_bus_subscription(bus_handle_t*h,bus_event_sub_t*e,uint32_t n){(void)h;(void)n;snprintf(ibs_sub_name,sizeof(ibs_sub_name),"%s",e->event_name);ibs_sub_calls++;return ibs_sub_fail?bus_error_general:bus_error_success;}
static void run_csi_enable_timer(wifi_app_t*a,bool b){(void)a;(void)b;ibs_timer_calls++;}
static int ibs_snprintf(char*out,size_t sz,const char*fmt,...){int r;va_list ap;if(sz>IBS_NAME_SZ)sz=IBS_NAME_SZ;memset(ibs_slot,0,sz);va_start(ap,fmt);r=vsnprintf(ibs_slot,sz,fmt,ap);va_end(ap);memcpy(out,ibs_slot,sz);ibs_name_len=strnlen(ibs_slot,sz);return r;}
#define snprintf(o,n,...) ibs_snprintf((o),(n),__VA_ARGS__)

/* --- copied verbatim from source/apps/csi/wifi_csi_analytics.c --- */
bus_error_t init_bus_subscription(bus_handle_t *bus_handle, wifi_app_t *p_app)
{
    char *component_name = "CsiAnanlytics";
    bus_error_t rc;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    csi_analytics_info_t *p_info = &p_app->data.u.csi_analytics;

    rc = bus_desc->bus_open_fn(bus_handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d bus_open failed: %d\n", __func__, __LINE__, rc);
        return rc;
    }

    if (p_info->csi_session_index == 0) {
        uint32_t csi_index = 0;
        bus_name_string_t name = { 0 };

        rc = bus_desc->bus_add_table_row_fn(bus_handle, "Device.WiFi.X_RDK_CSI.", NULL, &csi_index);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Failed to add CSI\n", __func__, __LINE__);
            rc = bus_desc->bus_close_fn(bus_handle);
            if (rc != bus_error_success) {
                wifi_util_error_print(WIFI_APPS,
                    "%s:%d: Unable to close"
                    " bus handle\n",
                    __func__, __LINE__);
            }
            return rc;
        }
        wifi_util_info_print(WIFI_APPS, "%s:%d CSI session:%d added\n", __func__, __LINE__,
            csi_index);

        bus_event_sub_t bus_events[] = {
            /* Event Name, filter, interval, duration, handler, user data, handle */
            { CSI_SUB_DATA, NULL, CSI_ANALYTICS_INTERVAL, 0, do_nothing_handler, NULL, NULL, NULL,
             false }
        };

        snprintf(name, BUS_MAX_NAME_LENGTH, bus_events[0].event_name, csi_index);
        bus_events[0].event_name = (char const *)name;
        rc = csi_analytics_bus_subscription(bus_handle, &bus_events[0], 1);
        if (rc != bus_error_success) {
            return rc;
        }

        p_info->csi_session_index = csi_index;
        run_csi_enable_timer(p_app, true);
    }

    return rc;
}
