/*
 * HANDLER: apps_reassoc_req_frame_event
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes; the
 * non-CONFIG_IEEE80211BE variant, as compiled for this tree). Local array:
 *   - char namespace[50] : snprintf(namespace, sizeof(namespace),
 *     "Device.WiFi.Events.VAP.%d.Frames.Mgmt", ap_index + 1); at most 46 bytes
 *     + NUL. Bounded -> SAFE.
 *
 * Scaffolding (NOT under test): mgmt_frame_bus_send is a recording stub.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE   "Device.WiFi.Events.VAP.%d.Frames.Mgmt"
/* 'namespace' is a C++ keyword (source is C): rename the identifier only */
#define namespace ns_buf

static void mgmt_frame_bus_send(void *handle, const char *ns, frame_data_t *msg)
{
    (void)handle; (void)msg;
    snprintf(arf_sent_ns, sizeof(arf_sent_ns), "%s", ns);
    arf_send_calls++;
}

/* ================= VERBATIM from wifi_levl.c ================= */
void apps_reassoc_req_frame_event(wifi_app_t *apps, frame_data_t *msg)
{
    char namespace[50];
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi reassoc req mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
    mgmt_frame_bus_send(&apps->handle, namespace, msg);
}
