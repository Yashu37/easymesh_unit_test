/*
 * HANDLER: hal_ipc_init
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/server_hal_ipc.c:150-183 (~/Desktop/G/rdk-wifi-hal).  With RDK_HIN_FIX 0
 * it is the VERBATIM original (reproduces the finding); with RDK_HIN_FIX 1 it carries FIX 1 below.
 *
 * The function registers the HAL IPC notification callbacks and creates the notification client and the sync-call
 * server nodes.  The registration functions it calls are copied VERBATIM from src/wifi_hal.c (wifi_hal_steering_event
 * Register, wifi_hal_BTMQueryRequest_callback_register, wifi_hal_RMBeaconRequestCallbackRegister,
 * get_hal_device_callbacks; the HAL_IPC build, i.e. without the nl80211 steering registration) over a trimmed
 * wifi_device_callbacks_t that keeps the members they touch (steering_event_callback, bcnrpt_callback[MAX_AP_INDEX],
 * btm_callback[MAX_AP_INDEX]) in a runner-owned slab.  MAX_AP_INDEX is 15 (non VAP_REINDEX build, wifi_hal_rdk_framework.h).
 * The four callbacks it registers are static in server_hal_ipc.c and have their own harnesses; here they are stand-ins
 * with the same signatures whose addresses the runner compares.  rdk_create_hal_ipc_node is a recording stub with
 * failure injection (construct file) - the real one starts the listener thread of the sync-call server.  The prints
 * are the real macros over the log sink.  The function under test is renamed hwr_hal_ipc_init.
 */
#include "hwr_hin.h"
#include <stdio.h>

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_HIN_FIX  0

#define HAL_IPC
#define MAX_AP_INDEX 15
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal                 (*hwr_hin_world)
#define hal_ipc_init               hwr_hal_ipc_init
#define rdk_create_hal_ipc_node    hwr_hin_create_node
#define wifi_hal_steering_eventRegister            hwr_hin_steering_eventRegister
#define wifi_hal_BTMQueryRequest_callback_register hwr_hin_BTMQuery_register
#define wifi_hal_RMBeaconRequestCallbackRegister   hwr_hin_RMBeacon_register
#define get_hal_device_callbacks   hwr_hin_get_device_callbacks

hwr_hin_world_t *hwr_hin_world;
wifi_device_callbacks_t *get_hal_device_callbacks();

/* stand-ins for the static callbacks of server_hal_ipc.c (covered by their own harnesses) */
static INT hal_ipc_BTMQueryRequestEvent(UINT apIndex, CHAR *peerMac, wifi_BTMQuery_t *query, UINT inMemSize, wifi_BTMRequest_t *request)
{ (void)apIndex; (void)peerMac; (void)query; (void)inMemSize; (void)request; return 0; }
static INT hal_ipc_BTMResponseEvent(UINT apIndex, CHAR *peerMac, wifi_BTMResponse_t *response)
{ (void)apIndex; (void)peerMac; (void)response; return 0; }
static INT hal_ipc_RMBeaconReportEvent(UINT apIndex, wifi_BeaconReport_t *out_struct, UINT *out_array_size, UCHAR *out_DialogToken)
{ (void)apIndex; (void)out_struct; (void)out_array_size; (void)out_DialogToken; return 0; }
static void hal_ipc_send_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event)
{ (void)steeringgroupIndex; (void)event; }
extern "C" void *hwr_hin_cb_steer(void)  { return (void *)hal_ipc_send_steering_event; }
extern "C" void *hwr_hin_cb_rm(void)     { return (void *)hal_ipc_RMBeaconReportEvent; }
extern "C" void *hwr_hin_cb_btmq(void)   { return (void *)hal_ipc_BTMQueryRequestEvent; }
extern "C" void *hwr_hin_cb_btmr(void)   { return (void *)hal_ipc_BTMResponseEvent; }

/* --- copied verbatim from wifi_hal.c:4696 (registration functions) --- */
INT wifi_hal_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }
    callbacks->steering_event_callback = event_cb;
#ifndef HAL_IPC
    wifi_steering_eventRegister(nl80211_steering_event);
#endif
    return 0;
}
INT wifi_hal_BTMQueryRequest_callback_register(UINT apIndex,
                                            wifi_BTMQueryRequest_callback btmQueryCallback,
                                            wifi_BTMResponse_callback btmResponseCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    callbacks->btm_callback[apIndex].query_callback = btmQueryCallback;
    callbacks->btm_callback[apIndex].response_callback = btmResponseCallback;
    return RETURN_OK;
}
INT wifi_hal_RMBeaconRequestCallbackRegister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    if (NULL != callbacks->bcnrpt_callback[apIndex])
        return RETURN_ERR;

    callbacks->bcnrpt_callback[apIndex] = beaconReportCallback;
    return RETURN_OK;
}
wifi_device_callbacks_t *get_hal_device_callbacks()
{
    return &g_wifi_hal.device_callbacks;
}
/* --- copied from server_hal_ipc.c:150 --- */
extern "C" {
int hal_ipc_init(void)
{
    hal_ipc_node_t *node;
#if RDK_HIN_FIX
    int reg_failed = 0;
#endif

    // Register HAL IPC function as steering event callback
    // in rdk-wifi-hal callbacks struct g_wifi_hal.device_callbacks
#if RDK_HIN_FIX
    /* FIX 1: the results of the three registrations were ignored, so hal_ipc_init() returned 0 (and went on to create the
     * notification / sync-call nodes) although a callback could not be registered - e.g. wifi_hal_RMBeaconRequestCallback
     * Register() returns RETURN_ERR for an AP index that already has a beacon callback (another registrant, or a second
     * call of hal_ipc_init(), which would also start a second sync-call listener).  Remember the failure, still try
     * every registration, and fail before any node is created. */
    if (wifi_hal_steering_eventRegister(hal_ipc_send_steering_event) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Failed to register steering event callback\n", __func__, __LINE__);
        reg_failed = 1;
    }
#else
    wifi_hal_steering_eventRegister(hal_ipc_send_steering_event);
#endif

    // Register HAL IPC function as RM Beacon Report event callback
    // in rdk-wifi-hal callbacks struct g_wifi_hal.device_callbacks
    for (int ap_index = 0; ap_index < MAX_AP_INDEX; ap_index++) {
#if RDK_HIN_FIX
        if (wifi_hal_RMBeaconRequestCallbackRegister(ap_index, hal_ipc_RMBeaconReportEvent) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Failed to register RM beacon report callback for ap %d\n", __func__, __LINE__, ap_index);
            reg_failed = 1;
        }
#else
        wifi_hal_RMBeaconRequestCallbackRegister(ap_index, hal_ipc_RMBeaconReportEvent);
#endif
    }

    // Register HAL IPC function as BTM Query/Request event callback
    // in rdk-wifi-hal callbacks struct g_wifi_hal.device_callbacks
    for (int ap_index = 0; ap_index < MAX_AP_INDEX; ap_index++) {
#if RDK_HIN_FIX
        if (wifi_hal_BTMQueryRequest_callback_register(ap_index, hal_ipc_BTMQueryRequestEvent, hal_ipc_BTMResponseEvent) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Failed to register BTM callbacks for ap %d\n", __func__, __LINE__, ap_index);
            reg_failed = 1;
        }
#else
        wifi_hal_BTMQueryRequest_callback_register( ap_index, 
                                                    hal_ipc_BTMQueryRequestEvent,
                                                    hal_ipc_BTMResponseEvent);
#endif
    }

#if RDK_HIN_FIX
    if (reg_failed) {
        return -1;
    }
#endif
    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_sync_call_server)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create sync call server node\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}
}
