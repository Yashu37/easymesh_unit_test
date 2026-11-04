/*
 * HANDLER: ipc_client_notification_input
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_processors.c:1149-1281
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_CNI_FIX 0 it is the VERBATIM original (reproduces the findings);
 * with RDK_CNI_FIX 1 it carries FIX 1..3 below.
 *
 * Scaffolding only (same approach as ipc_server_output): compiled as C (the original jumps across
 * initialisations in the switch), REAL wifi_hal.h + the REAL hal_ipc.h descriptor definitions via
 * hso_hal_ipc.h; malloc / free go to counting stubs; wifi_hal_*_print are the real macros over a log sink.
 */
#include "hso_hal_ipc.h"

/* 1 = with FIX 1..3, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_CNI_FIX  1

#define wifi_hal_dbg_print(format, ...)    hcn_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)   hcn_print(1, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hcn_print(2, format, ##__VA_ARGS__)
void hcn_print(int level, const char *format, ...) __attribute__((format(printf, 2, 3)));
void *hcn_malloc(size_t n);
void  hcn_free(void *p);
#define malloc  hcn_malloc
#define free    hcn_free

//--------------------------------------------------------------------------------------------------
int ipc_client_notification_input(struct hal_ipc_processor_desc *desc,
                                  void *arg1,
                                  void *arg2,
                                  void *arg3,
                                  void *arg4,
                                  void *arg5)
{
#if RDK_CNI_FIX
    /* FIX 3: desc was dereferenced unchecked. */
    if (desc == NULL) {
        return -1;
    }
#endif
    wifi_hal_dbg_print("%s:%d Enter: client notification input %s\n", __func__, __LINE__, desc->name);
    switch (desc->type) {
        case hal_ipc_desc_type_steering_event:
            if (!arg1 || !arg2) {
                wifi_hal_dbg_print("%s:%d function %s require 2 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.steering_event_data.steering_group_index = *(unsigned int*) arg1;
            if (!memcpy((unsigned char*) &desc->in.steering_event_data.evt,
                       (unsigned char*) arg2,
                       sizeof(wifi_steering_event_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_steering_event_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->len = sizeof(hal_ipc_processor_desc_t);
            break;

        case hal_ipc_desc_type_mgmt_frame_event:

            break;

        case hal_ipc_rm_beacon_report_event:
            if (!arg1 || !arg2 || !arg3 || !arg4) {
                wifi_hal_dbg_print("%s:%d function %s require 4 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            
            desc->in.rm_beacon_report_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.rm_beacon_report_event_data.apIndex);

            desc->scratch_buf = (unsigned char*) malloc(sizeof(wifi_BeaconReport_t));
            if (!desc->scratch_buf) {
                wifi_hal_dbg_print("%s:%d FAIL desc->scratch_buf malloc %s for wifi_BeaconReport_t\n", __func__, __LINE__, desc->name);
                return -1;
            }

            if (!memcpy((unsigned char*) desc->scratch_buf,
                        (unsigned char*) arg2,
                        sizeof(wifi_BeaconReport_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BeaconReport_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }

            desc->in.rm_beacon_report_event_data.out_array_size = *(unsigned int*) arg3;
            desc->in.rm_beacon_report_event_data.out_DialogToken = *(unsigned char*) arg4;

            desc->scratch_buf_size = sizeof(wifi_BeaconReport_t);
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            break;

        case hal_ipc_btm_query_request_event:
#if RDK_CNI_FIX
            /* FIX 1: arg5 (the wifi_BTMRequest_t) is copied below but was the one argument not checked. */
            if (!arg1 || !arg2 || !arg3 || !arg4 || !arg5) {
#else
            if (!arg1 || !arg2 || !arg3 || !arg4) {
#endif
                wifi_hal_dbg_print("%s:%d function %s require 4 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.btm_query_request_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.btm_query_request_event_data.apIndex);
            if (!memcpy((unsigned char*) &desc->in.btm_query_request_event_data.peerMac,
                        (unsigned char*) arg2,
                        sizeof(mac_address_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s mac_address_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.btm_query_request_event_data.inMemSize = *(unsigned int*) arg4;
            
            desc->scratch_buf = (unsigned char*) malloc(sizeof(wifi_BTMQuery_t) + sizeof(wifi_BTMRequest_t));
            if (!desc->scratch_buf) {
                wifi_hal_dbg_print("%s:%d FAIL desc->scratch_buf malloc %s for wifi_BTMQuery_t and wifi_BTMRequest_t\n", __func__, __LINE__, desc->name);
                return -1;
            }

            if (!memcpy((unsigned char*) desc->scratch_buf,
                        (unsigned char*) arg3,
                        sizeof(wifi_BTMQuery_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }

            if (!memcpy((unsigned char*) (desc->scratch_buf + sizeof(wifi_BTMQuery_t)),
                        (unsigned char*) arg5,
                        sizeof(wifi_BTMRequest_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }
            desc->scratch_buf_size = sizeof(wifi_BTMQuery_t) + sizeof(wifi_BTMRequest_t);
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;

            break;

        case hal_ipc_btm_response_event:
            if (!arg1 || !arg2 || !arg3) {
                wifi_hal_dbg_print("%s:%d function %s require 3 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            mac_address_t sta_mac;
            memset(sta_mac, 0, sizeof(mac_address_t));
#if RDK_CNI_FIX
            /* FIX 2: arg2 is a "xx:xx:xx:xx:xx:xx" string from the caller: read at most 17 characters (it was
             * passed to %s and sscanf unbounded), reject a string that does not parse into 6 bytes instead of
             * silently sending a zero MAC, and set desc->len (the server asserts len == sizeof(desc) + scratch). */
            char mac_str[18];
            size_t mac_len = strnlen((const char *)arg2, sizeof(mac_str) - 1);
            memcpy(mac_str, arg2, mac_len);
            mac_str[mac_len] = 0;
            desc->len = sizeof(hal_ipc_processor_desc_t);
#endif

            desc->in.btm_response_event_data.apIndex = *(unsigned int*) arg1;
#if RDK_CNI_FIX
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d peer_mac:%s\n", __func__, __LINE__, desc->name,
                                    desc->in.btm_response_event_data.apIndex, mac_str);
            if (sscanf(mac_str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &sta_mac[0], &sta_mac[1], &sta_mac[2],&sta_mac[3], &sta_mac[4], &sta_mac[5]) != 6) {
                wifi_hal_dbg_print("%s:%d FAIL %s invalid peer mac string\n", __func__, __LINE__, desc->name);
                return -1;
            }
#else
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d peer_mac:%s\n", __func__, __LINE__, desc->name,
                                    desc->in.btm_response_event_data.apIndex, (char *)arg2);
            sscanf((char *)arg2, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &sta_mac[0], &sta_mac[1], &sta_mac[2],&sta_mac[3], &sta_mac[4], &sta_mac[5]);
#endif

            if (!memcpy((unsigned char*) &desc->in.btm_response_event_data.peerMac,
                        (unsigned char*) sta_mac,
                        sizeof(mac_address_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s mac_address_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            if (!memcpy((unsigned char*) &desc->in.btm_response_event_data.response,
                        (unsigned char*) arg3,
                        sizeof(wifi_BTMResponse_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            break;

        default:
            wifi_hal_dbg_print("%s:%d RFC API %s reached default.\n", __func__, __LINE__, desc->name);
            return -1;
            break;
    }
    return 0;
}

int ipc_client_notification_input_entry(struct hal_ipc_processor_desc *desc, void *a1, void *a2, void *a3, void *a4, void *a5)
{ return ipc_client_notification_input(desc, a1, a2, a3, a4, a5); }
