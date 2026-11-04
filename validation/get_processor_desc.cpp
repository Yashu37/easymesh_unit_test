/*
 * HANDLER: get_processor_desc
 *
 * Function copied VERBATIM from rdk-wifi-hal: hal_ipc/server/hal_ipc.c:820
 * (~/Desktop/G/rdk-wifi-hal).  No fixes, no edits.
 *
 * Scaffolding only: the real hal_ipc.h needs the whole hostap/nl80211 header
 * tree, so common.h carries (a) the hal_ipc_desc_type_t enum copied verbatim
 * and (b) a hal_ipc_processor_desc_t with the real leading fields
 * (type, name[128], ipc_processor[5], len, ret) and a pad standing in for
 * the in/out unions.  The processor_desc[] table below has the real
 * hal_ipc_desc_type_max (=41) entries, with the real type/name of each
 * entry taken from hal_ipc.c:36-734 (the callbacks/unions are not needed:
 * get_processor_desc() only takes the address of an element).
 */
#include <stdio.h>
#include <string.h>
#include "common.h"

/* --- table: entry order/names verified against hal_ipc.c:36-734 --- */
hal_ipc_processor_desc_t processor_desc[hal_ipc_desc_type_max] = {
    { hal_ipc_desc_type_set_radio_stats_enable, "wifi_setRadioStatsEnable" },
    { hal_ipc_desc_type_get_ssid_num_of_entries, "wifi_getSSIDNumberOfEntries" },
    { hal_ipc_desc_type_get_ap_assoc_dev_stats, "wifi_getApAssociatedDeviceStats" },
    { hal_ipc_desc_type_get_radio_chan_stats, "wifi_getRadioChannelStats" },
    { hal_ipc_desc_type_start_neighbor_scan, "wifi_startNeighborScan" },
    { hal_ipc_desc_type_get_neighbor_wifi_status, "wifi_getNeighboringWiFiStatus" },
    { hal_ipc_desc_type_get_ssid_traffic_stats2, "wifi_getSSIDTrafficStats2" },
    { hal_ipc_desc_type_get_ap_assoc_dev_rx_stats_result, "wifi_getApAssociatedDeviceRxStatsResult" },
    { hal_ipc_desc_type_get_ssid_enable, "wifi_getSSIDEnable" },
    { hal_ipc_desc_type_get_ssid_radio_index, "wifi_getSSIDRadioIndex" },
    { hal_ipc_desc_type_get_ssid_name_status, "wifi_getSSIDNameStatus" },
    { hal_ipc_desc_type_get_ap_name, "wifi_getApName" },
    { hal_ipc_desc_type_get_neighbor_report_activation, "wifi_getNeighborReportActivation" },
    { hal_ipc_desc_type_get_bss_transition_activation, "wifi_getBSSTransitionActivation" },
    { hal_ipc_desc_type_get_ap_assoc_dev_diag_result3, "wifi_getApAssociatedDeviceDiagnosticResult3" },
    { hal_ipc_desc_type_get_ap_assoc_client_diag_result, "wifi_getApAssociatedClientDiagnosticResult" },
    { hal_ipc_desc_type_get_radio_operating_freq_band, "wifi_getRadioOperatingFrequencyBand" },
    { hal_ipc_desc_type_get_radio_num_of_entries, "wifi_getRadioNumberOfEntries" },
    { hal_ipc_desc_type_get_ap_assoc_dev_tx_stats_result, "wifi_getApAssociatedDeviceTxStatsResult" },
    { hal_ipc_desc_type_steering_set_group, "wifi_steering_setGroup" },
    { hal_ipc_desc_type_steering_client_set, "wifi_steering_clientSet" },
    { hal_ipc_desc_type_steering_client_remove, "wifi_steering_clientRemove" },
    { hal_ipc_desc_type_steering_client_disconnect, "wifi_steering_clientDisconnect" },
    { hal_ipc_desc_type_set_btm_request, "wifi_setBTMRequest" },
    { hal_ipc_desc_type_get_ssid_name, "wifi_getSSIDName" },
    { hal_ipc_desc_type_set_rm_beacon_request, "wifi_setRMBeaconRequest" },
    { hal_ipc_desc_type_get_association_req_ies, "wifi_getAssociationReqIEs" },
    { hal_ipc_desc_type_set_neighbor_reports, "wifi_setNeighborReports" },
    { hal_ipc_desc_type_set_neighbor_report_activation, "wifi_setNeighborReportActivation" },
    { hal_ipc_desc_type_get_radio_if_name, "wifi_getRadioIfName" },
    { hal_ipc_desc_type_get_ap_num_assoc_devs, "wifi_getApNumDevicesAssociated" },
    { hal_ipc_desc_type_steering_unregister, "wifi_steering_eventUnregister" },
    { hal_ipc_desc_type_steering_register, "wifi_steering_eventRegister" },
    { hal_ipc_desc_type_steering_event, "steering event notification" },
    { hal_ipc_desc_type_mgmt_frame_callback_register, "wifi_mgmt_frame_callbacks_register" },
    { hal_ipc_desc_type_mgmt_frame_event, "mgmt frame event notification" },
    { hal_ipc_rm_beacon_request_register, "wifi_RMBeaconRequestCallbackRegister" },
    { hal_ipc_rm_beacon_report_event, "RM beacon report event notification" },
    { hal_ipc_btm_query_request_register, "wifi_BTMQueryRequest_callback_register" },
    { hal_ipc_btm_query_request_event, "BTM query request event notification" },
    { hal_ipc_btm_response_event, "BTM response event notification" },
};

/* --- copied verbatim from hal_ipc.c:820 --- */
hal_ipc_processor_desc_t *get_processor_desc(hal_ipc_desc_type_t type)
{
    return &processor_desc[type];
}
