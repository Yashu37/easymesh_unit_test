/*
 * UNIT TEST (input constructor): construct_get_processor_desc
 *
 * get_processor_desc() takes ONE parameter, the descriptor type, and returns
 * &processor_desc[type] with no range check.  The input space is the type
 * value: every valid enum value (0 .. hal_ipc_desc_type_max-1) and a set of
 * invalid / edge values (negative, == max, > max, huge, INT_MIN/INT_MAX),
 * each checked several ways:
 *   valid   : returned pointer == &table[t]; name matches the real table
 *             entry; desc->type == t; pointer lies inside the table;
 *             adjacent entries are exactly sizeof(desc) apart.
 *   invalid : returns NULL; contract check "NULL or inside the table"; and a
 *             dereference (when non-NULL), which must not crash (run in-process
 *             and last, so without FIX 1 the run aborts with the ASan report).  Before FIX 1 every invalid case failed (no bounds check
 *             on `type`, pointer outside processor_desc[], ASan
 *             global-buffer-overflow on use); with FIX 1 all pass.
 * Expected result is the SAFE contract (1 = ok), so a FAIL is a finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "common.h"

char gpd_name_buf[GPD_NAME_SZ];

const char *gpd_expected_names[] = {
	"wifi_setRadioStatsEnable",
	"wifi_getSSIDNumberOfEntries",
	"wifi_getApAssociatedDeviceStats",
	"wifi_getRadioChannelStats",
	"wifi_startNeighborScan",
	"wifi_getNeighboringWiFiStatus",
	"wifi_getSSIDTrafficStats2",
	"wifi_getApAssociatedDeviceRxStatsResult",
	"wifi_getSSIDEnable",
	"wifi_getSSIDRadioIndex",
	"wifi_getSSIDNameStatus",
	"wifi_getApName",
	"wifi_getNeighborReportActivation",
	"wifi_getBSSTransitionActivation",
	"wifi_getApAssociatedDeviceDiagnosticResult3",
	"wifi_getApAssociatedClientDiagnosticResult",
	"wifi_getRadioOperatingFrequencyBand",
	"wifi_getRadioNumberOfEntries",
	"wifi_getApAssociatedDeviceTxStatsResult",
	"wifi_steering_setGroup",
	"wifi_steering_clientSet",
	"wifi_steering_clientRemove",
	"wifi_steering_clientDisconnect",
	"wifi_setBTMRequest",
	"wifi_getSSIDName",
	"wifi_setRMBeaconRequest",
	"wifi_getAssociationReqIEs",
	"wifi_setNeighborReports",
	"wifi_setNeighborReportActivation",
	"wifi_getRadioIfName",
	"wifi_getApNumDevicesAssociated",
	"wifi_steering_eventUnregister",
	"wifi_steering_eventRegister",
	"steering event notification",
	"wifi_mgmt_frame_callbacks_register",
	"mgmt frame event notification",
	"wifi_RMBeaconRequestCallbackRegister",
	"RM beacon report event notification",
	"wifi_BTMQueryRequest_callback_register",
	"BTM query request event notification",
	"BTM response event notification",
	NULL
};

gpd_test_case_t get_processor_desc_suite[] = {
	{ "valid_t00_ptr_eq_set_radio_stats_enable", 0, 0, 1 },
	{ "valid_t00_name_set_radio_stats_enable", 0, 1, 1 },
	{ "valid_t00_typefield_set_radio_stats_enable", 0, 2, 1 },
	{ "valid_t00_in_range_set_radio_stats_enable", 0, 3, 1 },
	{ "valid_t01_ptr_eq_get_ssid_num_of_entries", 1, 0, 1 },
	{ "valid_t01_name_get_ssid_num_of_entries", 1, 1, 1 },
	{ "valid_t01_typefield_get_ssid_num_of_entries", 1, 2, 1 },
	{ "valid_t01_in_range_get_ssid_num_of_entries", 1, 3, 1 },
	{ "valid_t02_ptr_eq_get_ap_assoc_dev_stats", 2, 0, 1 },
	{ "valid_t02_name_get_ap_assoc_dev_stats", 2, 1, 1 },
	{ "valid_t02_typefield_get_ap_assoc_dev_stats", 2, 2, 1 },
	{ "valid_t02_in_range_get_ap_assoc_dev_stats", 2, 3, 1 },
	{ "valid_t03_ptr_eq_get_radio_chan_stats", 3, 0, 1 },
	{ "valid_t03_name_get_radio_chan_stats", 3, 1, 1 },
	{ "valid_t03_typefield_get_radio_chan_stats", 3, 2, 1 },
	{ "valid_t03_in_range_get_radio_chan_stats", 3, 3, 1 },
	{ "valid_t04_ptr_eq_start_neighbor_scan", 4, 0, 1 },
	{ "valid_t04_name_start_neighbor_scan", 4, 1, 1 },
	{ "valid_t04_typefield_start_neighbor_scan", 4, 2, 1 },
	{ "valid_t04_in_range_start_neighbor_scan", 4, 3, 1 },
	{ "valid_t05_ptr_eq_get_neighbor_wifi_status", 5, 0, 1 },
	{ "valid_t05_name_get_neighbor_wifi_status", 5, 1, 1 },
	{ "valid_t05_typefield_get_neighbor_wifi_status", 5, 2, 1 },
	{ "valid_t05_in_range_get_neighbor_wifi_status", 5, 3, 1 },
	{ "valid_t06_ptr_eq_get_ssid_traffic_stats2", 6, 0, 1 },
	{ "valid_t06_name_get_ssid_traffic_stats2", 6, 1, 1 },
	{ "valid_t06_typefield_get_ssid_traffic_stats2", 6, 2, 1 },
	{ "valid_t06_in_range_get_ssid_traffic_stats2", 6, 3, 1 },
	{ "valid_t07_ptr_eq_get_ap_assoc_dev_rx_stats_result", 7, 0, 1 },
	{ "valid_t07_name_get_ap_assoc_dev_rx_stats_result", 7, 1, 1 },
	{ "valid_t07_typefield_get_ap_assoc_dev_rx_stats_result", 7, 2, 1 },
	{ "valid_t07_in_range_get_ap_assoc_dev_rx_stats_result", 7, 3, 1 },
	{ "valid_t08_ptr_eq_get_ssid_enable", 8, 0, 1 },
	{ "valid_t08_name_get_ssid_enable", 8, 1, 1 },
	{ "valid_t08_typefield_get_ssid_enable", 8, 2, 1 },
	{ "valid_t08_in_range_get_ssid_enable", 8, 3, 1 },
	{ "valid_t09_ptr_eq_get_ssid_radio_index", 9, 0, 1 },
	{ "valid_t09_name_get_ssid_radio_index", 9, 1, 1 },
	{ "valid_t09_typefield_get_ssid_radio_index", 9, 2, 1 },
	{ "valid_t09_in_range_get_ssid_radio_index", 9, 3, 1 },
	{ "valid_t10_ptr_eq_get_ssid_name_status", 10, 0, 1 },
	{ "valid_t10_name_get_ssid_name_status", 10, 1, 1 },
	{ "valid_t10_typefield_get_ssid_name_status", 10, 2, 1 },
	{ "valid_t10_in_range_get_ssid_name_status", 10, 3, 1 },
	{ "valid_t11_ptr_eq_get_ap_name", 11, 0, 1 },
	{ "valid_t11_name_get_ap_name", 11, 1, 1 },
	{ "valid_t11_typefield_get_ap_name", 11, 2, 1 },
	{ "valid_t11_in_range_get_ap_name", 11, 3, 1 },
	{ "valid_t12_ptr_eq_get_neighbor_report_activation", 12, 0, 1 },
	{ "valid_t12_name_get_neighbor_report_activation", 12, 1, 1 },
	{ "valid_t12_typefield_get_neighbor_report_activation", 12, 2, 1 },
	{ "valid_t12_in_range_get_neighbor_report_activation", 12, 3, 1 },
	{ "valid_t13_ptr_eq_get_bss_transition_activation", 13, 0, 1 },
	{ "valid_t13_name_get_bss_transition_activation", 13, 1, 1 },
	{ "valid_t13_typefield_get_bss_transition_activation", 13, 2, 1 },
	{ "valid_t13_in_range_get_bss_transition_activation", 13, 3, 1 },
	{ "valid_t14_ptr_eq_get_ap_assoc_dev_diag_result3", 14, 0, 1 },
	{ "valid_t14_name_get_ap_assoc_dev_diag_result3", 14, 1, 1 },
	{ "valid_t14_typefield_get_ap_assoc_dev_diag_result3", 14, 2, 1 },
	{ "valid_t14_in_range_get_ap_assoc_dev_diag_result3", 14, 3, 1 },
	{ "valid_t15_ptr_eq_get_ap_assoc_client_diag_result", 15, 0, 1 },
	{ "valid_t15_name_get_ap_assoc_client_diag_result", 15, 1, 1 },
	{ "valid_t15_typefield_get_ap_assoc_client_diag_result", 15, 2, 1 },
	{ "valid_t15_in_range_get_ap_assoc_client_diag_result", 15, 3, 1 },
	{ "valid_t16_ptr_eq_get_radio_operating_freq_band", 16, 0, 1 },
	{ "valid_t16_name_get_radio_operating_freq_band", 16, 1, 1 },
	{ "valid_t16_typefield_get_radio_operating_freq_band", 16, 2, 1 },
	{ "valid_t16_in_range_get_radio_operating_freq_band", 16, 3, 1 },
	{ "valid_t17_ptr_eq_get_radio_num_of_entries", 17, 0, 1 },
	{ "valid_t17_name_get_radio_num_of_entries", 17, 1, 1 },
	{ "valid_t17_typefield_get_radio_num_of_entries", 17, 2, 1 },
	{ "valid_t17_in_range_get_radio_num_of_entries", 17, 3, 1 },
	{ "valid_t18_ptr_eq_get_ap_assoc_dev_tx_stats_result", 18, 0, 1 },
	{ "valid_t18_name_get_ap_assoc_dev_tx_stats_result", 18, 1, 1 },
	{ "valid_t18_typefield_get_ap_assoc_dev_tx_stats_result", 18, 2, 1 },
	{ "valid_t18_in_range_get_ap_assoc_dev_tx_stats_result", 18, 3, 1 },
	{ "valid_t19_ptr_eq_steering_set_group", 19, 0, 1 },
	{ "valid_t19_name_steering_set_group", 19, 1, 1 },
	{ "valid_t19_typefield_steering_set_group", 19, 2, 1 },
	{ "valid_t19_in_range_steering_set_group", 19, 3, 1 },
	{ "valid_t20_ptr_eq_steering_client_set", 20, 0, 1 },
	{ "valid_t20_name_steering_client_set", 20, 1, 1 },
	{ "valid_t20_typefield_steering_client_set", 20, 2, 1 },
	{ "valid_t20_in_range_steering_client_set", 20, 3, 1 },
	{ "valid_t21_ptr_eq_steering_client_remove", 21, 0, 1 },
	{ "valid_t21_name_steering_client_remove", 21, 1, 1 },
	{ "valid_t21_typefield_steering_client_remove", 21, 2, 1 },
	{ "valid_t21_in_range_steering_client_remove", 21, 3, 1 },
	{ "valid_t22_ptr_eq_steering_client_disconnect", 22, 0, 1 },
	{ "valid_t22_name_steering_client_disconnect", 22, 1, 1 },
	{ "valid_t22_typefield_steering_client_disconnect", 22, 2, 1 },
	{ "valid_t22_in_range_steering_client_disconnect", 22, 3, 1 },
	{ "valid_t23_ptr_eq_set_btm_request", 23, 0, 1 },
	{ "valid_t23_name_set_btm_request", 23, 1, 1 },
	{ "valid_t23_typefield_set_btm_request", 23, 2, 1 },
	{ "valid_t23_in_range_set_btm_request", 23, 3, 1 },
	{ "valid_t24_ptr_eq_get_ssid_name", 24, 0, 1 },
	{ "valid_t24_name_get_ssid_name", 24, 1, 1 },
	{ "valid_t24_typefield_get_ssid_name", 24, 2, 1 },
	{ "valid_t24_in_range_get_ssid_name", 24, 3, 1 },
	{ "valid_t25_ptr_eq_set_rm_beacon_request", 25, 0, 1 },
	{ "valid_t25_name_set_rm_beacon_request", 25, 1, 1 },
	{ "valid_t25_typefield_set_rm_beacon_request", 25, 2, 1 },
	{ "valid_t25_in_range_set_rm_beacon_request", 25, 3, 1 },
	{ "valid_t26_ptr_eq_get_association_req_ies", 26, 0, 1 },
	{ "valid_t26_name_get_association_req_ies", 26, 1, 1 },
	{ "valid_t26_typefield_get_association_req_ies", 26, 2, 1 },
	{ "valid_t26_in_range_get_association_req_ies", 26, 3, 1 },
	{ "valid_t27_ptr_eq_set_neighbor_reports", 27, 0, 1 },
	{ "valid_t27_name_set_neighbor_reports", 27, 1, 1 },
	{ "valid_t27_typefield_set_neighbor_reports", 27, 2, 1 },
	{ "valid_t27_in_range_set_neighbor_reports", 27, 3, 1 },
	{ "valid_t28_ptr_eq_set_neighbor_report_activation", 28, 0, 1 },
	{ "valid_t28_name_set_neighbor_report_activation", 28, 1, 1 },
	{ "valid_t28_typefield_set_neighbor_report_activation", 28, 2, 1 },
	{ "valid_t28_in_range_set_neighbor_report_activation", 28, 3, 1 },
	{ "valid_t29_ptr_eq_get_radio_if_name", 29, 0, 1 },
	{ "valid_t29_name_get_radio_if_name", 29, 1, 1 },
	{ "valid_t29_typefield_get_radio_if_name", 29, 2, 1 },
	{ "valid_t29_in_range_get_radio_if_name", 29, 3, 1 },
	{ "valid_t30_ptr_eq_get_ap_num_assoc_devs", 30, 0, 1 },
	{ "valid_t30_name_get_ap_num_assoc_devs", 30, 1, 1 },
	{ "valid_t30_typefield_get_ap_num_assoc_devs", 30, 2, 1 },
	{ "valid_t30_in_range_get_ap_num_assoc_devs", 30, 3, 1 },
	{ "valid_t31_ptr_eq_steering_unregister", 31, 0, 1 },
	{ "valid_t31_name_steering_unregister", 31, 1, 1 },
	{ "valid_t31_typefield_steering_unregister", 31, 2, 1 },
	{ "valid_t31_in_range_steering_unregister", 31, 3, 1 },
	{ "valid_t32_ptr_eq_steering_register", 32, 0, 1 },
	{ "valid_t32_name_steering_register", 32, 1, 1 },
	{ "valid_t32_typefield_steering_register", 32, 2, 1 },
	{ "valid_t32_in_range_steering_register", 32, 3, 1 },
	{ "valid_t33_ptr_eq_steering_event", 33, 0, 1 },
	{ "valid_t33_name_steering_event", 33, 1, 1 },
	{ "valid_t33_typefield_steering_event", 33, 2, 1 },
	{ "valid_t33_in_range_steering_event", 33, 3, 1 },
	{ "valid_t34_ptr_eq_mgmt_frame_callback_register", 34, 0, 1 },
	{ "valid_t34_name_mgmt_frame_callback_register", 34, 1, 1 },
	{ "valid_t34_typefield_mgmt_frame_callback_register", 34, 2, 1 },
	{ "valid_t34_in_range_mgmt_frame_callback_register", 34, 3, 1 },
	{ "valid_t35_ptr_eq_mgmt_frame_event", 35, 0, 1 },
	{ "valid_t35_name_mgmt_frame_event", 35, 1, 1 },
	{ "valid_t35_typefield_mgmt_frame_event", 35, 2, 1 },
	{ "valid_t35_in_range_mgmt_frame_event", 35, 3, 1 },
	{ "valid_t36_ptr_eq_rm_beacon_request_register", 36, 0, 1 },
	{ "valid_t36_name_rm_beacon_request_register", 36, 1, 1 },
	{ "valid_t36_typefield_rm_beacon_request_register", 36, 2, 1 },
	{ "valid_t36_in_range_rm_beacon_request_register", 36, 3, 1 },
	{ "valid_t37_ptr_eq_rm_beacon_report_event", 37, 0, 1 },
	{ "valid_t37_name_rm_beacon_report_event", 37, 1, 1 },
	{ "valid_t37_typefield_rm_beacon_report_event", 37, 2, 1 },
	{ "valid_t37_in_range_rm_beacon_report_event", 37, 3, 1 },
	{ "valid_t38_ptr_eq_btm_query_request_register", 38, 0, 1 },
	{ "valid_t38_name_btm_query_request_register", 38, 1, 1 },
	{ "valid_t38_typefield_btm_query_request_register", 38, 2, 1 },
	{ "valid_t38_in_range_btm_query_request_register", 38, 3, 1 },
	{ "valid_t39_ptr_eq_btm_query_request_event", 39, 0, 1 },
	{ "valid_t39_name_btm_query_request_event", 39, 1, 1 },
	{ "valid_t39_typefield_btm_query_request_event", 39, 2, 1 },
	{ "valid_t39_in_range_btm_query_request_event", 39, 3, 1 },
	{ "valid_t40_ptr_eq_btm_response_event", 40, 0, 1 },
	{ "valid_t40_name_btm_response_event", 40, 1, 1 },
	{ "valid_t40_typefield_btm_response_event", 40, 2, 1 },
	{ "valid_t40_in_range_btm_response_event", 40, 3, 1 },
	{ "valid_t00_stride_to_next", 0, 4, 1 },
	{ "valid_t01_stride_to_next", 1, 4, 1 },
	{ "valid_t02_stride_to_next", 2, 4, 1 },
	{ "valid_t03_stride_to_next", 3, 4, 1 },
	{ "valid_t04_stride_to_next", 4, 4, 1 },
	{ "valid_t05_stride_to_next", 5, 4, 1 },
	{ "valid_t06_stride_to_next", 6, 4, 1 },
	{ "valid_t07_stride_to_next", 7, 4, 1 },
	{ "valid_t08_stride_to_next", 8, 4, 1 },
	{ "valid_t09_stride_to_next", 9, 4, 1 },
	{ "valid_t10_stride_to_next", 10, 4, 1 },
	{ "valid_t11_stride_to_next", 11, 4, 1 },
	{ "valid_t12_stride_to_next", 12, 4, 1 },
	{ "valid_t13_stride_to_next", 13, 4, 1 },
	{ "valid_t14_stride_to_next", 14, 4, 1 },
	{ "valid_t15_stride_to_next", 15, 4, 1 },
	{ "valid_t16_stride_to_next", 16, 4, 1 },
	{ "valid_t17_stride_to_next", 17, 4, 1 },
	{ "valid_t18_stride_to_next", 18, 4, 1 },
	{ "valid_t19_stride_to_next", 19, 4, 1 },
	{ "valid_t20_stride_to_next", 20, 4, 1 },
	{ "valid_t21_stride_to_next", 21, 4, 1 },
	{ "valid_t22_stride_to_next", 22, 4, 1 },
	{ "valid_t23_stride_to_next", 23, 4, 1 },
	{ "valid_t24_stride_to_next", 24, 4, 1 },
	{ "valid_t25_stride_to_next", 25, 4, 1 },
	{ "valid_t26_stride_to_next", 26, 4, 1 },
	{ "valid_t27_stride_to_next", 27, 4, 1 },
	{ "valid_t28_stride_to_next", 28, 4, 1 },
	{ "valid_t29_stride_to_next", 29, 4, 1 },
	{ "valid_t30_stride_to_next", 30, 4, 1 },
	{ "valid_t31_stride_to_next", 31, 4, 1 },
	{ "valid_t32_stride_to_next", 32, 4, 1 },
	{ "valid_t33_stride_to_next", 33, 4, 1 },
	{ "valid_t34_stride_to_next", 34, 4, 1 },
	{ "valid_t35_stride_to_next", 35, 4, 1 },
	{ "valid_t36_stride_to_next", 36, 4, 1 },
	{ "valid_t37_stride_to_next", 37, 4, 1 },
	{ "valid_t38_stride_to_next", 38, 4, 1 },
	{ "valid_t39_stride_to_next", 39, 4, 1 },
	{ "invalid_neg1_returns_null", -1, 5, 1 },
	{ "invalid_neg1_returns_null_or_in_table", -1, 6, 1 },
	{ "invalid_neg2_returns_null", -2, 5, 1 },
	{ "invalid_neg2_returns_null_or_in_table", -2, 6, 1 },
	{ "invalid_neg41_returns_null", -41, 5, 1 },
	{ "invalid_neg41_returns_null_or_in_table", -41, 6, 1 },
	{ "invalid_neg100_returns_null", -100, 5, 1 },
	{ "invalid_neg100_returns_null_or_in_table", -100, 6, 1 },
	{ "invalid_neg2147483648_returns_null", -2147483648, 5, 1 },
	{ "invalid_neg2147483648_returns_null_or_in_table", -2147483648, 6, 1 },
	{ "invalid_pos41_returns_null", 41, 5, 1 },
	{ "invalid_pos41_returns_null_or_in_table", 41, 6, 1 },
	{ "invalid_pos42_returns_null", 42, 5, 1 },
	{ "invalid_pos42_returns_null_or_in_table", 42, 6, 1 },
	{ "invalid_pos43_returns_null", 43, 5, 1 },
	{ "invalid_pos43_returns_null_or_in_table", 43, 6, 1 },
	{ "invalid_pos64_returns_null", 64, 5, 1 },
	{ "invalid_pos64_returns_null_or_in_table", 64, 6, 1 },
	{ "invalid_pos100_returns_null", 100, 5, 1 },
	{ "invalid_pos100_returns_null_or_in_table", 100, 6, 1 },
	{ "invalid_pos1000_returns_null", 1000, 5, 1 },
	{ "invalid_pos1000_returns_null_or_in_table", 1000, 6, 1 },
	{ "invalid_pos65536_returns_null", 65536, 5, 1 },
	{ "invalid_pos65536_returns_null_or_in_table", 65536, 6, 1 },
	{ "invalid_pos2147483647_returns_null", 2147483647, 5, 1 },
	{ "invalid_pos2147483647_returns_null_or_in_table", 2147483647, 6, 1 },
	/* crash cases last: without FIX 1 the first of these aborts under ASan */
	{ "invalid_pos41_deref_does_not_crash", 41, 7, 1 },
	{ "invalid_neg1_deref_does_not_crash", -1, 7, 1 },
	{ "invalid_neg2_deref_does_not_crash", -2, 7, 1 },
	{ "invalid_neg41_deref_does_not_crash", -41, 7, 1 },
	{ "invalid_neg100_deref_does_not_crash", -100, 7, 1 },
	{ "invalid_neg2147483648_deref_does_not_crash", -2147483648, 7, 1 },
	{ "invalid_pos42_deref_does_not_crash", 42, 7, 1 },
	{ "invalid_pos43_deref_does_not_crash", 43, 7, 1 },
	{ "invalid_pos64_deref_does_not_crash", 64, 7, 1 },
	{ "invalid_pos100_deref_does_not_crash", 100, 7, 1 },
	{ "invalid_pos1000_deref_does_not_crash", 1000, 7, 1 },
	{ "invalid_pos65536_deref_does_not_crash", 65536, 7, 1 },
	{ "invalid_pos2147483647_deref_does_not_crash", 2147483647, 7, 1 },
	{ NULL, 0, 0, 0 }
};

static const gpd_test_case_t *cur_tc;

void construct_get_processor_desc_input(const gpd_test_case_t *tc)
{
	cur_tc = tc;
	memset(gpd_name_buf, 0, GPD_NAME_SZ);
}

static int in_table(const void *p)
{
	return (const char *)p >= (const char *)&processor_desc[0] &&
	       (const char *)p <  (const char *)&processor_desc[hal_ipc_desc_type_max];
}

static int deref_in_child(hal_ipc_processor_desc_t *d)
{
	/* What every real caller does: use desc->... (a correct caller checks NULL first).
	 * Run in-process: without FIX 1 this is the ASan abort. */
	if (d != NULL) {
		volatile int sink = d->type;
		(void)sink;
	}
	return 1;                                     /* reached = did not crash */
}

int get_processor_desc_run_current(void)
{
	hal_ipc_desc_type_t t = (hal_ipc_desc_type_t)cur_tc->type_value;
	hal_ipc_processor_desc_t *d = get_processor_desc(t);

	switch (cur_tc->kind) {
	case GPD_PTR_EQ:
		return d == &processor_desc[cur_tc->type_value];
	case GPD_NAME:
		strncpy(gpd_name_buf, d->name, GPD_NAME_USE - 1);   /* runner-owned copy, tail poisoned */
		return !strcmp(gpd_name_buf, gpd_expected_names[cur_tc->type_value]);
	case GPD_TYPEFIELD:
		return d->type == t;
	case GPD_IN_RANGE:
		return d != NULL && in_table(d);
	case GPD_STRIDE: {
		hal_ipc_processor_desc_t *n = get_processor_desc((hal_ipc_desc_type_t)(cur_tc->type_value + 1));
		return (size_t)((char *)n - (char *)d) == sizeof(hal_ipc_processor_desc_t);
	}
	case GPD_PTR_ARITH:                               /* invalid type -> NULL (was: unchecked arithmetic before FIX 1) */
		return d == NULL;
	case GPD_SAFE_RANGE:
		return d == NULL || in_table(d);
	case GPD_DEREF_NO_CRASH:
		return deref_in_child(d);
	}
	return 0;
}
