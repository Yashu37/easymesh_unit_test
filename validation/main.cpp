#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
extern "C" void run_all_tests_ipc_server_output(void);
extern "C" void run_all_tests_ipc_client_notification_input(void);
extern "C" void run_all_tests_wifi_hal_setRadioStatsEnable(void);
extern "C" void run_all_tests_wifi_hal_getSSIDNumberOfEntries(void);
extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceStats(void);
extern "C" void run_all_tests_wifi_hal_getRadioChannelStats(void);
extern "C" void run_all_tests_wifi_hal_getSSIDTrafficStats2(void);
extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceRxStatsResult(void);
extern "C" void run_all_tests_wifi_hal_getSSIDEnable(void);
extern "C" void run_all_tests_wifi_hal_getSSIDRadioIndex(void);
extern "C" void run_all_tests_wifi_hal_getSSIDNameStatus(void);
extern "C" void run_all_tests_wifi_hal_getApName(void);
extern "C" void run_all_tests_wifi_hal_getNeighborReportActivation(void);
extern "C" void run_all_tests_wifi_hal_getBSSTransitionActivation(void);
extern "C" void run_all_tests_wifi_hal_getApAssociatedClientDiagnosticResult(void);
extern "C" void run_all_tests_wifi_hal_getRadioOperatingFrequencyBand(void);
extern "C" void run_all_tests_wifi_hal_getRadioNumberOfEntries(void);
extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceTxStatsResult(void);
extern "C" void run_all_tests_wifi_hal_getMultiPskClientKey(void);
extern "C" void run_all_tests_wifi_hal_steering_setGroup(void);
extern "C" void run_all_tests_wifi_hal_steering_clientSet(void);
extern "C" void run_all_tests_wifi_hal_steering_clientRemove(void);
extern "C" void run_all_tests_wifi_hal_steering_clientDisconnect(void);
extern "C" void run_all_tests_wifi_hal_getSSIDName(void);
extern "C" void run_all_tests_wifi_hal_getAssociationReqIEs(void);
extern "C" void run_all_tests_wifi_hal_getRadioCountryCode(void);
extern "C" void run_all_tests_wifi_hal_getRadioOperatingChannelBandwidth(void);
extern "C" void run_all_tests_wifi_hal_getRadioTransmitPower(void);
extern "C" void run_all_tests_wifi_hal_setNeighborReportActivation(void);
extern "C" void run_all_tests_wifi_hal_getRadioIfName(void);
extern "C" void run_all_tests_wifi_hal_getApNumDevicesAssociated(void);
extern "C" void run_all_tests_hal_ipc_BTMQueryRequestEvent(void);   /* declared here: that harness does not use common.h */

int main() {
	/* unbuffered stdout so per-test lines flush before any crash/abort */
	setvbuf(stdout, NULL, _IONBF, 0);

	// dpp_dummy (rdk-wifi-hal feature_dpp/dpp.c)
//	run_all_tests_dpp_dummy();

	// hal_ipc_server_set_ap_assoc_dev_diag_res3_callback (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_hal_ipc_server_set_ap_assoc_dev_diag_res3_callback();

	// hal_ipc_server_set_neighbor_ap2_callback (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_hal_ipc_server_set_neighbor_ap2_callback();

	// hal_ipc_server_set_radio_channel_stats_callback (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_hal_ipc_server_set_radio_channel_stats_callback();

	// hal_ipc_server_get_ap_assoc_dev_diag_res3_callback (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_hal_ipc_server_get_ap_assoc_dev_diag_res3_callback();

	// hal_ipc_server_get_neighbor_ap2_callback (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_hal_ipc_server_get_neighbor_ap2_callback();

	// hal_ipc_server_get_radio_channel_stats_callback (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_hal_ipc_server_get_radio_channel_stats_callback();

	// get_processor_desc (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_get_processor_desc();

	// rdk_hal_ipc_exec (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_rdk_hal_ipc_exec();

	// rdk_hal_server_func (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_rdk_hal_server_func();

	// rdk_create_hal_ipc_node (rdk-wifi-hal hal_ipc/server/hal_ipc.c)
//	run_all_tests_rdk_create_hal_ipc_node();

	// cleanup_client_data (rdk-wifi-hal hal_ipc/server/hal_ipc_processors.c)
//	run_all_tests_cleanup_client_data();

	// cleanup_desc_scratch_buf (rdk-wifi-hal hal_ipc/server/hal_ipc_processors.c)
//	run_all_tests_cleanup_desc_scratch_buf();

	// sync_hostapd_freq_param (rdk-wifi-hal hal_ipc/server/hal_ipc_processors.c)
//	run_all_tests_sync_hostapd_freq_param();

	// ipc_server_output (rdk-wifi-hal hal_ipc/server/hal_ipc_processors.c)
//	run_all_tests_ipc_server_output();

	// ipc_client_notification_input (rdk-wifi-hal hal_ipc/server/hal_ipc_processors.c)
//	run_all_tests_ipc_client_notification_input();

	// wifi_hal_setRadioStatsEnable (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_setRadioStatsEnable();

	// wifi_hal_getSSIDNumberOfEntries (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getSSIDNumberOfEntries();

	// wifi_hal_getApAssociatedDeviceStats (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getApAssociatedDeviceStats();

	// wifi_hal_getRadioChannelStats (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioChannelStats();

	// wifi_hal_getSSIDTrafficStats2 (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getSSIDTrafficStats2();

	// wifi_hal_getApAssociatedDeviceRxStatsResult (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getApAssociatedDeviceRxStatsResult();

	// wifi_hal_getSSIDEnable (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getSSIDEnable();

	// wifi_hal_getSSIDRadioIndex (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getSSIDRadioIndex();

	// wifi_hal_getSSIDNameStatus (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getSSIDNameStatus();

	// wifi_hal_getApName (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getApName();

	// wifi_hal_getNeighborReportActivation (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getNeighborReportActivation();

	// wifi_hal_getBSSTransitionActivation (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getBSSTransitionActivation();

	// wifi_hal_getApAssociatedClientDiagnosticResult (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getApAssociatedClientDiagnosticResult();

	// wifi_hal_getRadioOperatingFrequencyBand (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioOperatingFrequencyBand();

	// wifi_hal_getRadioNumberOfEntries (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioNumberOfEntries();

	// wifi_hal_getApAssociatedDeviceTxStatsResult (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getApAssociatedDeviceTxStatsResult();

	// wifi_hal_getMultiPskClientKey (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getMultiPskClientKey();

	// wifi_hal_steering_setGroup (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_steering_setGroup();

	// wifi_hal_steering_clientSet (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_steering_clientSet();

	// wifi_hal_steering_clientRemove (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_steering_clientRemove();

	// wifi_hal_steering_clientDisconnect (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_steering_clientDisconnect();

	// wifi_hal_getSSIDName (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getSSIDName();

	// wifi_hal_getAssociationReqIEs (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getAssociationReqIEs();

	// wifi_hal_getRadioCountryCode (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioCountryCode();

	// wifi_hal_getRadioOperatingChannelBandwidth (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioOperatingChannelBandwidth();

	// wifi_hal_getRadioTransmitPower (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioTransmitPower();

	// wifi_hal_setNeighborReportActivation (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_setNeighborReportActivation();

	// wifi_hal_getRadioIfName (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getRadioIfName();

	// wifi_hal_getApNumDevicesAssociated (rdk-wifi-hal hal_ipc/server/hal_ipc_wifi_wrappers.c)
//	run_all_tests_wifi_hal_getApNumDevicesAssociated();

	// hal_ipc_BTMQueryRequestEvent (rdk-wifi-hal hal_ipc/server/server_hal_ipc.c)
	run_all_tests_hal_ipc_BTMQueryRequestEvent();

	return 0;
}
