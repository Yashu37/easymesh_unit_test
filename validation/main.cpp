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
extern "C" void run_all_tests_wifi_hal_getBSSTransitionActivation(void);   /* declared here: that harness does not use common.h */

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
	run_all_tests_wifi_hal_getBSSTransitionActivation();

	return 0;
}
