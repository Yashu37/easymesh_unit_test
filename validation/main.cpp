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
extern "C" void run_all_tests_hal_ipc_BTMQueryRequestEvent(void);
extern "C" void run_all_tests_hal_ipc_BTMResponseEvent(void);
extern "C" void run_all_tests_hal_ipc_RMBeaconReportEvent(void);
extern "C" void run_all_tests_hal_ipc_send_steering_event(void);
extern "C" void run_all_tests_hal_ipc_init(void);
extern "C" void run_all_tests_wifi_nvram_defaultRead(void);
extern "C" void run_all_tests_json_parse_backhaul_keypassphrase(void);
extern "C" void run_all_tests_json_parse_backhaul_ssid(void);
extern "C" void run_all_tests_platform_pre_init(void);
extern "C" void run_all_tests_platform_post_init(void);
extern "C" void run_all_tests_platform_set_radio(void);
extern "C" void run_all_tests_platform_set_radio_pre_init(void);
extern "C" void run_all_tests_platform_create_vap(void);
extern "C" void run_all_tests_nvram_get_radio_enable_status(void);
extern "C" void run_all_tests_nvram_get_vap_enable_status(void);
extern "C" void run_all_tests_nvram_get_current_security_mode(void);
extern "C" void run_all_tests_platform_get_keypassphrase_default(void);
extern "C" void run_all_tests_platform_get_ssid_default(void);
extern "C" void run_all_tests_platform_get_wps_pin_default(void);
extern "C" void run_all_tests_platform_wps_event(void);
extern "C" void run_all_tests_platform_get_country_code_default(void);
extern "C" void run_all_tests_nvram_get_current_password(void);   /* declared here: that harness does not use common.h */
extern "C" void run_all_tests_nvram_get_current_ssid(void);
extern "C" void run_all_tests_platform_pre_create_vap(void);
extern "C" void run_all_tests_platform_flags_init(void);
extern "C" void run_all_tests_wifi_getNeighboringWiFiStatus(void);
extern "C" void run_all_tests_wifi_setQamPlus(void);
extern "C" void run_all_tests_wifi_setApRetrylimit(void);
extern "C" void run_all_tests_wifi_sendActionFrameExt(void);
extern "C" void run_all_tests_wifi_sendActionFrame(void);
extern "C" void run_all_tests_wifi_getApManagementFramePowerControl(void);
extern "C" void run_all_tests_wifi_getRadioChannelStats(void);
extern "C" void run_all_tests_wifi_getApEnable(void);
extern "C" void run_all_tests_wifi_setApIsolationEnable(void);
extern "C" void run_all_tests_wifi_freq_to_op_class(void);
extern "C" void run_all_tests_wifi_setProxyArp(void);
extern "C" void run_all_tests_wifi_setCountryIe(void);
extern "C" void run_all_tests_wifi_getLayer2TrafficInspectionFiltering(void);
extern "C" void run_all_tests_wifi_getCountryIe(void);
extern "C" void run_all_tests_wifi_getDownStreamGroupAddress(void);
extern "C" void run_all_tests_wifi_getProxyArp(void);
extern "C" void run_all_tests_wifi_getBssLoad(void);
extern "C" void run_all_tests_wifi_setDownStreamGroupAddress(void);
extern "C" void run_all_tests_wifi_setBssLoad(void);
extern "C" void run_all_tests_wifi_getApAssociatedClientDiagnosticResult(void);
extern "C" void run_all_tests_wifi_setP2PCrossConnect(void);
extern "C" void run_all_tests_wifi_setLayer2TrafficInspectionFiltering(void);
extern "C" void run_all_tests_wifi_pushApHotspotElement(void);
extern "C" void run_all_tests_wifi_applyGASConfiguration(void);
extern "C" void run_all_tests_wifi_steering_eventRegister(void);
extern "C" void run_all_tests_wifi_setApManagementFramePowerControl(void);
extern "C" void run_all_tests_wifi_drv_get_phy_eht_cap_mac(void);
extern "C" void run_all_tests_wifi_getNeighboringWiFiStatus_bcm(void);
extern "C" void run_all_tests_bcm_wifi_getApAssociatedDeviceDiagnosticResult3(void);
extern "C" void run_all_tests_bcm_wifi_getRadioChannelStats(void);
extern "C" void run_all_tests_bcm_wifi_getRadioTrafficStats2(void);
extern "C" void run_all_tests_bcm_wifi_setApManagementFramePowerControl(void);
extern "C" void run_all_tests_wifi_getRadioTransmitPower_bcm(void);
extern "C" void run_all_tests_int_wifi_allow2G80211ax(void);
extern "C" void run_all_tests_int_wifi_setQamPlus(void);
extern "C" void run_all_tests_int_wifi_setApRetrylimit(void);
extern "C" void run_all_tests_int_wifi_getApInterworkingElement(void);
extern "C" void run_all_tests_int_wifi_pushApRoamingConsortiumElement(void);
extern "C" void run_all_tests_int_wifi_setApManagementFramePowerControl(void);
extern "C" void run_all_tests_int_wifi_setApMacAddressControlMode(void);
extern "C" void run_all_tests_int_wifi_setRadioDfsAtBootUpEnable(void);
extern "C" void run_all_tests_int_wifi_getRadioChannel(void);
extern "C" void run_all_tests_int_wifi_setProxyArp(void);
extern "C" void run_all_tests_int_wifi_setCountryIe(void);
extern "C" void run_all_tests_int_wifi_getLayer2TrafficInspectionFiltering(void);
extern "C" void run_all_tests_int_wifi_getCountryIe(void);
extern "C" void run_all_tests_int_wifi_setP2PCrossConnect(void);
extern "C" void run_all_tests_int_wifi_getDownStreamGroupAddress(void);
extern "C" void run_all_tests_int_wifi_getProxyArp(void);
extern "C" void run_all_tests_int_wifi_applyGASConfiguration(void);
extern "C" void run_all_tests_int_wifi_pushApHotspotElement(void);
extern "C" void run_all_tests_int_wifi_setBssLoad(void);
extern "C" void run_all_tests_int_wifi_getApInterworkingServiceEnable(void);
extern "C" void run_all_tests_int_wifi_sendActionFrameExt(void);
extern "C" void run_all_tests_int_wifi_setDownStreamGroupAddress(void);
extern "C" void run_all_tests_wifi_getApAssociatedDeviceDiagnosticResult3(void);
extern "C" void run_all_tests_wifi_startNeighborScan(void);

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
//	run_all_tests_hal_ipc_BTMQueryRequestEvent();

	// hal_ipc_BTMResponseEvent (rdk-wifi-hal hal_ipc/server/server_hal_ipc.c)
//	run_all_tests_hal_ipc_BTMResponseEvent();

	// hal_ipc_RMBeaconReportEvent (rdk-wifi-hal hal_ipc/server/server_hal_ipc.c)
//	run_all_tests_hal_ipc_RMBeaconReportEvent();

	// hal_ipc_send_steering_event (rdk-wifi-hal hal_ipc/server/server_hal_ipc.c)
//	run_all_tests_hal_ipc_send_steering_event();

	// hal_ipc_init (rdk-wifi-hal hal_ipc/server/server_hal_ipc.c)
//	run_all_tests_hal_ipc_init();

	// wifi_nvram_defaultRead (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_nvram_defaultRead();

	// json_parse_backhaul_keypassphrase (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_json_parse_backhaul_keypassphrase();

	// json_parse_backhaul_ssid (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_json_parse_backhaul_ssid();

	// platform_pre_init (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_pre_init();

	// platform_post_init (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_post_init();

	// platform_set_radio (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_set_radio();

	// platform_set_radio_pre_init (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_set_radio_pre_init();

	// platform_create_vap (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_create_vap();

	// nvram_get_radio_enable_status (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_nvram_get_radio_enable_status();

	// nvram_get_vap_enable_status (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_nvram_get_vap_enable_status();

	// nvram_get_current_security_mode (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_nvram_get_current_security_mode();

	// platform_get_keypassphrase_default (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_get_keypassphrase_default();

	// platform_get_ssid_default (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_get_ssid_default();

	// platform_get_wps_pin_default (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_get_wps_pin_default();

	// platform_wps_event (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_wps_event();

	// platform_get_country_code_default (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_get_country_code_default();

	// nvram_get_current_password (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_nvram_get_current_password();

	// nvram_get_current_ssid (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_nvram_get_current_ssid();

	// platform_pre_create_vap (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_pre_create_vap();

	// platform_flags_init (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_platform_flags_init();

	// wifi_startNeighborScan (rdk-wifi-hal platform/banana-pi/platform.c -> src/wifi_hal.c wifi_hal_startNeighborScan)
//	run_all_tests_wifi_startNeighborScan();

	// wifi_getNeighboringWiFiStatus (rdk-wifi-hal platform/banana-pi/platform.c -> src/wifi_hal.c)
//	run_all_tests_wifi_getNeighboringWiFiStatus();

	// wifi_setQamPlus (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setQamPlus();

	// wifi_setApRetrylimit (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setApRetrylimit();

	// wifi_sendActionFrameExt (rdk-wifi-hal platform/banana-pi/platform.c -> src/wifi_hal.c wifi_hal_send_mgmt_frame)
//	run_all_tests_wifi_sendActionFrameExt();

	// wifi_sendActionFrame (rdk-wifi-hal platform/banana-pi/platform.c -> wifi_sendActionFrameExt)
//	run_all_tests_wifi_sendActionFrame();

	// wifi_getApManagementFramePowerControl (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getApManagementFramePowerControl();

	// wifi_getRadioChannelStats (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getRadioChannelStats();

	// wifi_getApAssociatedDeviceDiagnosticResult3 (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getApAssociatedDeviceDiagnosticResult3();

	// wifi_getApEnable (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getApEnable();

	// wifi_setApIsolationEnable (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setApIsolationEnable();

	// wifi_freq_to_op_class (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_freq_to_op_class();

	// wifi_setProxyArp (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setProxyArp();

	// wifi_setCountryIe (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setCountryIe();

	// wifi_getLayer2TrafficInspectionFiltering (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getLayer2TrafficInspectionFiltering();

	// wifi_getCountryIe (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getCountryIe();

	// wifi_getDownStreamGroupAddress (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getDownStreamGroupAddress();

	// wifi_getProxyArp (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getProxyArp();

	// wifi_getBssLoad (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getBssLoad();

	// wifi_setDownStreamGroupAddress (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setDownStreamGroupAddress();

	// wifi_setBssLoad (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setBssLoad();

	// wifi_getApAssociatedClientDiagnosticResult (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_getApAssociatedClientDiagnosticResult();

	// wifi_setP2PCrossConnect (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setP2PCrossConnect();

	// wifi_setLayer2TrafficInspectionFiltering (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setLayer2TrafficInspectionFiltering();

	// wifi_pushApHotspotElement (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_pushApHotspotElement();

	// wifi_applyGASConfiguration (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_applyGASConfiguration();

	// wifi_steering_eventRegister (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_steering_eventRegister();

	// wifi_setApManagementFramePowerControl (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_setApManagementFramePowerControl();

	// wifi_drv_get_phy_eht_cap_mac (rdk-wifi-hal platform/banana-pi/platform.c)
//	run_all_tests_wifi_drv_get_phy_eht_cap_mac();

	// platform/broadcom: wifi_getNeighboringWiFiStatus (rdk-wifi-hal platform/broadcom/platform.c)
//	run_all_tests_wifi_getNeighboringWiFiStatus_bcm();

	// platform/broadcom: wifi_getApAssociatedDeviceDiagnosticResult3 (rdk-wifi-hal platform/broadcom/platform.c)
//	run_all_tests_bcm_wifi_getApAssociatedDeviceDiagnosticResult3();

	// platform/broadcom: wifi_getRadioChannelStats (rdk-wifi-hal platform/broadcom/platform.c)
//	run_all_tests_bcm_wifi_getRadioChannelStats();

	// platform/broadcom: wifi_getRadioTrafficStats2 (rdk-wifi-hal platform/broadcom/platform.c)
//	run_all_tests_bcm_wifi_getRadioTrafficStats2();

	// platform/broadcom: wifi_setApManagementFramePowerControl (rdk-wifi-hal platform/broadcom/platform.c)
//	run_all_tests_bcm_wifi_setApManagementFramePowerControl();

	// platform/broadcom: wifi_getRadioTransmitPower (rdk-wifi-hal platform/broadcom/platform.c)
//	run_all_tests_wifi_getRadioTransmitPower_bcm();

	// platform/intel: wifi_allow2G80211ax (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_allow2G80211ax();

	// platform/intel: wifi_setQamPlus (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setQamPlus();

	// platform/intel: wifi_setApRetrylimit (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setApRetrylimit();

	// platform/intel: wifi_getApInterworkingElement (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getApInterworkingElement();

	// platform/intel: wifi_pushApRoamingConsortiumElement (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_pushApRoamingConsortiumElement();

	// platform/intel: wifi_setApManagementFramePowerControl (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setApManagementFramePowerControl();

	// platform/intel: wifi_setApMacAddressControlMode (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setApMacAddressControlMode();

	// platform/intel: wifi_setRadioDfsAtBootUpEnable (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setRadioDfsAtBootUpEnable();

	// platform/intel: wifi_getRadioChannel (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getRadioChannel();

	// platform/intel: wifi_setProxyArp (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setProxyArp();

	// platform/intel: wifi_setCountryIe (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setCountryIe();

	// platform/intel: wifi_getLayer2TrafficInspectionFiltering (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getLayer2TrafficInspectionFiltering();

	// platform/intel: wifi_getCountryIe (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getCountryIe();

	// platform/intel: wifi_setP2PCrossConnect (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setP2PCrossConnect();

	// platform/intel: wifi_getDownStreamGroupAddress (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getDownStreamGroupAddress();

	// platform/intel: wifi_getProxyArp (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getProxyArp();

	// platform/intel: wifi_applyGASConfiguration (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_applyGASConfiguration();

	// platform/intel: wifi_pushApHotspotElement (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_pushApHotspotElement();

	// platform/intel: wifi_setBssLoad (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_setBssLoad();

	// platform/intel: wifi_getApInterworkingServiceEnable (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_getApInterworkingServiceEnable();

	// platform/intel: wifi_sendActionFrameExt (rdk-wifi-hal platform/intel/platform.c)
//	run_all_tests_int_wifi_sendActionFrameExt();

	// platform/intel: wifi_setDownStreamGroupAddress (rdk-wifi-hal platform/intel/platform.c)
	run_all_tests_int_wifi_setDownStreamGroupAddress();

	return 0;
}
