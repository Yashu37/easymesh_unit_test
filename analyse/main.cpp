#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int main() {
	/* unbuffered stdout so per-test lines flush before any crash/abort */
	setvbuf(stdout, NULL, _IONBF, 0);
#if 0
	run_all_tests_handle_bsta_cap_report();
	run_all_tests_get_first_tlv();
	run_all_tests_get_next_tlv();
	run_all_tests_handle_ap_metrics_response();
	run_all_tests_handle_channel_scan_rprt();
	run_all_tests_handle_channel_scan_req();
	run_all_tests_handle_unassoc_sta_link_metrics_tlv();
	run_all_tests_handle_ap_operational_bss();
        run_all_tests_handle_beacon_metrics_query();
        run_all_tests_get_supported_service();
	run_all_tests_handle_channel_scan_req();
	run_all_tests_get_radio_id_channel_scan_req();
#endif
	// base64_decode OOB crash check (OneWifi lib/common/util.c).
	// Kept last: it aborts under ASan on invalid-char input.
//	run_all_tests_base64_decode();

	// base64_encode OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_base64_encode();

	// cmd_log OOB crash check (OneWifi lib/common/os.c).
//	run_all_tests_cmd_log();

	// file_get OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_file_get();

	// mon_check_process OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_check_process();

	// mon_sig_crash OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_sig_crash();

	// mon_sig_forward OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_sig_forward();

	// mon_sig_str OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_sig_str();

	// os_cmd_exec_xv OOB crash check (OneWifi lib/common/os_exec.c).
//	run_all_tests_os_cmd_exec_xv();

	// os_pid_from_file OOB crash check (OneWifi lib/common/os.c).
//	run_all_tests_os_pid_from_file();

	// os_popen OOB crash check (OneWifi lib/common/os.c).
//	run_all_tests_os_popen();

	// parse_uri OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_parse_uri();

	// strexread OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_strexread();

	// unii_5g_chan2list OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_unii_5g_chan2list();

	// devinfo_get_inet_iface_config OOB check (OneWifi lib/datapipeline/devinfo.c).
//	run_all_tests_devinfo_cfg();

	// dpp_mac_str_tmp OOB crash check (OneWifi lib/datapipeline/dppline.c).
//	run_all_tests_dpp_mac_str_tmp();

	// osp_unit_dhcpc_hostname_get OOB check (OneWifi lib/datapipeline/osp_unit_rdk.c).
//	run_all_tests_osp_hostname();

	// radio_get_name_from_cfg OOB check (OneWifi lib/datapipeline/dpp_types.h).
//	run_all_tests_radio_name();

	// ds_tree_check_r OOB crash check (OneWifi lib/ds/ds_tree.c).
//	run_all_tests_ds_tree_check();

	// ds_tree_graphviz_r OOB crash check (OneWifi lib/ds/ds_tree.c).
//	run_all_tests_ds_tree_gv();

	// ds_tree_node_str OOB crash check (OneWifi lib/ds/ds_tree.c).
//	run_all_tests_ds_node_str();

	// log_dynamic_full_path_get OOB check (OneWifi lib/log/log.c).
//	run_all_tests_log_fullpath();

	// log_dynamic_state_handler OOB check (OneWifi lib/log/log.c).
//	run_all_tests_log_state();

	// log_dynamic_update OOB check (OneWifi lib/log/log.c).
//	run_all_tests_log_update();

	// log_meminfo OOB check (OneWifi lib/log/log.c).
//	run_all_tests_log_meminfo();

	// log_severity_parse_sink OOB check (OneWifi lib/log/log.c).
//	run_all_tests_log_sev();

	// logger_remote_log OOB check (OneWifi lib/log/log_remote.c).
//	run_all_tests_logger_remote();

	// logger_traceback_log OOB check (OneWifi lib/log/log_traceback.c).
//	run_all_tests_logger_tb();

	// mlog OOB check (OneWifi lib/log/log.c).
//	run_all_tests_mlog();

	// os_file_open OOB check (OneWifi lib/osa/os_file_ops.c).
//	run_all_tests_os_file_open();

	// os_name_to_pid OOB check (OneWifi lib/osa/os_proc.c).
//	run_all_tests_os_name_pid();

	// os_nif_gateway_del OOB check (OneWifi lib/osa/os_nif_linux.c).
//	run_all_tests_os_nif_gateway_del();

	// os_nif_gateway_set OOB check (OneWifi lib/osa/os_nif_linux.c).
//	run_all_tests_os_nif_gateway_set();

	// os_nif_list_get OOB check (OneWifi lib/osa/os_nif_linux.c).
//	run_all_tests_os_nif_list_get();

	// os_nif_macaddr_from_str OOB check (OneWifi lib/osa/os_nif_linux.c).
//	run_all_tests_os_nif_macaddr_from_str();

	// os_nif_softwds_create OOB check (OneWifi lib/osa/os_nif_linux.c).
//	run_all_tests_os_nif_softwds_create();

	// os_nif_softwds_destroy OOB check (OneWifi lib/osa/os_nif_linux.c).
//	run_all_tests_os_nif_softwds_destroy();

	// os_pid_to_name OOB check (OneWifi lib/osa/os_proc.c).
//	run_all_tests_os_pid_to_name();

	// _ovsdb_cache_insert_row OOB check (OneWifi lib/ovsdb/ovsdb_cache.c).
//	run_all_tests_ovsdb_cache_insert_row();

	// onewifi_ovsdb_cache_pre_fetch OOB check (OneWifi lib/ovsdb/ovsdb_cache.c).
//	run_all_tests_ovsdb_cache_pre_fetch();

	// onewifi_ovsdb_cache_update_cb OOB check (OneWifi lib/ovsdb/ovsdb_cache.c).
//	run_all_tests_ovsdb_cache_update_cb();

	// onewifi_ovsdb_cache_upsert OOB check (OneWifi lib/ovsdb/ovsdb_cache.c).
//	run_all_tests_ovsdb_cache_upsert();

	// onewifi_ovsdb_method_send_s OOB check (OneWifi lib/ovsdb/ovsdb_sync.c).
//	run_all_tests_ovsdb_method_send_s();

	// onewifi_ovsdb_sync_update_one_get_uuid OOB check (OneWifi lib/ovsdb/ovsdb_sync_api.c).
//	run_all_tests_ovsdb_sync_update_one_get_uuid();

	// onewifi_ovsdb_sync_update_where OOB check (OneWifi lib/ovsdb/ovsdb_sync_api.c).
//	run_all_tests_ovsdb_sync_update_where();

	// onewifi_ovsdb_sync_upsert_where OOB check (OneWifi lib/ovsdb/ovsdb_sync_api.c).
//	run_all_tests_ovsdb_sync_upsert_where();

	// onewifi_ovsdb_table_filter_row OOB check (OneWifi lib/ovsdb/ovsdb_table.c).
//	run_all_tests_ovsdb_table_filter_row();

	// onewifi_ovsdb_table_from_json OOB check (OneWifi lib/ovsdb/ovsdb_table.c).
//	run_all_tests_ovsdb_table_from_json();

	// onewifi_ovsdb_table_monitor_columns OOB check (OneWifi lib/ovsdb/ovsdb_table.c).
//	run_all_tests_ovsdb_table_monitor_columns();

	// onewifi_ovsdb_table_monitor_filter OOB check (OneWifi lib/ovsdb/ovsdb_table.c).
//	run_all_tests_ovsdb_table_monitor_filter();

	// onewifi_ovsdb_table_to_json OOB check (OneWifi lib/ovsdb/ovsdb_table.c).
//	run_all_tests_ovsdb_table_to_json();

	// onewifi_ovsdb_table_update_cb OOB check (OneWifi lib/ovsdb/ovsdb_table.c).
//	run_all_tests_ovsdb_table_update_cb();

	// onewifi_ovsdb_tran_comment OOB check (OneWifi lib/ovsdb/ovsdb_method.c).
//	run_all_tests_ovsdb_tran_comment();

	// onewifi_ovsdb_update_changed OOB check (OneWifi lib/ovsdb/ovsdb_update.c).
//	run_all_tests_ovsdb_update_changed();

	// ovsdb_get_update_result_count_off OOB check (OneWifi lib/ovsdb/ovsdb_sync_api.c).
//	run_all_tests_ovsdb_get_update_result_count_off();

	// ovsdb_sync_get_uuid_and_count OOB check (OneWifi lib/ovsdb/ovsdb_sync_api.c).
//	run_all_tests_ovsdb_sync_get_uuid_and_count();

	// pgctrl_command OOB check (OneWifi lib/pktgen/pktgen.c).
//	run_all_tests_pgctrl_command();

	// onewifi_pktgen_is_running OOB check (OneWifi lib/pktgen/pktgen.c).
//	run_all_tests_pktgen_is_running();

	// pktgen_configure OOB check (OneWifi lib/pktgen/pktgen.c).
//	run_all_tests_pktgen_configure();

	// get_app_by_inst OOB check (OneWifi source/apps/wifi_apps_mgr.c).
//	run_all_tests_get_app_by_inst();

	// app_register OOB check (OneWifi source/apps/wifi_apps_mgr.c).
//	run_all_tests_app_register();

	// device_statistics_info OOB check (OneWifi source/apps/analytics/wifi_analytics.c).
//	run_all_tests_device_statistics_info();

	// analytics_event_hal_sta_conn_status OOB check (OneWifi source/apps/analytics/wifi_analytics.c).
//	run_all_tests_analytics_event_hal_sta_conn_status();

	// analytics_event_hal_assoc_device OOB check (OneWifi source/apps/analytics/wifi_analytics.c).
//	run_all_tests_analytics_event_hal_assoc_device();

	// analytics_event_hal_disassoc_device OOB check (OneWifi source/apps/analytics/wifi_analytics.c).
//	run_all_tests_analytics_event_hal_disassoc_device();

	// analytics_event_hal_scan_results OOB check (OneWifi source/apps/analytics/wifi_analytics.c).
//	run_all_tests_analytics_event_hal_scan_results();

	// analytics_event_hal_channel_change OOB check (OneWifi source/apps/analytics/wifi_analytics.c).
//	run_all_tests_analytics_event_hal_channel_change();
	return 0;
}
