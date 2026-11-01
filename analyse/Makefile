CXX = g++

SRC = main.cpp handle_topology_response.cpp handle_channel_scan_req.cpp handle_channel_scan_req_em_mes.cpp handle_channel_scan_req_test.cpp  supported_service.cpp supported_service_test.cpp construct_supported_service.cpp handle_ap_operational_bss.cpp construct_ap_operational_bss.cpp ap_operational_bss_test.cpp handle_unassoc_sta_link_metrics_tlv.cpp construct_unassoc_sta_link_metrics_tlv.cpp construct_handle_channel_scan_req_test.cpp bsta_test.cpp bsta.cpp common_test.cpp construct_test.cpp get_first_tlv_test.cpp get_first_tlv.cpp get_next_tlv_test.cpp get_next_tlv.cpp handle_ap_metrics_response.cpp em_mes.cpp process.cpp bsta_gft_gnt_construct.cpp construct_ap_metrics_test.cpp handle_channel_scan_rprt.cpp base64_decode.cpp construct_base64_decode.cpp base64_decode_test.cpp base64_encode.cpp construct_base64_encode.cpp base64_encode_test.cpp cmd_log.cpp construct_cmd_log.cpp cmd_log_test.cpp file_get.cpp construct_file_get.cpp file_get_test.cpp mon_check_process.cpp construct_mon_check_process.cpp mon_check_process_test.cpp mon_sig_crash.cpp construct_mon_sig_crash.cpp mon_sig_crash_test.cpp mon_sig_forward.cpp construct_mon_sig_forward.cpp mon_sig_forward_test.cpp mon_sig_str.cpp construct_mon_sig_str.cpp mon_sig_str_test.cpp os_cmd_exec_xv.cpp construct_os_cmd_exec_xv.cpp os_cmd_exec_xv_test.cpp os_pid_from_file.cpp construct_os_pid_from_file.cpp os_pid_from_file_test.cpp os_popen.cpp construct_os_popen.cpp os_popen_test.cpp parse_uri.cpp construct_parse_uri.cpp parse_uri_test.cpp strexread.cpp construct_strexread.cpp strexread_test.cpp unii_5g_chan2list.cpp construct_unii_5g_chan2list.cpp unii_5g_chan2list_test.cpp devinfo_get_inet_iface_config.cpp construct_devinfo_get_inet_iface_config.cpp devinfo_get_inet_iface_config_test.cpp dpp_mac_str_tmp.cpp construct_dpp_mac_str_tmp.cpp dpp_mac_str_tmp_test.cpp osp_unit_dhcpc_hostname_get.cpp construct_osp_unit_dhcpc_hostname_get.cpp osp_unit_dhcpc_hostname_get_test.cpp radio_get_name_from_cfg.cpp construct_radio_get_name_from_cfg.cpp radio_get_name_from_cfg_test.cpp ds_tree_check_r.cpp construct_ds_tree_check_r.cpp ds_tree_check_r_test.cpp ds_tree_graphviz_r.cpp construct_ds_tree_graphviz_r.cpp ds_tree_graphviz_r_test.cpp ds_tree_node_str.cpp construct_ds_tree_node_str.cpp ds_tree_node_str_test.cpp log_dynamic_full_path_get.cpp construct_log_dynamic_full_path_get.cpp log_dynamic_full_path_get_test.cpp log_dynamic_state_handler.cpp construct_log_dynamic_state_handler.cpp log_dynamic_state_handler_test.cpp log_dynamic_update.cpp construct_log_dynamic_update.cpp log_dynamic_update_test.cpp log_meminfo.cpp construct_log_meminfo.cpp log_meminfo_test.cpp log_severity_parse_sink.cpp construct_log_severity_parse_sink.cpp log_severity_parse_sink_test.cpp logger_remote_log.cpp construct_logger_remote_log.cpp logger_remote_log_test.cpp logger_traceback_log.cpp construct_logger_traceback_log.cpp logger_traceback_log_test.cpp mlog.cpp construct_mlog.cpp mlog_test.cpp os_file_open.cpp construct_os_file_open.cpp os_file_open_test.cpp os_name_to_pid.cpp construct_os_name_to_pid.cpp os_name_to_pid_test.cpp os_nif_gateway_del.cpp construct_os_nif_gateway_del.cpp os_nif_gateway_del_test.cpp
#SRC = handle_ap_metrics_response.cpp handle_ap_metrics_response_test.cpp
OUT = main

all: run wireshark

# -fpermissive: base64_decode.cpp keeps the verbatim char base64_table[64]
# initialised from a 64-char literal (no NUL); C++ makes that a hard error,
# so this downgrades it to a warning. No source is changed.
$(OUT): $(SRC)

	$(CXX) $(SRC) -o $(OUT) -fsanitize=address -g -O0 -Wall -fpermissive

run: $(OUT)

	./$(OUT)

wireshark:

# Upstream gtest file, built with the stand-in headers in gtest_shim/
# Needs gtest once: sudo apt install libgtest-dev
GTEST_SRC = test_l1_em_configuration.cpp $(filter-out main.cpp,$(SRC))
GTEST_OUT = gtest_main

gtest: $(GTEST_SRC)

	$(CXX) -Igtest_shim $(GTEST_SRC) -o $(GTEST_OUT) -fsanitize=address -g -O0 -Wall -lgtest -lgtest_main -pthread
	./$(GTEST_OUT)

# New get_radio_id() gtest cases for upstream tests/test_l1_em_msg.cpp (PR #818)
GTEST_MSG_SRC = test_l1_em_msg.cpp $(filter-out main.cpp,$(SRC))
GTEST_MSG_OUT = gtest_em_msg

gtest_em_msg: $(GTEST_MSG_SRC)

	$(CXX) -Igtest_shim $(GTEST_MSG_SRC) -o $(GTEST_MSG_OUT) -fsanitize=address -g -O0 -Wall -lgtest -lgtest_main -pthread
	./$(GTEST_MSG_OUT)

clean:

	rm -f $(OUT) $(GTEST_OUT) $(GTEST_MSG_OUT) a.out
