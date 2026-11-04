#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

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
	run_all_tests_cleanup_desc_scratch_buf();

	return 0;
}
