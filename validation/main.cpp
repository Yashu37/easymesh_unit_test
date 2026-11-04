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
	run_all_tests_hal_ipc_server_get_ap_assoc_dev_diag_res3_callback();

	return 0;
}
