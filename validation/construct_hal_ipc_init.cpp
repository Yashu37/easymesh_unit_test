/*
 * UNIT TEST (input constructor): construct_hal_ipc_init
 *
 * hal_ipc_init() registers the HAL IPC notification callbacks (steering event, RM beacon report and BTM query /
 * response for every AP index below MAX_AP_INDEX) and creates the notification client node and the sync-call server
 * node; it returns -1 when a node cannot be created and 0 otherwise.
 *
 * The suite is a table of "start states" (AP indexes whose RM beacon callback is already taken by another registrant,
 * steering / BTM callbacks already set, node creation failures, how many times hal_ipc_init is called) plus the
 * expected result of every call; the runner (hal_ipc_init_test.cpp) owns the callbacks structure in a slab whose tail
 * it POISONS, calls the function, unpoisons and checks the return values, the callbacks that are registered afterwards
 * (steering, every bcnrpt_callback[] and btm_callback[] entry, foreign registrations must not be overwritten), the
 * nodes created and the log.
 * Inputs crossed: a clean start, steering / BTM callbacks already set by another registrant (overwritten, still
 * success), an RM beacon callback already registered for the first / a middle / the last / every AP index (the
 * registration fails), a second and third call of hal_ipc_init (the beacon registrations fail), a failing
 * notification client node, a failing sync-call server node, both failing, and the log lines.
 * Expected result is the SAFE contract (a failed registration makes hal_ipc_init fail before any node - i.e. the
 * sync-call listener thread - is created), so a FAIL is a finding.
 */
#include "hwr_hin.h"

hwr_hin_rec_t hwr_hin_rec;
hal_ipc_node_t hwr_hin_nodes[hal_ipc_node_type_max];

extern "C" hal_ipc_node_t *hwr_hin_create_node(hal_ipc_node_type_t type)
{
	hwr_hin_rec.calls[type]++;
	if ((type == hal_ipc_node_type_notification_client && (hwr_hin_rec.fail_mask & 1)) ||
	    (type == hal_ipc_node_type_sync_call_server && (hwr_hin_rec.fail_mask & 2))) return NULL;
	hwr_hin_nodes[type].type = type;
	return &hwr_hin_nodes[type];
}

#define ALL 0x7FFFu
/* name, foreign_rm, foreign_steer, foreign_btm, node_fail, init_calls, expected_ret[3], clients, servers, check_log */
hwr_hin_case_t hal_ipc_init_suite[] = {
	/* ---- clean start ---- */
	{ "clean_start_registers_everything",     0, 0, 0, 0, 1, { 0, 0, 0 }, 1, 1, 0 },
	{ "steering_callback_already_set",        0, 1, 0, 0, 1, { 0, 0, 0 }, 1, 1, 0 },
	{ "btm_callbacks_already_set_all_aps",    0, 0, 1, 0, 1, { 0, 0, 0 }, 1, 1, 0 },
	{ "steering_and_btm_already_set",         0, 1, 1, 0, 1, { 0, 0, 0 }, 1, 1, 0 },
	/* ---- another registrant already owns an RM beacon callback: the registration fails, so must hal_ipc_init ---- */
	{ "rm_beacon_taken_ap_0",              0x1, 0, 0, 0, 1, { -1, 0, 0 }, 0, 0, 0 },
	{ "rm_beacon_taken_ap_7",             0x80, 0, 0, 0, 1, { -1, 0, 0 }, 0, 0, 0 },
	{ "rm_beacon_taken_last_ap_14",     0x4000, 0, 0, 0, 1, { -1, 0, 0 }, 0, 0, 0 },
	{ "rm_beacon_taken_ap_0_and_14",    0x4001, 0, 0, 0, 1, { -1, 0, 0 }, 0, 0, 0 },
	{ "rm_beacon_taken_every_ap",           ALL, 0, 0, 0, 1, { -1, 0, 0 }, 0, 0, 0 },
	{ "rm_beacon_taken_logs_failure",      0x8, 0, 0, 0, 1, { -1, 0, 0 }, 0, 0, 1 },
	{ "rm_beacon_taken_with_steering_set", 0x2, 1, 1, 0, 1, { -1, 0, 0 }, 0, 0, 0 },
	/* ---- hal_ipc_init called again: the beacon callbacks are already registered, no second listener thread ---- */
	{ "init_twice_second_call_fails",         0, 0, 0, 0, 2, { 0, -1, 0 }, 1, 1, 0 },
	{ "init_three_times_only_first_succeeds", 0, 0, 0, 0, 3, { 0, -1, -1 }, 1, 1, 0 },
	/* ---- node creation failures ---- */
	{ "notification_client_node_fails",       0, 0, 0, 1, 1, { -1, 0, 0 }, 1, 0, 2 },
	{ "sync_call_server_node_fails",          0, 0, 0, 2, 1, { -1, 0, 0 }, 1, 1, 3 },
	{ "both_nodes_fail",                      0, 0, 0, 3, 1, { -1, 0, 0 }, 1, 0, 0 },
	{ "node_failure_with_steering_set",       0, 1, 1, 2, 1, { -1, 0, 0 }, 1, 1, 0 },
	{ NULL, 0, 0, 0, 0, 0, { 0, 0, 0 }, 0, 0, 0 }
};
