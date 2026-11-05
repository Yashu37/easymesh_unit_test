/*
 * UNIT TEST (input constructor): construct_hal_ipc_RMBeaconReportEvent
 *
 * hal_ipc_RMBeaconReportEvent(apIndex, out_struct, out_array_size, out_DialogToken) is the RM beacon report notification
 * client: it fills the descriptor with ipc_client_notification_input (apIndex, *out_array_size, *out_DialogToken and a
 * malloc'd scratch buffer holding a copy of the wifi_BeaconReport_t) and sends it to the notification server with
 * rdk_hal_ipc_exec, which frees the scratch buffer once it is sent.
 *
 * The suite is a table of calls (apIndex, NULL arguments, the array size and dialog token values, the failure point of
 * the socket layer, a failing node creation); the runner (hal_ipc_RMBeaconReportEvent_test.cpp) owns the descriptor, the
 * node, the report, the size and token variables and the "sent" buffer in slabs whose tails it POISONS, calls the
 * function, unpoisons and checks the result, the log, that nothing stays allocated, and the bytes that were sent
 * (descriptor apIndex / out_array_size / out_DialogToken / len, scratch buffer = the report).
 * Inputs crossed: valid calls with apIndex 0 / 1 / 15 / INT_MAX / UINT_MAX, out_array_size 0 / 1 / 16 / UINT_MAX,
 * dialog token 0 / 1 / 0xFF, NULL out_struct / out_array_size / out_DialogToken / all, every failure point of
 * rdk_hal_ipc_exec (socket, bind, both setsockopt, connect, descriptor send, scratch send), a failing node creation,
 * repeated calls and the log lines.  rdk_hal_ipc_exec carries the fix of tracker #78 (see the handler), so a FAIL is a
 * new finding.
 */
#include <limits.h>
#include <errno.h>
#include "hwr_rmb.h"

hwr_rmb_world_t hwr_rmb_world;

/* ---- stubs the handler redirects to ---- */
extern "C" void *hwr_rmb_malloc(size_t n)
{
	void *p = malloc(n);
	if (p && hwr_rmb_world.live < 8) { hwr_rmb_world.live_ptrs[hwr_rmb_world.live++] = p; hwr_rmb_world.live_bytes += n; }
	return p;
}
extern "C" void hwr_rmb_free(void *p)
{
	if (!p) return;
	for (int i = 0; i < hwr_rmb_world.live; i++) if (hwr_rmb_world.live_ptrs[i] == p) { hwr_rmb_world.live_ptrs[i] = hwr_rmb_world.live_ptrs[--hwr_rmb_world.live]; break; }
	free(p);
}
extern "C" hal_ipc_processor_desc_t *hwr_rmb_get_processor_desc(hal_ipc_desc_type_t type)
{
	(void)type;
	return hwr_rmb_world.desc;
}
extern "C" hal_ipc_node_t *hwr_rmb_create_node(hal_ipc_node_type_t type)
{
	if (hwr_rmb_world.node_fail) return NULL;
	hwr_rmb_world.node->type = type;
	strcpy(hwr_rmb_world.node->node_path, "/tmp/hal_notification_client");
	return hwr_rmb_world.node;
}
extern "C" int hwr_rmb_socket(int d, int t, int p)  { (void)d; (void)t; (void)p; hwr_rmb_world.sockets++; if (hwr_rmb_world.fail_at == 1) { errno = ENOMEM; return -1; } return 42; }
extern "C" int hwr_rmb_bind(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_rmb_world.fail_at == 2) { errno = EADDRINUSE; return -1; } return 0; }
extern "C" int hwr_rmb_setsockopt(int fd, int lv, int on, const void *v, socklen_t l)
{
	(void)fd; (void)lv; (void)on; (void)v; (void)l;
	hwr_rmb_world.setsockopts++;
	if ((hwr_rmb_world.fail_at == 3 && hwr_rmb_world.setsockopts == 1) || (hwr_rmb_world.fail_at == 4 && hwr_rmb_world.setsockopts == 2)) { errno = ENOBUFS; return -1; }
	return 0;
}
extern "C" int hwr_rmb_connect(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_rmb_world.fail_at == 5) { errno = ECONNREFUSED; return -1; } return 0; }
extern "C" ssize_t hwr_rmb_send(int fd, const void *buf, size_t len, int flags)
{
	(void)fd; (void)flags;
	hwr_rmb_world.send_calls++;
	int scratch_phase = hwr_rmb_world.sent_total >= sizeof(hal_ipc_processor_desc_t);
	if ((hwr_rmb_world.fail_at == 6 && !scratch_phase) || (hwr_rmb_world.fail_at == 7 && scratch_phase)) { errno = EPIPE; return -1; }
	if (hwr_rmb_world.sent_total + len > HWR_RMB_SENT_CAP) len = HWR_RMB_SENT_CAP - hwr_rmb_world.sent_total;
	memcpy(hwr_rmb_world.sent + hwr_rmb_world.sent_total, buf, len);                 /* reads the caller's buffer: an over-read aborts */
	hwr_rmb_world.sent_total += len;
	return (ssize_t)len;
}
extern "C" int hwr_rmb_close(int fd) { (void)fd; return 0; }
extern "C" int hwr_rmb_unlink(const char *p) { (void)p; return 0; }

/* name, ap, null_struct, null_size, null_token, array_size, token, fail_at, node_fail, calls, check_log, expected_ret, forked */
hwr_rmb_case_t hal_ipc_RMBeaconReportEvent_suite[] = {
	/* ---- valid calls: sent descriptor + scratch buffer, nothing left allocated ---- */
	{ "ok_basic",                         0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_ap_index_1",                    1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_ap_index_15",                  15, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_ap_index_int_max",        INT_MAX, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_ap_index_uint_max",      UINT_MAX, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_array_size_0",                  2, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_array_size_16",                 2, 0, 0, 0, 16, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_array_size_uint_max",           2, 0, 0, 0, UINT_MAX, 1, 0, 0, 1, 0, 0, 0 },
	{ "ok_dialog_token_0_autonomous",     2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 },
	{ "ok_dialog_token_0xff",             2, 0, 0, 0, 1, 0xFF, 0, 0, 1, 0, 0, 0 },
	{ "ok_repeated_calls_x3",             3, 0, 0, 0, 1, 1, 0, 0, 3, 0, 0, 0 },
	{ "ok_logs_ap_index_line",            4, 0, 0, 0, 1, 1, 0, 0, 1, 4, 0, 0 },
	/* ---- NULL arguments: rejected before anything is allocated or sent ---- */
	{ "out_struct_null",                  0, 1, 0, 0, 1, 1, 0, 0, 1, 0, -1, 0 },
	{ "out_array_size_null",              0, 0, 1, 0, 1, 1, 0, 0, 1, 0, -1, 0 },
	{ "out_dialog_token_null",            0, 0, 0, 1, 1, 1, 0, 0, 1, 0, -1, 0 },
	{ "all_pointers_null",                0, 1, 1, 1, 1, 1, 0, 0, 1, 0, -1, 0 },
	{ "out_struct_null_logs_input_failed", 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, -1, 0 },
	/* ---- failures of rdk_hal_ipc_exec: -1 and the scratch buffer must not stay allocated ---- */
	{ "exec_fail_socket",                 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, -1, 0 },
	{ "exec_fail_bind",                   0, 0, 0, 0, 1, 1, 2, 0, 1, 0, -1, 0 },
	{ "exec_fail_setsockopt_rcvbuf",      0, 0, 0, 0, 1, 1, 3, 0, 1, 0, -1, 0 },
	{ "exec_fail_setsockopt_sndbuf",      0, 0, 0, 0, 1, 1, 4, 0, 1, 0, -1, 0 },
	{ "exec_fail_connect_server_down",    0, 0, 0, 0, 1, 1, 5, 0, 1, 0, -1, 0 },
	{ "exec_fail_send_descriptor",        0, 0, 0, 0, 1, 1, 6, 0, 1, 0, -1, 0 },
	{ "exec_fail_send_scratch",           0, 0, 0, 0, 1, 1, 7, 0, 1, 0, -1, 0 },
	{ "exec_fail_connect_repeated_x3",    0, 0, 0, 0, 1, 1, 5, 0, 3, 0, -1, 0 },
	{ "exec_fail_logs_ipc_processor_failed", 0, 0, 0, 0, 1, 1, 5, 0, 1, 2, -1, 0 },
	/* ---- node creation ---- */
	{ "node_create_fails",                0, 0, 0, 0, 1, 1, 0, 1, 1, 3, -1, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
