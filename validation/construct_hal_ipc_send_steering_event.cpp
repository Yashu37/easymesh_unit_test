/*
 * UNIT TEST (input constructor): construct_hal_ipc_send_steering_event
 *
 * hal_ipc_send_steering_event(steeringgroupIndex, event) is the steering event callback: it fills the descriptor with
 * ipc_client_notification_input (steering group index and a copy of the wifi_steering_event_t), logs the event and
 * sends it to the notification server with rdk_hal_ipc_exec.  It returns void; there is no scratch buffer.
 *
 * The suite is a table of calls (group index, event type / apIndex / timestamp, NULL event, the failure point of the
 * socket layer, a failing node creation); the runner (hal_ipc_send_steering_event_test.cpp) owns the descriptor, the node,
 * the event and the "sent" buffer in slabs whose tails it POISONS, calls the function, unpoisons and checks whether the
 * event was sent (bytes seen by the stubbed send()), the log, that nothing stays allocated and the bytes that were
 * sent (descriptor steering_group_index / len, the event byte for byte).
 * Inputs crossed: group index 0 / 1 / 15 / INT_MAX / UINT_MAX, every steering event type 0..8 and an out-of-range type,
 * apIndex 0 / -1 / INT_MAX, timestamps 0 / 1 / ULLONG_MAX, a NULL event, every failure point of rdk_hal_ipc_exec, a
 * failing node creation, repeated calls and the log lines.  Expected result is the SAFE contract (a NULL event is not
 * dereferenced, nothing leaked), so a FAIL is a finding.
 */
#include <limits.h>
#include <errno.h>
#include "hwr_sse.h"

hwr_sse_world_t hwr_sse_world;

/* ---- stubs the handler redirects to ---- */
extern "C" void *hwr_sse_malloc(size_t n)
{
	void *p = malloc(n);
	if (p && hwr_sse_world.live < 8) { hwr_sse_world.live_ptrs[hwr_sse_world.live++] = p; hwr_sse_world.live_bytes += n; }
	return p;
}
extern "C" void hwr_sse_free(void *p)
{
	if (!p) return;
	for (int i = 0; i < hwr_sse_world.live; i++) if (hwr_sse_world.live_ptrs[i] == p) { hwr_sse_world.live_ptrs[i] = hwr_sse_world.live_ptrs[--hwr_sse_world.live]; break; }
	free(p);
}
extern "C" hal_ipc_processor_desc_t *hwr_sse_get_processor_desc(hal_ipc_desc_type_t type)
{
	(void)type;
	return hwr_sse_world.desc;
}
extern "C" hal_ipc_node_t *hwr_sse_create_node(hal_ipc_node_type_t type)
{
	if (hwr_sse_world.node_fail) return NULL;
	hwr_sse_world.node->type = type;
	strcpy(hwr_sse_world.node->node_path, "/tmp/hal_notification_client");
	return hwr_sse_world.node;
}
extern "C" int hwr_sse_socket(int d, int t, int p)  { (void)d; (void)t; (void)p; hwr_sse_world.sockets++; if (hwr_sse_world.fail_at == 1) { errno = ENOMEM; return -1; } return 42; }
extern "C" int hwr_sse_bind(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_sse_world.fail_at == 2) { errno = EADDRINUSE; return -1; } return 0; }
extern "C" int hwr_sse_setsockopt(int fd, int lv, int on, const void *v, socklen_t l)
{
	(void)fd; (void)lv; (void)on; (void)v; (void)l;
	hwr_sse_world.setsockopts++;
	if ((hwr_sse_world.fail_at == 3 && hwr_sse_world.setsockopts == 1) || (hwr_sse_world.fail_at == 4 && hwr_sse_world.setsockopts == 2)) { errno = ENOBUFS; return -1; }
	return 0;
}
extern "C" int hwr_sse_connect(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_sse_world.fail_at == 5) { errno = ECONNREFUSED; return -1; } return 0; }
extern "C" ssize_t hwr_sse_send(int fd, const void *buf, size_t len, int flags)
{
	(void)fd; (void)flags;
	hwr_sse_world.send_calls++;
	int scratch_phase = hwr_sse_world.sent_total >= sizeof(hal_ipc_processor_desc_t);
	if (hwr_sse_world.fail_at == 6 && !scratch_phase) { errno = EPIPE; return -1; }
	if (hwr_sse_world.sent_total + len > HWR_SSE_SENT_CAP) len = HWR_SSE_SENT_CAP - hwr_sse_world.sent_total;
	memcpy(hwr_sse_world.sent + hwr_sse_world.sent_total, buf, len);                 /* reads the caller's buffer: an over-read aborts */
	hwr_sse_world.sent_total += len;
	return (ssize_t)len;
}
extern "C" int hwr_sse_close(int fd) { (void)fd; return 0; }
extern "C" int hwr_sse_unlink(const char *p) { (void)p; return 0; }

/* name, group, null_event, ev_type, ev_ap, ev_ts, fail_at, node_fail, calls, check_log, expected_ret */
hwr_sse_case_t hal_ipc_send_steering_event_suite[] = {
	/* ---- valid calls: the event reaches the server unchanged ---- */
	{ "ok_basic",                         0, 0, 1, 0, 1000, 0, 0, 1, 0, 0 },
	{ "ok_group_1",                       1, 0, 1, 0, 1000, 0, 0, 1, 0, 0 },
	{ "ok_group_15",                     15, 0, 1, 0, 1000, 0, 0, 1, 0, 0 },
	{ "ok_group_int_max",           INT_MAX, 0, 1, 0, 1000, 0, 0, 1, 0, 0 },
	{ "ok_group_uint_max",         UINT_MAX, 0, 1, 0, 1000, 0, 0, 1, 0, 0 },
	{ "ok_event_type_0",                  2, 0, 0, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_1",                  2, 0, 1, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_2",                  2, 0, 2, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_3",                  2, 0, 3, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_4",                  2, 0, 4, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_5",                  2, 0, 5, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_6",                  2, 0, 6, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_7",                  2, 0, 7, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_8",                  2, 0, 8, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_type_out_of_range_0xff",  2, 0, 0xFF, 1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_ap_index_minus_1",        2, 0, 1, -1, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_ap_index_int_max",        2, 0, 1, INT_MAX, 1, 0, 0, 1, 0, 0 },
	{ "ok_event_timestamp_0",             2, 0, 1, 1, 0, 0, 0, 1, 0, 0 },
	{ "ok_event_timestamp_ullong_max",    2, 0, 1, 1, ULLONG_MAX, 0, 0, 1, 0, 0 },
	{ "ok_repeated_calls_x3",             3, 0, 2, 1, 5, 0, 0, 3, 0, 0 },
	{ "ok_logs_steering_event_line",      4, 0, 3, 7, 5, 0, 0, 1, 4, 0 },
	/* ---- NULL event: rejected by the processor, the logging that follows must not dereference it ---- */
	{ "event_null",                       0, 1, 1, 0, 0, 0, 0, 1, 0, -1 },
	{ "event_null_logs_input_failed",     0, 1, 1, 0, 0, 0, 0, 1, 1, -1 },
	{ "event_null_repeated_x3",           5, 1, 1, 0, 0, 0, 0, 3, 0, -1 },
	/* ---- failures of rdk_hal_ipc_exec: nothing sent, nothing allocated ---- */
	{ "exec_fail_socket",                 0, 0, 1, 0, 1, 1, 0, 1, 0, -1 },
	{ "exec_fail_bind",                   0, 0, 1, 0, 1, 2, 0, 1, 0, -1 },
	{ "exec_fail_setsockopt_rcvbuf",      0, 0, 1, 0, 1, 3, 0, 1, 0, -1 },
	{ "exec_fail_setsockopt_sndbuf",      0, 0, 1, 0, 1, 4, 0, 1, 0, -1 },
	{ "exec_fail_connect_server_down",    0, 0, 1, 0, 1, 5, 0, 1, 0, -1 },
	{ "exec_fail_send_descriptor",        0, 0, 1, 0, 1, 6, 0, 1, 0, -1 },
	{ "exec_fail_connect_repeated_x3",    0, 0, 1, 0, 1, 5, 0, 3, 0, -1 },
	{ "exec_fail_logs_ipc_processor_failed", 0, 0, 1, 0, 1, 5, 0, 1, 2, -1 },
	/* ---- node creation ---- */
	{ "node_create_fails",                0, 0, 1, 0, 1, 0, 1, 1, 3, -1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
