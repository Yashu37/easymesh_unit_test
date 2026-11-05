/*
 * UNIT TEST (input constructor): construct_hal_ipc_BTMQueryRequestEvent
 *
 * hal_ipc_BTMQueryRequestEvent(apIndex, peerMac, query, inMemSize, request) is the BTM-query notification client:
 * it fills the descriptor with ipc_client_notification_input (apIndex, peer MAC, inMemSize and a malloc'd scratch
 * buffer holding the wifi_BTMQuery_t followed by the wifi_BTMRequest_t) and sends it to the notification server
 * with rdk_hal_ipc_exec, which frees the scratch buffer once it is sent.  peerMac is a CHAR * - the caller
 * (wifi_hal_wnm_rrm.c, non-PHASE2 build) passes a "xx:xx:xx:xx:xx:xx" string.
 *
 * The suite is a table of calls (apIndex, peerMac string, NULL arguments, inMemSize, the failure point of the
 * socket layer, a failing node creation); the runner (hal_ipc_BTMQueryRequestEvent_test.cpp) owns the descriptor,
 * the node, the input structures, the MAC string and the "sent" buffer in slabs whose tails it POISONS, calls the
 * function, unpoisons and checks the result, the log, that nothing stays allocated, and the bytes that were sent
 * (descriptor fields, peer MAC, scratch buffer = query || request).
 * Inputs crossed: valid calls with apIndex 0 / 1 / 15 / INT_MAX / UINT_MAX and inMemSize 0 / 1234 / UINT_MAX,
 * peer MACs in lower / upper case, digits, all-zero, all-ff and multicast form (compared byte by byte, also with strings longer than 17 characters), NULL
 * peerMac / query / request / all NULL, malformed peer MAC strings (letters, too few octets, no separators,
 * strings shorter than 6 bytes = over-read, forked), every failure point of rdk_hal_ipc_exec (socket, bind, both
 * setsockopt, connect, descriptor send, scratch send), a failing node creation, repeated calls and the log lines.
 * Expected result is the SAFE contract (wrong / malformed MAC rejected, nothing leaked on any failure), so a FAIL is
 * a finding.
 */
#include <limits.h>
#include <errno.h>
#include "hwr_bqe.h"

hwr_bqe_world_t hwr_bqe_world;

/* ---- stubs the handler redirects to ---- */
extern "C" void *hwr_bqe_malloc(size_t n)
{
	void *p = malloc(n);
	if (p && hwr_bqe_world.live < 8) { hwr_bqe_world.live_ptrs[hwr_bqe_world.live++] = p; hwr_bqe_world.live_bytes += n; }
	return p;
}
extern "C" void hwr_bqe_free(void *p)
{
	if (!p) return;
	for (int i = 0; i < hwr_bqe_world.live; i++) if (hwr_bqe_world.live_ptrs[i] == p) { hwr_bqe_world.live_ptrs[i] = hwr_bqe_world.live_ptrs[--hwr_bqe_world.live]; break; }
	free(p);
}
extern "C" hal_ipc_processor_desc_t *hwr_bqe_get_processor_desc(hal_ipc_desc_type_t type)
{
	(void)type;
	return hwr_bqe_world.desc;
}
extern "C" hal_ipc_node_t *hwr_bqe_create_node(hal_ipc_node_type_t type)
{
	if (hwr_bqe_world.node_fail) return NULL;
	hwr_bqe_world.node->type = type;
	strcpy(hwr_bqe_world.node->node_path, "/tmp/hal_notification_client");
	return hwr_bqe_world.node;
}
extern "C" int hwr_bqe_socket(int d, int t, int p)  { (void)d; (void)t; (void)p; hwr_bqe_world.sockets++; if (hwr_bqe_world.fail_at == 1) { errno = ENOMEM; return -1; } return 42; }
extern "C" int hwr_bqe_bind(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_bqe_world.fail_at == 2) { errno = EADDRINUSE; return -1; } return 0; }
extern "C" int hwr_bqe_setsockopt(int fd, int lv, int on, const void *v, socklen_t l)
{
	(void)fd; (void)lv; (void)on; (void)v; (void)l;
	hwr_bqe_world.setsockopts++;
	if ((hwr_bqe_world.fail_at == 3 && hwr_bqe_world.setsockopts == 1) || (hwr_bqe_world.fail_at == 4 && hwr_bqe_world.setsockopts == 2)) { errno = ENOBUFS; return -1; }
	return 0;
}
extern "C" int hwr_bqe_connect(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_bqe_world.fail_at == 5) { errno = ECONNREFUSED; return -1; } return 0; }
extern "C" ssize_t hwr_bqe_send(int fd, const void *buf, size_t len, int flags)
{
	(void)fd; (void)flags;
	hwr_bqe_world.send_calls++;
	int scratch_phase = hwr_bqe_world.sent_total >= sizeof(hal_ipc_processor_desc_t);
	if ((hwr_bqe_world.fail_at == 6 && !scratch_phase) || (hwr_bqe_world.fail_at == 7 && scratch_phase)) { errno = EPIPE; return -1; }
	if (hwr_bqe_world.sent_total + len > HWR_BQE_SENT_CAP) len = HWR_BQE_SENT_CAP - hwr_bqe_world.sent_total;
	memcpy(hwr_bqe_world.sent + hwr_bqe_world.sent_total, buf, len);                 /* reads the caller's buffer: an over-read aborts */
	hwr_bqe_world.sent_total += len;
	return (ssize_t)len;
}
extern "C" int hwr_bqe_close(int fd) { (void)fd; return 0; }
extern "C" int hwr_bqe_unlink(const char *p) { (void)p; return 0; }

/* name, ap, mac, null_query, null_request, in_mem_size, fail_at, node_fail, calls, check_log, expected_ret, exp_mac, forked */
#define OKMAC "aa:bb:cc:dd:ee:ff"
hwr_bqe_case_t hal_ipc_BTMQueryRequestEvent_suite[] = {
	/* ---- valid calls: sent descriptor + scratch buffer, nothing left allocated ---- */
	{ "ok_basic",                         0, OKMAC, 0, 0, 1234, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_1",                    1, OKMAC, 0, 0, 1234, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_15",                  15, OKMAC, 0, 0, 1234, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_int_max",        INT_MAX, OKMAC, 0, 0, 1234, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_uint_max",      UINT_MAX, OKMAC, 0, 0, 1234, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_in_mem_size_0",                 2, OKMAC, 0, 0, 0, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_in_mem_size_uint_max",          2, OKMAC, 0, 0, UINT_MAX, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_repeated_calls_x3",             3, OKMAC, 0, 0, 1234, 0, 0, 3, 0, 0, NULL, 0 },
	{ "ok_logs_ap_index_line",            4, OKMAC, 0, 0, 1234, 0, 0, 1, 4, 0, NULL, 0 },
	/* ---- the peer MAC string must reach the server as the 6 MAC bytes ---- */
	{ "mac_lowercase",                    0, "aa:bb:cc:dd:ee:ff", 0, 0, 1, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	{ "mac_uppercase",                    0, "AA:BB:CC:DD:EE:FF", 0, 0, 1, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	{ "mac_digits",                       0, "01:23:45:67:89:ab", 0, 0, 1, 0, 0, 1, 0, 0, "0123456789ab", 0 },
	{ "mac_all_zero",                     0, "00:00:00:00:00:00", 0, 0, 1, 0, 0, 1, 0, 0, "000000000000", 0 },
	{ "mac_all_ff",                       0, "ff:ff:ff:ff:ff:ff", 0, 0, 1, 0, 0, 1, 0, 0, "ffffffffffff", 0 },
	{ "mac_multicast_form",               0, "01:00:5e:00:00:fb", 0, 0, 1, 0, 0, 1, 0, 0, "01005e0000fb", 0 },
	{ "mac_string_longer_than_17_chars",  0, "aa:bb:cc:dd:ee:ff:00:11", 0, 0, 1, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	{ "mac_string_41_chars_read_bounded", 0, "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77", 0, 0, 1, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	/* ---- NULL arguments: rejected before anything is allocated or sent ---- */
	{ "peer_mac_null",                    0, NULL, 0, 0, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "query_null",                       0, OKMAC, 1, 0, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "request_null",                     0, OKMAC, 0, 1, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "all_pointers_null",                0, NULL, 1, 1, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "query_null_logs_input_failed",     0, OKMAC, 1, 0, 1, 0, 0, 1, 1, -1, NULL, 0 },
	/* ---- malformed peer MAC strings: rejected, not sent as garbage ---- */
	{ "mac_malformed_letters",            0, "zz:zz:zz:zz:zz:zz", 0, 0, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_too_few_octets",               0, "aa:bb:cc:dd:ee", 0, 0, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_no_separators",                0, "aabbccddeeff", 0, 0, 1, 0, 0, 1, 0, -1, NULL, 0 },
	/* ---- crash group (forked): a peer MAC string shorter than 6 bytes is read as 6 raw bytes ---- */
	{ "crash_mac_empty_string",           0, "", 0, 0, 1, 0, 0, 1, 0, -1, NULL, 1 },
	{ "crash_mac_two_chars",              0, "ab", 0, 0, 1, 0, 0, 1, 0, -1, NULL, 1 },
	{ "crash_mac_four_chars",             0, "aa:b", 0, 0, 1, 0, 0, 1, 0, -1, NULL, 1 },
	/* ---- failures of rdk_hal_ipc_exec: -1 and the scratch buffer must not stay allocated ---- */
	{ "exec_fail_socket",                 0, OKMAC, 0, 0, 1, 1, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_bind",                   0, OKMAC, 0, 0, 1, 2, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_setsockopt_rcvbuf",      0, OKMAC, 0, 0, 1, 3, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_setsockopt_sndbuf",      0, OKMAC, 0, 0, 1, 4, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_connect_server_down",    0, OKMAC, 0, 0, 1, 5, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_send_descriptor",        0, OKMAC, 0, 0, 1, 6, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_send_scratch",           0, OKMAC, 0, 0, 1, 7, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_connect_repeated_x3",    0, OKMAC, 0, 0, 1, 5, 0, 3, 0, -1, NULL, 0 },
	{ "exec_fail_logs_ipc_processor_failed", 0, OKMAC, 0, 0, 1, 5, 0, 1, 2, -1, NULL, 0 },
	/* ---- node creation ---- */
	{ "node_create_fails",                0, OKMAC, 0, 0, 1, 0, 1, 1, 3, -1, NULL, 0 },
	{ NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0 }
};
