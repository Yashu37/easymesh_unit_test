/*
 * UNIT TEST (input constructor): construct_hal_ipc_BTMResponseEvent
 *
 * hal_ipc_BTMResponseEvent(apIndex, peerMac, response) is the BTM-response notification client: it fills the
 * descriptor with ipc_client_notification_input (apIndex, the peer MAC parsed from the "xx:xx:xx:xx:xx:xx" string and
 * the wifi_BTMResponse_t) and sends it to the notification server with rdk_hal_ipc_exec.  There is no scratch buffer.
 *
 * The suite is a table of calls (apIndex, peerMac string, NULL arguments, the failure point of the socket layer, a
 * failing node creation); the runner (hal_ipc_BTMResponseEvent_test.cpp) owns the descriptor, the node, the response,
 * the MAC string and the "sent" buffer in slabs whose tails it POISONS, calls the function, unpoisons and checks the
 * result, the log, that nothing stays allocated, and the bytes that were sent (descriptor apIndex / len / peer MAC /
 * response).
 * Inputs crossed: valid calls with apIndex 0 / 1 / 15 / INT_MAX / UINT_MAX, peer MACs in lower / upper case, digits,
 * all-zero, all-ff and multicast form (compared byte by byte, also strings longer than 17 characters), NULL peerMac /
 * response / both, malformed peer MAC strings (letters, too few octets, no separators, strings shorter than 6 bytes),
 * every failure point of rdk_hal_ipc_exec, a failing node creation, repeated calls and the log lines.
 * The processor case is the one fixed by tracker #25-#27 (see the handler), so this harness checks the wrapper and
 * its chain against the SAFE contract: a FAIL would be a new finding.
 */
#include <limits.h>
#include <errno.h>
#include "hwr_bre.h"

hwr_bre_world_t hwr_bre_world;

/* ---- stubs the handler redirects to ---- */
extern "C" void *hwr_bre_malloc(size_t n)
{
	void *p = malloc(n);
	if (p && hwr_bre_world.live < 8) { hwr_bre_world.live_ptrs[hwr_bre_world.live++] = p; hwr_bre_world.live_bytes += n; }
	return p;
}
extern "C" void hwr_bre_free(void *p)
{
	if (!p) return;
	for (int i = 0; i < hwr_bre_world.live; i++) if (hwr_bre_world.live_ptrs[i] == p) { hwr_bre_world.live_ptrs[i] = hwr_bre_world.live_ptrs[--hwr_bre_world.live]; break; }
	free(p);
}
extern "C" hal_ipc_processor_desc_t *hwr_bre_get_processor_desc(hal_ipc_desc_type_t type)
{
	(void)type;
	return hwr_bre_world.desc;
}
extern "C" hal_ipc_node_t *hwr_bre_create_node(hal_ipc_node_type_t type)
{
	if (hwr_bre_world.node_fail) return NULL;
	hwr_bre_world.node->type = type;
	strcpy(hwr_bre_world.node->node_path, "/tmp/hal_notification_client");
	return hwr_bre_world.node;
}
extern "C" int hwr_bre_socket(int d, int t, int p)  { (void)d; (void)t; (void)p; hwr_bre_world.sockets++; if (hwr_bre_world.fail_at == 1) { errno = ENOMEM; return -1; } return 42; }
extern "C" int hwr_bre_bind(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_bre_world.fail_at == 2) { errno = EADDRINUSE; return -1; } return 0; }
extern "C" int hwr_bre_setsockopt(int fd, int lv, int on, const void *v, socklen_t l)
{
	(void)fd; (void)lv; (void)on; (void)v; (void)l;
	hwr_bre_world.setsockopts++;
	if ((hwr_bre_world.fail_at == 3 && hwr_bre_world.setsockopts == 1) || (hwr_bre_world.fail_at == 4 && hwr_bre_world.setsockopts == 2)) { errno = ENOBUFS; return -1; }
	return 0;
}
extern "C" int hwr_bre_connect(int fd, const struct sockaddr *a, socklen_t l)  { (void)fd; (void)a; (void)l; if (hwr_bre_world.fail_at == 5) { errno = ECONNREFUSED; return -1; } return 0; }
extern "C" ssize_t hwr_bre_send(int fd, const void *buf, size_t len, int flags)
{
	(void)fd; (void)flags;
	hwr_bre_world.send_calls++;
	int scratch_phase = hwr_bre_world.sent_total >= sizeof(hal_ipc_processor_desc_t);
	if (hwr_bre_world.fail_at == 6 && !scratch_phase) { errno = EPIPE; return -1; }
	if (hwr_bre_world.sent_total + len > HWR_BRE_SENT_CAP) len = HWR_BRE_SENT_CAP - hwr_bre_world.sent_total;
	memcpy(hwr_bre_world.sent + hwr_bre_world.sent_total, buf, len);                 /* reads the caller's buffer: an over-read aborts */
	hwr_bre_world.sent_total += len;
	return (ssize_t)len;
}
extern "C" int hwr_bre_close(int fd) { (void)fd; return 0; }
extern "C" int hwr_bre_unlink(const char *p) { (void)p; return 0; }

/* name, ap, mac, null_response, fail_at, node_fail, calls, check_log, expected_ret, exp_mac, forked */
#define OKMAC "aa:bb:cc:dd:ee:ff"
hwr_bre_case_t hal_ipc_BTMResponseEvent_suite[] = {
	/* ---- valid calls ---- */
	{ "ok_basic",                         0, OKMAC, 0, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_1",                    1, OKMAC, 0, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_15",                  15, OKMAC, 0, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_int_max",        INT_MAX, OKMAC, 0, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_ap_index_uint_max",      UINT_MAX, OKMAC, 0, 0, 0, 1, 0, 0, NULL, 0 },
	{ "ok_repeated_calls_x3",             3, OKMAC, 0, 0, 0, 3, 0, 0, NULL, 0 },
	{ "ok_logs_ap_index_line",            4, OKMAC, 0, 0, 0, 1, 4, 0, NULL, 0 },
	/* ---- the peer MAC string must reach the server as the 6 MAC bytes ---- */
	{ "mac_lowercase",                    0, "aa:bb:cc:dd:ee:ff", 0, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	{ "mac_uppercase",                    0, "AA:BB:CC:DD:EE:FF", 0, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	{ "mac_digits",                       0, "01:23:45:67:89:ab", 0, 0, 0, 1, 0, 0, "0123456789ab", 0 },
	{ "mac_all_zero",                     0, "00:00:00:00:00:00", 0, 0, 0, 1, 0, 0, "000000000000", 0 },
	{ "mac_all_ff",                       0, "ff:ff:ff:ff:ff:ff", 0, 0, 0, 1, 0, 0, "ffffffffffff", 0 },
	{ "mac_multicast_form",               0, "01:00:5e:00:00:fb", 0, 0, 0, 1, 0, 0, "01005e0000fb", 0 },
	{ "mac_string_longer_than_17_chars",  0, "aa:bb:cc:dd:ee:ff:00:11", 0, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	{ "mac_string_41_chars_read_bounded", 0, "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77", 0, 0, 0, 1, 0, 0, "aabbccddeeff", 0 },
	/* ---- NULL arguments ---- */
	{ "peer_mac_null",                    0, NULL, 0, 0, 0, 1, 0, -1, NULL, 0 },
	{ "response_null",                    0, OKMAC, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "all_pointers_null",                0, NULL, 1, 0, 0, 1, 0, -1, NULL, 0 },
	{ "response_null_logs_input_failed",  0, OKMAC, 1, 0, 0, 1, 1, -1, NULL, 0 },
	/* ---- malformed peer MAC strings: rejected, nothing sent, no over-read ---- */
	{ "mac_malformed_letters",            0, "zz:zz:zz:zz:zz:zz", 0, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_malformed_logs_invalid_mac",   0, "zz:zz:zz:zz:zz:zz", 0, 0, 0, 1, 5, -1, NULL, 0 },
	{ "mac_too_few_octets",               0, "aa:bb:cc:dd:ee", 0, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_no_separators",                0, "aabbccddeeff", 0, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_empty_string",                 0, "", 0, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_two_chars",                    0, "ab", 0, 0, 0, 1, 0, -1, NULL, 0 },
	{ "mac_four_chars",                   0, "aa:b", 0, 0, 0, 1, 0, -1, NULL, 0 },
	/* ---- failures of rdk_hal_ipc_exec: -1, nothing allocated ---- */
	{ "exec_fail_socket",                 0, OKMAC, 0, 1, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_bind",                   0, OKMAC, 0, 2, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_setsockopt_rcvbuf",      0, OKMAC, 0, 3, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_setsockopt_sndbuf",      0, OKMAC, 0, 4, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_connect_server_down",    0, OKMAC, 0, 5, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_send_descriptor",        0, OKMAC, 0, 6, 0, 1, 0, -1, NULL, 0 },
	{ "exec_fail_connect_repeated_x3",    0, OKMAC, 0, 5, 0, 3, 0, -1, NULL, 0 },
	{ "exec_fail_logs_ipc_processor_failed", 0, OKMAC, 0, 5, 0, 1, 2, -1, NULL, 0 },
	/* ---- node creation ---- */
	{ "node_create_fails",                0, OKMAC, 0, 0, 1, 1, 3, -1, NULL, 0 },
	{ NULL, 0, NULL, 0, 0, 0, 0, 0, 0, NULL, 0 }
};
