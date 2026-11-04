/*
 * UNIT TEST (input constructor): construct_rdk_hal_ipc_exec
 *
 * rdk_hal_ipc_exec(p_ipc_node, desc) is the client side of the HAL IPC: it
 * binds a client AF_UNIX socket at p_ipc_node->node_path, connects to the
 * sync/notification server chosen by p_ipc_node->type, then sends the
 * descriptor (in chunks if sizeof(desc) > max_size) and, when desc->len >
 * sizeof(desc), the scratch buffer (and frees it).
 *
 * Inputs crossed here:
 * (capped at 50 cases: representative combinations, not the full cross product)
 *   node type  : the 3 client types, the 2 server types, hal_ipc_node_type_max, -1, 99
 *   fail point : none, socket, bind, SO_RCVBUF, SO_SNDBUF, connect,
 *                first send, scratch-phase send, short (1000-byte) sends
 *   desc shape : len 0 / == sizeof / sizeof+1 / +scratch 1000 / 25000 /
 *                exactly 10240 / 10241
 *   max_size   : 1 / 1000 / 4096 / 10240 / 100000   (separate group)
 *   node_path  : normal / empty / 63 chars / 64 unterminated (zero tail)
 *   crash group (forked, ASan report visible on stderr): NULL node, NULL
 *                desc, unterminated node_path with non-zero tail, scratch
 *                size larger than the allocation.
 * Syscalls are stubs (see rdk_hal_ipc_exec.cpp), so each case observes what
 * the function asked the kernel to do.  The expected result is the SAFE
 * contract (client types only connect; every error path returns -1 and
 * closes the socket; every byte is sent; scratch freed once), so a FAIL is
 * a finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "common.h"

unsigned char hipc_node_slab[sizeof(hal_ipc_node_t) + HIPC_PAD];
unsigned char hipc_desc_slab[sizeof(hal_ipc_processor_desc_t) + HIPC_PAD];
unsigned char hipc_scr_slab[HIPC_SCR_SZ];
size_t hipc_cur_scr_size;
unsigned int hipc_max_ipc_buff = 10240;
char hipc_exec_why[256];

enum { F_NONE, F_SOCKET, F_BIND, F_RCVBUF, F_SNDBUF, F_CONNECT, F_SEND1, F_SCRATCH, F_SHORT };

/* ------------------------- syscall stubs ------------------------- */
static struct {
	int fail_at, send_nth_fail;
	int sock_calls, bind_calls, connect_calls, close_calls, send_calls, unlink_calls, free_calls;
	int rcv_calls, snd_calls, opt_order_ok, last_opt;
	unsigned int rcv_val, snd_val;
	char bind_path[128], connect_path[128], unlink_path[128];
	size_t total_sent, max_chunk;
	void *last_free;
} st;

#define FAKE_FD 77

int hipc_stub_socket(int, int, int)
{
	st.sock_calls++;
	if (st.fail_at == F_SOCKET) { errno = EMFILE; return -1; }
	return FAKE_FD;
}

int hipc_stub_bind(int, const struct sockaddr *addr, socklen_t)
{
	const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
	size_t n = strnlen(un->sun_path, sizeof(un->sun_path));

	st.bind_calls++;
	memcpy(st.bind_path, un->sun_path, n < 127 ? n : 127);
	st.bind_path[n < 127 ? n : 127] = 0;
	if (st.fail_at == F_BIND) { errno = EADDRINUSE; return -1; }
	return 0;
}

int hipc_stub_connect(int, const struct sockaddr *addr, socklen_t)
{
	const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
	size_t n = strnlen(un->sun_path, sizeof(un->sun_path));

	st.connect_calls++;
	memcpy(st.connect_path, un->sun_path, n < 127 ? n : 127);
	st.connect_path[n < 127 ? n : 127] = 0;
	if (st.fail_at == F_CONNECT) { errno = ECONNREFUSED; return -1; }
	return 0;
}

int hipc_stub_setsockopt(int, int, int optname, const void *optval, socklen_t)
{
	unsigned int v = *(const unsigned int *)optval;

	if (optname == SO_RCVBUF) { st.rcv_calls++; st.rcv_val = v; if (st.last_opt != 0) st.opt_order_ok = 0; st.last_opt = SO_RCVBUF;
		if (st.fail_at == F_RCVBUF) { errno = ENOBUFS; return -1; } }
	if (optname == SO_SNDBUF) { st.snd_calls++; st.snd_val = v; if (st.last_opt != SO_RCVBUF) st.opt_order_ok = 0; st.last_opt = SO_SNDBUF;
		if (st.fail_at == F_SNDBUF) { errno = ENOBUFS; return -1; } }
	return 0;
}

ssize_t hipc_stub_send(int, const void *buf, size_t len, int)
{
	size_t n = len;
	volatile unsigned char sum = 0;

	st.send_calls++;
	if (st.send_nth_fail && st.send_calls == st.send_nth_fail) { errno = EPIPE; return -1; }
	if (buf == NULL) { errno = EFAULT; return -1; }
	if (st.fail_at == F_SHORT && n > 1000) n = 1000;
	for (size_t i = 0; i < n; i++) sum ^= ((const unsigned char *)buf)[i];   /* the kernel reads these bytes */
	st.total_sent += n;
	if (len > st.max_chunk) st.max_chunk = len;
	return (ssize_t)n;
}

int hipc_stub_close(int fd) { if (fd == FAKE_FD) st.close_calls++; return 0; }

int hipc_stub_unlink(const char *path)
{
	st.unlink_calls++;
	strncpy(st.unlink_path, path, 127); st.unlink_path[127] = 0;
	return 0;
}

void hipc_stub_free(void *p) { st.free_calls++; st.last_free = p; }   /* runner owns the slabs; never really freed */

/* ------------------------- suite ------------------------- */
hipc_exec_test_case_t rdk_hal_ipc_exec_suite[] = {
	{ "matrix_notif_client_fail_none_shape0", 1, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape1", 1, 0, 1, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape2", 1, 0, 2, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape3", 1, 0, 3, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape4", 1, 0, 4, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape5", 1, 0, 5, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape6", 1, 0, 6, 10240u, 0, 0, 1 },
	{ "matrix_sync_sm_client_fail_none_shape0", 3, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_sync_bm_client_fail_none_shape3", 4, 0, 3, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_socket_shape0", 1, 1, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_bind_shape0", 1, 2, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_rcvbuf_shape0", 1, 3, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_sndbuf_shape0", 1, 4, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_connect_shape0", 1, 5, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_send1_shape0", 1, 6, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_scratch_send_shape3", 1, 7, 3, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_scratch_send_shape4", 1, 7, 4, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_scratch_send_shape6", 1, 7, 6, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_short_send_shape0", 1, 8, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_short_send_shape4", 1, 8, 4, 10240u, 0, 0, 1 },
	{ "matrix_sync_bm_client_fail_connect_shape4", 4, 5, 4, 10240u, 0, 0, 1 },
	{ "matrix_sync_sm_client_fail_send1_shape3", 3, 6, 3, 10240u, 0, 0, 1 },
	{ "matrix_sync_sm_client_fail_bind_shape4", 3, 2, 4, 10240u, 0, 0, 1 },
	{ "matrix_notif_server_fail_none_shape0", 0, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_sync_server_fail_none_shape0", 2, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_type_max_fail_none_shape0", 5, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_neg1_fail_none_shape0", -1, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_pos99_fail_none_shape0", 99, 0, 0, 10240u, 0, 0, 1 },
	{ "matrix_sync_server_fail_connect_shape3", 2, 5, 3, 10240u, 0, 0, 1 },
	{ "matrix_notif_server_fail_socket_shape0", 0, 1, 0, 10240u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape1_max1", 1, 0, 1, 1u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape3_max1000", 1, 0, 3, 1000u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape4_max4096", 1, 0, 4, 4096u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape4_max100000", 1, 0, 4, 100000u, 0, 0, 1 },
	{ "matrix_notif_client_fail_none_shape0_max4096", 1, 0, 0, 4096u, 0, 0, 1 },
	{ "matrix_notif_client_fail_scratch_send_shape3_max1000", 1, 7, 3, 1000u, 0, 0, 1 },
	{ "path_empty_notif_client", 1, 0, 0, 10240u, 1, 0, 1 },
	{ "path_len63_notif_client", 1, 0, 0, 10240u, 2, 0, 1 },
	{ "path_len64_unterminated_zero_tail_notif_client", 1, 0, 0, 10240u, 3, 0, 1 },
	{ "crash_p_ipc_node_NULL", 1, 0, 0, 10240u, 5, 1, 1 },
	{ "crash_desc_NULL", 1, 0, 0, 10240u, 6, 1, 1 },
	{ "crash_path_len64_unterminated_nonzero_tail", 1, 0, 0, 10240u, 4, 1, 1 },
	{ "crash_scratch_size_1_over_alloc", 1, 0, 3, 10240u, 7, 1, 1 },
	{ "crash_scratch_size_1000_over_alloc", 1, 0, 3, 10240u, 8, 1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};

static const hipc_exec_test_case_t *cur_tc;
static hal_ipc_node_t *node;
static hal_ipc_processor_desc_t *desc;
static size_t D = sizeof(hal_ipc_processor_desc_t);
static int has_scratch_phase, len_gt_D;

static void fill_node(const hipc_exec_test_case_t *tc)
{
	memset(hipc_node_slab, 0, sizeof(hipc_node_slab));
	node = (hal_ipc_node_t *)hipc_node_slab;
	node->type = (hal_ipc_node_type_t)tc->node_type;
	switch (tc->path_variant) {
	case 1: node->node_path[0] = 0; break;
	case 2: memset(node->node_path, 'p', 63); break;
	case 3: memset(node->node_path, 'p', 64); break;                  /* no NUL, tail is zero */
	case 4: memset(node->node_path, 'p', 64);                          /* no NUL, tail non-zero */
		memset(hipc_node_slab + 64, 0x41, sizeof(hal_ipc_node_t) - 64); break;
	default: strcpy(node->node_path, "/tmp/hipc_cli_node"); break;
	}
}

static void fill_desc(const hipc_exec_test_case_t *tc)
{
	static const size_t sizes[7] = { 0, 0, 0, 1000, 25000, 10240, 10241 };
	size_t ssz = sizes[tc->shape];

	memset(hipc_desc_slab, 0, sizeof(hipc_desc_slab));
	desc = (hal_ipc_processor_desc_t *)hipc_desc_slab;
	strcpy(desc->name, "wifi_exec_test");
	switch (tc->shape) {
	case 0: desc->len = 0; break;
	case 1: desc->len = (unsigned int)D; break;
	case 2: desc->len = (unsigned int)D + 1; break;
	default: desc->len = (unsigned int)D + (unsigned int)ssz; break;
	}
	memset(hipc_scr_slab, 0x5A, sizeof(hipc_scr_slab));
	desc->scratch_buf = ssz ? hipc_scr_slab : NULL;
	desc->scratch_buf_size = (unsigned int)ssz;
	hipc_cur_scr_size = ssz;
	if (tc->kind == 1 && tc->path_variant == 7) desc->scratch_buf_size += 1;      /* caller lies: size > allocation */
	if (tc->kind == 1 && tc->path_variant == 8) desc->scratch_buf_size += 1000;
	len_gt_D = desc->len > D;
	has_scratch_phase = len_gt_D && desc->scratch_buf_size > 0;
}

void construct_rdk_hal_ipc_exec_input(const hipc_exec_test_case_t *tc)
{
	cur_tc = tc;
	memset(&st, 0, sizeof(st));
	st.fail_at = tc->fail_at;
	st.opt_order_ok = 1;
	hipc_max_ipc_buff = tc->max_buf;
	fill_node(tc);
	fill_desc(tc);
	if (tc->fail_at == F_SEND1) st.send_nth_fail = 1;
	if (tc->fail_at == F_SCRATCH && has_scratch_phase) {
		size_t desc_sends = (D > hipc_max_ipc_buff) ? (D + hipc_max_ipc_buff - 1) / hipc_max_ipc_buff : 1;
		st.send_nth_fail = (int)desc_sends + 1;                       /* first send of the scratch phase */
	}
	hipc_exec_why[0] = 0;
}

#define WHY(...) do { snprintf(hipc_exec_why, sizeof(hipc_exec_why), __VA_ARGS__); return 0; } while (0)

static int check_matrix(int ret)
{
	const hipc_exec_test_case_t *tc = cur_tc;
	int t = tc->node_type, f = tc->fail_at;
	int client = (t == hal_ipc_node_type_notification_client || t == hal_ipc_node_type_sync_call_sm_client ||
	              t == hal_ipc_node_type_sync_call_bm_client);
	int created = f != F_SOCKET;
	int reaches_connect = created && f != F_BIND && f != F_RCVBUF && f != F_SNDBUF;
	int scratch_fail = f == F_SCRATCH && has_scratch_phase;
	int expect_fail = !created || f == F_BIND || f == F_RCVBUF || f == F_SNDBUF || (client && (f == F_CONNECT || f == F_SEND1 || scratch_fail)) || !client;
	size_t want_total = D + (has_scratch_phase ? desc->scratch_buf_size : 0);

	/* socket / bind / cleanup invariants (every type) */
	if (st.sock_calls != 1) WHY("socket called %d times", st.sock_calls);
	if (created && st.close_calls != 1) WHY("socket closed %d times (leak or double close)", st.close_calls);
	if (!created && st.close_calls != 0) WHY("close called although socket() failed");

	if (!client) {      /* server types / max / -1 / 99: this is the client function, must reject without connecting */
		if (reaches_connect || (created && f != F_BIND && f != F_RCVBUF && f != F_SNDBUF)) { /* fallthrough to contract */ }
		if (st.connect_calls != 0) WHY("connect() called for non-client node type %d (srv_sockaddr.sun_path uninitialised)", t);
		if (ret != -1) WHY("returned %d for non-client node type %d (expected -1)", ret, t);
		return 1;
	}
	/* client node types */
	if (created) {
		if (st.unlink_calls != 1 || strcmp(st.unlink_path, node->node_path)) WHY("unlink path '%s' calls=%d", st.unlink_path, st.unlink_calls);
		if (st.bind_calls != 1) WHY("bind called %d times", st.bind_calls);
		if (strcmp(st.bind_path, node->node_path)) WHY("bind path '%s' != node_path", st.bind_path);
	}
	if (f == F_BIND && (st.connect_calls || st.send_calls)) WHY("continued after bind failure");
	if (f == F_RCVBUF && (st.connect_calls || st.send_calls)) WHY("continued after SO_RCVBUF failure");
	if (f == F_SNDBUF && (st.connect_calls || st.send_calls)) WHY("continued after SO_SNDBUF failure");
	if (reaches_connect) {
		if (st.rcv_calls != 1 || st.snd_calls != 1 || !st.opt_order_ok) WHY("setsockopt rcv=%d snd=%d order_ok=%d", st.rcv_calls, st.snd_calls, st.opt_order_ok);
		if (st.rcv_val != tc->max_buf || st.snd_val != tc->max_buf) WHY("buffer sizes %u/%u != %u", st.rcv_val, st.snd_val, tc->max_buf);
		if (st.connect_calls != 1) WHY("connect called %d times", st.connect_calls);
		const char *want = t == hal_ipc_node_type_notification_client ? "/tmp/hal_notification_server" : "/tmp/hal_sync_server";
		if (strcmp(st.connect_path, want)) WHY("connect path '%s' != '%s'", st.connect_path, want);
	}
	if (f == F_CONNECT && st.send_calls) WHY("sent data after connect failure");
	if (expect_fail != (ret == -1)) WHY("ret=%d expected %d", ret, expect_fail ? -1 : 0);
	if (ret == 0) {
		if (st.total_sent != want_total) WHY("sent %zu of %zu bytes%s", st.total_sent, want_total, f == F_SHORT ? " (short send not handled)" : "");
		if (st.max_chunk > tc->max_buf && tc->max_buf) WHY("chunk %zu > max_size %u", st.max_chunk, tc->max_buf);
		if (len_gt_D) { if (st.free_calls != 1 || st.last_free != desc->scratch_buf) WHY("scratch_buf freed %d times", st.free_calls); }
		else if (st.free_calls != 0) WHY("free() called although len <= sizeof(desc)");
	}
	if (scratch_fail && (st.free_calls != 1 || st.last_free != desc->scratch_buf)) WHY("scratch_buf freed %d times on send error", st.free_calls);
	return 1;
}

static int call_exec(void)
{
	switch (cur_tc->path_variant) {
	case 5: if (cur_tc->kind == 1) return rdk_hal_ipc_exec(NULL, desc); break;
	case 6: if (cur_tc->kind == 1) return rdk_hal_ipc_exec(node, NULL); break;
	}
	return rdk_hal_ipc_exec(node, desc);
}

int rdk_hal_ipc_exec_run_current(void)
{
	if (cur_tc->kind == 1) {          /* crash group: forked, ASan report left on stderr */
		int stt;
		pid_t pid;

		fflush(stdout);
		pid = fork();
		if (pid == 0) { call_exec(); _exit(0); }
		waitpid(pid, &stt, 0);
		return WIFEXITED(stt) && WEXITSTATUS(stt) == 0;       /* 1 = survived */
	}
	return check_matrix(call_exec());
}
