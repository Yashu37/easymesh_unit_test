/*
 * UNIT TEST (input constructor): construct_rdk_hal_server_func
 *
 * rdk_hal_server_func(arg) is the server thread of the HAL IPC: it validates
 * the node type, creates/binds/listens a server socket at node->node_path, and
 * then loops on accept(): per client it receives a descriptor (single recv or
 * chunks), an optional scratch buffer (malloc'd from the client-supplied
 * size), runs the processor for desc.type, and sends the descriptor (and any
 * response scratch buffer) back.
 *
 * The syscalls are stubs (see rdk_hal_server_func.cpp): clients are scripted
 * byte streams handed out by accept(), after which accept() returns -1 and the
 * loop ends.  Inputs crossed (representative combinations, capped at 50):
 *   node type    : the 2 server types, 3 client types, max, -1, 99
 *   setup fail   : socket / bind / SO_RCVBUF / SO_SNDBUF / listen
 *   node_path    : empty / 63 chars / 64 unterminated (zero / non-zero tail)
 *                  (an unterminated path is bounded by the NUL in srv_sock, so no overflow)
 *   request      : scratch 0 / 1000 / 10240 / 10241 / 25000, max_size
 *                  1000..100000 (single vs chunked recv), short recv, recv
 *                  error / EOF, invalid desc.type, no processor, processor
 *                  fail / ok / response scratch (single and chunked send),
 *                  send failures, short send, several clients in a row
 *   hostile desc : len = 0, len > sizeof with scratch_buf_size 0 (client-controlled
 *                  assert()s; run in a forked child so the abort is visible
 *                  but does not stop the run)
 *
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"

unsigned char hsrv_stream[HSRV_MAX_CLIENTS][HSRV_STREAM_SZ];
size_t        hsrv_stream_len[HSRV_MAX_CLIENTS];
int           hsrv_nclients;
void        (*hsrv_poison_fn)(int on);

#define SZ_DESC   (sizeof(hal_ipc_processor_desc_t))
#define SRV_FD    77
#define CLI_FD0   100
#define PROC_TYPE 5            /* hal_ipc_desc_type_get_neighbor_wifi_status: gets the test processor */
#define NOPROC_TYPE 7          /* table entry whose ipc_processor[server_output] stays NULL */

enum { WANT_OK, WANT_DROP, WANT_BADTYPE, WANT_SENDFAIL, WANT_PROCFAIL, WANT_NOPROC };
enum { LEN_OK, LEN_ZERO, LEN_BAD_SCR };

struct creq {
	int type; unsigned scr; int len_mode; int name_unterm; unsigned payload;   /* payload < 0 -> scr */
	int recv_cap, recv_fail_at, recv_eof_at, send_cap, send_fail_at, want;
};
struct srv {
	int node_type, fail, path_variant; unsigned max_buf; int proc_mode; unsigned resp_scr;
	int nclients; creq c[HSRV_MAX_CLIENTS];
};

/* ------------------------- stub state ------------------------- */
static struct {
	int fail;                                   /* 1 socket 2 bind 3 rcv 4 snd 5 listen */
	int sock_calls, bind_calls, listen_calls, accept_calls, srv_close, unlink_calls, malloc_out, double_free;
	int rcv_calls, snd_calls; int rcv_val, snd_val, backlog;
	char bind_path[128], unlink_path[128];
	int next_client, cur_client;
	struct { size_t pos; int recv_calls, send_calls, closed; size_t resp_len; int proc_calls, desc_intact, scr_intact;
	         int recv_cap, recv_fail_at, recv_eof_at, send_cap, send_fail_at; } c[HSRV_MAX_CLIENTS];
} h;
static unsigned char resp_buf[HSRV_MAX_CLIENTS][HSRV_RESP_SZ];
static unsigned char sent_img[HSRV_MAX_CLIENTS][sizeof(hal_ipc_processor_desc_t)];

int hsrv_stub_socket(int, int, int) { h.sock_calls++; if (h.fail == 1) { errno = EMFILE; return -1; } return SRV_FD; }
int hsrv_stub_bind(int, const struct sockaddr *a, socklen_t)
{
	const struct sockaddr_un *un = (const struct sockaddr_un *)a;
	size_t n = strnlen(un->sun_path, sizeof(un->sun_path));
	h.bind_calls++; memcpy(h.bind_path, un->sun_path, n < 127 ? n : 127); h.bind_path[n < 127 ? n : 127] = 0;
	if (h.fail == 2) { errno = EADDRINUSE; return -1; }
	return 0;
}
int hsrv_stub_setsockopt(int, int, int optname, const void *v, socklen_t)
{
	int val = *(const int *)v;
	if (optname == SO_RCVBUF) { h.rcv_calls++; h.rcv_val = val; if (h.fail == 3) { errno = ENOBUFS; return -1; } }
	if (optname == SO_SNDBUF) { h.snd_calls++; h.snd_val = val; if (h.fail == 4) { errno = ENOBUFS; return -1; } }
	return 0;
}
int hsrv_stub_listen(int, int backlog) { h.listen_calls++; h.backlog = backlog; if (h.fail == 5) { errno = EADDRINUSE; return -1; } return 0; }
int hsrv_stub_accept(int, struct sockaddr *, socklen_t *)
{
	h.accept_calls++;
	if (h.next_client >= hsrv_nclients) return -1;
	h.cur_client = h.next_client++;
	return CLI_FD0 + h.cur_client;
}
ssize_t hsrv_stub_recv(int fd, void *buf, size_t len, int)
{
	int i = fd - CLI_FD0;
	size_t avail, n;
	if (i < 0 || i >= HSRV_MAX_CLIENTS) return -1;
	h.c[i].recv_calls++;
	if (h.c[i].recv_fail_at == h.c[i].recv_calls) { errno = ECONNRESET; return -1; }
	if (h.c[i].recv_eof_at == h.c[i].recv_calls) return 0;
	avail = hsrv_stream_len[i] - h.c[i].pos;
	n = len < avail ? len : avail;
	if (h.c[i].recv_cap && n > (size_t)h.c[i].recv_cap) n = h.c[i].recv_cap;
	if (n == 0) return 0;
	memcpy(buf, &hsrv_stream[i][h.c[i].pos], n);          /* writes into the server's desc / scratch_buf */
	h.c[i].pos += n;
	return (ssize_t)n;
}
ssize_t hsrv_stub_send(int fd, const void *buf, size_t len, int)
{
	int i = fd - CLI_FD0;
	size_t n = len;
	if (i < 0 || i >= HSRV_MAX_CLIENTS) return -1;
	h.c[i].send_calls++;
	if (h.c[i].send_fail_at == h.c[i].send_calls) { errno = EPIPE; return -1; }
	if (h.c[i].send_cap && n > (size_t)h.c[i].send_cap) n = h.c[i].send_cap;
	if (h.c[i].resp_len + n > HSRV_RESP_SZ) n = HSRV_RESP_SZ - h.c[i].resp_len;
	memcpy(&resp_buf[i][h.c[i].resp_len], buf, n);        /* reads the server's desc / scratch_buf */
	h.c[i].resp_len += n;
	return (ssize_t)n;
}
int hsrv_stub_close(int fd)
{
	if (fd == SRV_FD) h.srv_close++;
	else if (fd >= CLI_FD0 && fd < CLI_FD0 + HSRV_MAX_CLIENTS) h.c[fd - CLI_FD0].closed++;
	return 0;
}
int hsrv_stub_unlink(const char *p) { h.unlink_calls++; strncpy(h.unlink_path, p, 127); h.unlink_path[127] = 0; return 0; }
void *hsrv_stub_malloc(size_t n)
{
	if (n >= (1u << 28)) return NULL;                     /* refuse absurd sizes instead of OOM-ing the test box */
	h.malloc_out++;
	return malloc(n ? n : 1);
}
void hsrv_stub_free(void *p) { if (p) { h.malloc_out--; free(p); } }

/* ------------------------- test processor ------------------------- */
static int g_mode; static unsigned g_resp_scr;
static unsigned char pat(size_t i) { return (unsigned char)(i * 7 + 3); }

static int proc(hal_ipc_processor_desc_t *d, void *, void *, void *, void *, void *)
{
	int c = h.cur_client;
	h.c[c].proc_calls++;
	h.c[c].desc_intact = !memcmp(d, sent_img[c], offsetof(hal_ipc_processor_desc_t, scratch_buf));
	h.c[c].scr_intact = 1;
	if (d->scratch_buf) {
		for (unsigned i = 0; i < d->scratch_buf_size; i++) if (d->scratch_buf[i] != pat(i)) { h.c[c].scr_intact = 0; break; }
		hsrv_stub_free(d->scratch_buf);                   /* the processor owns the request scratch buffer */
		d->scratch_buf = NULL;
	}
	if (g_mode == 1) return -1;
	d->ret = 77;
	d->scratch_buf = NULL; d->scratch_buf_size = 0; d->len = (unsigned)SZ_DESC;
	if (g_mode == 2 && g_resp_scr) {
		d->scratch_buf = (unsigned char *)hsrv_stub_malloc(g_resp_scr);
		memset(d->scratch_buf, 0xC3, g_resp_scr);
		d->scratch_buf_size = g_resp_scr; d->len = (unsigned)SZ_DESC + g_resp_scr;
	}
	return 0;
}

/* ------------------------- scenario plumbing ------------------------- */
#define FAIL_(...) do { snprintf(hipc_exec_why, 256, __VA_ARGS__); return 0; } while (0)

static creq mk(void) { creq r; memset(&r, 0, sizeof(r)); r.type = PROC_TYPE; r.payload = (unsigned)-1; r.want = WANT_OK; return r; }
static srv base(void) { srv s; memset(&s, 0, sizeof(s)); s.node_type = hal_ipc_node_type_sync_call_server; s.max_buf = 10240; s.nclients = 1; s.c[0] = mk(); for (int i = 1; i < HSRV_MAX_CLIENTS; i++) s.c[i] = mk(); return s; }

static void build_client(int i, const creq &r)
{
	unsigned char *img = sent_img[i];
	hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)img;
	unsigned payload = r.payload == (unsigned)-1 ? r.scr : r.payload;
	size_t total;

	memset(img, 0, SZ_DESC);
	if (r.name_unterm) memset(img, 0x41, SZ_DESC);        /* no NUL anywhere in the descriptor */
	if (!r.name_unterm) { memset(d->in_pad, 0x5A, sizeof(d->in_pad)); memset(d->out_pad, 0xA5, sizeof(d->out_pad)); }   /* non-zero tail: a partial recv is visible */
	d->type = (hal_ipc_desc_type_t)r.type;
	if (!r.name_unterm) strcpy(d->name, "srv_test_req");
	d->scratch_buf = (unsigned char *)(uintptr_t)0x1111;  /* client-side pointer value, meaningless to the server */
	d->scratch_buf_size = r.scr;
	switch (r.len_mode) {
	case LEN_ZERO: d->len = 0; break;
	case LEN_BAD_SCR: d->len = (unsigned)SZ_DESC + 100; d->scratch_buf_size = 0; break;
	default: d->len = r.scr ? (unsigned)SZ_DESC + r.scr : (unsigned)SZ_DESC; break;
	}
	memcpy(hsrv_stream[i], img, SZ_DESC);
	for (unsigned k = 0; k < payload && SZ_DESC + k < HSRV_STREAM_SZ; k++) hsrv_stream[i][SZ_DESC + k] = pat(k);
	total = SZ_DESC + payload;
	hsrv_stream_len[i] = total < HSRV_STREAM_SZ ? total : HSRV_STREAM_SZ;
	h.c[i].recv_cap = r.recv_cap; h.c[i].recv_fail_at = r.recv_fail_at; h.c[i].recv_eof_at = r.recv_eof_at;
	h.c[i].send_cap = r.send_cap; h.c[i].send_fail_at = r.send_fail_at;
}

static void setup(const srv &s)
{
	hal_ipc_node_t *node;
	memset(&h, 0, sizeof(h));
	memset(resp_buf, 0, sizeof(resp_buf));
	h.fail = s.fail;
	hsrv_nclients = s.nclients;
	for (int i = 0; i < HSRV_MAX_CLIENTS; i++) { hsrv_stream_len[i] = 0; if (i < s.nclients) build_client(i, s.c[i]); }
	hipc_max_ipc_buff = s.max_buf;
	for (int t = 0; t < hal_ipc_desc_type_max; t++) processor_desc[t].ipc_processor[processor_type_ipc_server_output] = NULL;
	processor_desc[PROC_TYPE].ipc_processor[processor_type_ipc_server_output] = proc;
	g_mode = s.proc_mode; g_resp_scr = s.resp_scr;
	memset(hipc_node_slab, 0, sizeof(hipc_node_slab));
	node = (hal_ipc_node_t *)hipc_node_slab;
	node->type = (hal_ipc_node_type_t)s.node_type;
	switch (s.path_variant) {
	case 1: node->node_path[0] = 0; break;
	case 2: memset(node->node_path, 'p', 63); break;
	case 3: memset(node->node_path, 'p', 64); break;
	case 4: memset(node->node_path, 'p', 64); memset(hipc_node_slab + 64, 0x41, sizeof(hal_ipc_node_t) - 64); break;
	default: strcpy(node->node_path, "/tmp/hipc_srv_node"); break;
	}
}

static int verify(const srv &s)
{
	hal_ipc_node_t *node = (hal_ipc_node_t *)hipc_node_slab;
	int server_type = s.node_type == hal_ipc_node_type_notification_server || s.node_type == hal_ipc_node_type_sync_call_server;
	int created = s.fail != 1;

	if (!server_type) {                                    /* this is the server function: client/invalid types must be rejected up front */
		if (h.sock_calls) FAIL_("node type %d accepted: socket() called (type check is dead code)", s.node_type);
		return 1;
	}
	if (h.sock_calls != 1) FAIL_("socket called %d times", h.sock_calls);
	if (created && h.srv_close != 1) FAIL_("server socket closed %d times", h.srv_close);
	if (!created && h.srv_close) FAIL_("close() after failed socket()");
	if (created) {
		if (h.unlink_calls != 1 || strcmp(h.unlink_path, node->node_path)) FAIL_("unlink '%s' calls=%d", h.unlink_path, h.unlink_calls);
		if (h.bind_calls != 1 || strcmp(h.bind_path, node->node_path)) FAIL_("bind '%s' calls=%d", h.bind_path, h.bind_calls);
	}
	if (s.fail >= 2 && s.fail <= 5 && h.accept_calls) FAIL_("accept() reached after setup failure %d", s.fail);
	if (s.fail == 0) {
		if (h.rcv_calls != 1 || h.snd_calls != 1 || h.rcv_val != (int)s.max_buf || h.snd_val != (int)s.max_buf) FAIL_("setsockopt rcv=%d/%d snd=%d/%d", h.rcv_calls, h.rcv_val, h.snd_calls, h.snd_val);
		if (h.listen_calls != 1 || h.backlog != 32) FAIL_("listen calls=%d backlog=%d", h.listen_calls, h.backlog);
		if (h.accept_calls != s.nclients + 1) FAIL_("accept called %d times for %d clients", h.accept_calls, s.nclients);
	}
	for (int i = 0; i < s.nclients && s.fail == 0; i++) {
		const creq &r = s.c[i];
		hal_ipc_processor_desc_t *rd = (hal_ipc_processor_desc_t *)resp_buf[i];
		if (h.c[i].closed != 1) FAIL_("client %d closed %d times", i, h.c[i].closed);
		switch (r.want) {
		case WANT_DROP:
			if (h.c[i].proc_calls) FAIL_("client %d: processor ran for a dropped request", i);
			if (h.c[i].resp_len) FAIL_("client %d: response sent for a dropped request", i);
			break;
		case WANT_BADTYPE:
			if (h.c[i].proc_calls) FAIL_("client %d: processor ran for invalid type", i);
			if (h.c[i].resp_len != SZ_DESC || rd->ret != -1 || rd->len != SZ_DESC) FAIL_("client %d: bad-type reply len=%zu ret=%d", i, h.c[i].resp_len, rd->ret);
			break;
		case WANT_NOPROC:
			if (h.c[i].proc_calls) FAIL_("client %d: unexpected processor call", i);
			if (h.c[i].resp_len != SZ_DESC) FAIL_("client %d: reply len %zu", i, h.c[i].resp_len);
			break;
		case WANT_PROCFAIL:
			if (h.c[i].proc_calls != 1) FAIL_("client %d: processor calls %d", i, h.c[i].proc_calls);
			if (h.c[i].resp_len != SZ_DESC || rd->ret != -1 || rd->len != SZ_DESC) FAIL_("client %d: fail reply len=%zu ret=%d", i, h.c[i].resp_len, rd->ret);
			break;
		case WANT_SENDFAIL:
			if (h.c[i].proc_calls != 1) FAIL_("client %d: processor calls %d", i, h.c[i].proc_calls);
			break;
		default: {
			size_t want = SZ_DESC + (s.proc_mode == 2 ? s.resp_scr : 0);
			if (h.c[i].proc_calls != 1) FAIL_("client %d: processor calls %d", i, h.c[i].proc_calls);
			if (!h.c[i].desc_intact) FAIL_("client %d: processor saw a corrupted descriptor (%d recv calls)", i, h.c[i].recv_calls);
			if (r.scr && !h.c[i].scr_intact) FAIL_("client %d: scratch buffer content corrupted (%u bytes, max_size %u)", i, r.scr, s.max_buf);
			if (h.c[i].resp_len != want) FAIL_("client %d: reply %zu bytes, expected %zu%s", i, h.c[i].resp_len, want, r.send_cap ? " (short send not handled)" : "");
			if (rd->ret != 77) FAIL_("client %d: reply ret=%d", i, rd->ret);
			for (size_t k = SZ_DESC; k < h.c[i].resp_len; k++) if (resp_buf[i][k] != 0xC3) FAIL_("client %d: reply scratch corrupted", i);
		}
		}
	}
	if (h.malloc_out != 0) FAIL_("%d scratch buffer(s) leaked", h.malloc_out);
	return 1;
}

static int run(const srv &s)
{
	void *rv;
	setup(s);
	hipc_exec_why[0] = 0;
	if (hsrv_poison_fn) hsrv_poison_fn(1);
	rv = rdk_hal_server_func_entry(hipc_node_slab);
	if (hsrv_poison_fn) hsrv_poison_fn(0);
	if (rv != NULL) FAIL_("returned non-NULL");
	return verify(s);
}

static int run_forked(const srv &s)                         /* assert()/ASan aborts stay visible but do not end the run */
{
	int st; pid_t pid;
	setup(s);
	fflush(stdout);
	if (hsrv_poison_fn) hsrv_poison_fn(1);
	pid = fork();
	if (pid == 0) { rdk_hal_server_func_entry(hipc_node_slab); _exit(0); }
	waitpid(pid, &st, 0);
	if (hsrv_poison_fn) hsrv_poison_fn(0);
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

#define S srv s = base();
hsrv_test_case_t rdk_hal_server_func_suite[] = {
	/* ---- node type check (the function is the SERVER side) ---- */
	{ "type_sync_server_ok",               [](void)->int { S return run(s); }, 1 },
	{ "type_notification_server_ok",       [](void)->int { S s.node_type = hal_ipc_node_type_notification_server; return run(s); }, 1 },
	{ "type_notification_client_rejected", [](void)->int { S s.node_type = hal_ipc_node_type_notification_client; return run(s); }, 1 },
	{ "type_sync_sm_client_rejected",      [](void)->int { S s.node_type = hal_ipc_node_type_sync_call_sm_client; return run(s); }, 1 },
	{ "type_sync_bm_client_rejected",      [](void)->int { S s.node_type = hal_ipc_node_type_sync_call_bm_client; return run(s); }, 1 },
	{ "type_max_rejected",                 [](void)->int { S s.node_type = hal_ipc_node_type_max; return run(s); }, 1 },
	{ "type_neg1_rejected",                [](void)->int { S s.node_type = -1; return run(s); }, 1 },
	{ "type_99_rejected",                  [](void)->int { S s.node_type = 99; return run(s); }, 1 },
	/* ---- setup failures ---- */
	{ "fail_socket",                       [](void)->int { S s.fail = 1; return run(s); }, 1 },
	{ "fail_bind",                         [](void)->int { S s.fail = 2; return run(s); }, 1 },
	{ "fail_so_rcvbuf",                    [](void)->int { S s.fail = 3; return run(s); }, 1 },
	{ "fail_so_sndbuf",                    [](void)->int { S s.fail = 4; return run(s); }, 1 },
	{ "fail_listen",                       [](void)->int { S s.fail = 5; return run(s); }, 1 },
	/* ---- node_path ---- */
	{ "path_empty",                        [](void)->int { S s.path_variant = 1; return run(s); }, 1 },
	{ "path_len63",                        [](void)->int { S s.path_variant = 2; return run(s); }, 1 },
	{ "path_len64_unterminated_zero_tail", [](void)->int { S s.path_variant = 3; return run(s); }, 1 },
	{ "path_len64_unterminated_stops_at_srv_sock", [](void)->int { S s.path_variant = 4; return run(s); }, 1 },   /* strcpy stops at the NUL in srv_sock (set just before): 73 bytes into sun_path[108] */
	/* ---- well-formed requests ---- */
	{ "req_no_scratch",                    [](void)->int { S return run(s); }, 1 },
	{ "req_desc_name_unterminated_stops_at_len_field", [](void)->int { S s.c[0].name_unterm = 1; return run(s); }, 1 },   /* %s of desc.name stops at the NUL bytes of desc.len */
	{ "req_scratch_1000",                  [](void)->int { S s.c[0].scr = 1000; return run(s); }, 1 },
	{ "req_scratch_10240_exact_max",       [](void)->int { S s.c[0].scr = 10240; return run(s); }, 1 },
	{ "req_scratch_10241_chunked",         [](void)->int { S s.c[0].scr = 10241; return run(s); }, 1 },
	{ "req_scratch_25000_chunked",         [](void)->int { S s.c[0].scr = 25000; return run(s); }, 1 },
	{ "req_scratch_25000_max_100000_single", [](void)->int { S s.c[0].scr = 25000; s.max_buf = 100000; return run(s); }, 1 },
	{ "req_scratch_3000_max_1000_chunked", [](void)->int { S s.c[0].scr = 3000; s.max_buf = 1000; return run(s); }, 1 },
	{ "req_desc_chunked_max_4096",         [](void)->int { S s.max_buf = 4096; return run(s); }, 1 },
	{ "req_desc_chunked_short_recv",       [](void)->int { S s.max_buf = 4096; s.c[0].recv_cap = 1000; return run(s); }, 1 },
	{ "req_desc_single_short_recv",        [](void)->int { S s.c[0].recv_cap = 1000; return run(s); }, 1 },
	/* ---- descriptor type / processor ---- */
	{ "req_invalid_type_neg1",             [](void)->int { S s.c[0].type = -1; s.c[0].want = WANT_BADTYPE; return run(s); }, 1 },
	{ "req_invalid_type_max",              [](void)->int { S s.c[0].type = hal_ipc_desc_type_max; s.c[0].want = WANT_BADTYPE; return run(s); }, 1 },
	{ "req_invalid_type_99_with_scratch",  [](void)->int { S s.c[0].type = 99; s.c[0].scr = 1000; s.c[0].want = WANT_BADTYPE; return run(s); }, 1 },
	{ "req_type_without_processor",        [](void)->int { S s.c[0].type = NOPROC_TYPE; s.c[0].want = WANT_NOPROC; return run(s); }, 1 },
	{ "req_processor_fails_no_scratch",    [](void)->int { S s.proc_mode = 1; s.c[0].want = WANT_PROCFAIL; return run(s); }, 1 },
	{ "req_processor_fails_with_scratch",  [](void)->int { S s.proc_mode = 1; s.c[0].scr = 1000; s.c[0].want = WANT_PROCFAIL; return run(s); }, 1 },
	/* ---- responses ---- */
	{ "resp_scratch_2000",                 [](void)->int { S s.proc_mode = 2; s.resp_scr = 2000; return run(s); }, 1 },
	{ "resp_scratch_25000_chunked_send",   [](void)->int { S s.proc_mode = 2; s.resp_scr = 25000; return run(s); }, 1 },
	{ "req_scratch_1000_resp_scratch_2000",[](void)->int { S s.proc_mode = 2; s.resp_scr = 2000; s.c[0].scr = 1000; return run(s); }, 1 },
	{ "send_fail_first_with_resp_scratch", [](void)->int { S s.proc_mode = 2; s.resp_scr = 2000; s.c[0].send_fail_at = 1; s.c[0].want = WANT_SENDFAIL; return run(s); }, 1 },
	{ "send_fail_in_scratch_phase",        [](void)->int { S s.proc_mode = 2; s.resp_scr = 2000; s.c[0].send_fail_at = 2; s.c[0].want = WANT_SENDFAIL; return run(s); }, 1 },
	{ "send_short_single_branch",          [](void)->int { S s.c[0].send_cap = 1000; return run(s); }, 1 },
	/* ---- client I/O errors and several clients ---- */
	{ "recv_error_first_call",             [](void)->int { S s.c[0].recv_fail_at = 1; s.c[0].want = WANT_DROP; return run(s); }, 1 },
	{ "recv_eof_first_call",               [](void)->int { S s.c[0].recv_eof_at = 1; s.c[0].want = WANT_DROP; return run(s); }, 1 },
	{ "recv_error_in_scratch",             [](void)->int { S s.c[0].scr = 1000; s.c[0].recv_fail_at = 2; s.c[0].want = WANT_DROP; return run(s); }, 1 },
	{ "three_clients_bad_good_badtype",    [](void)->int { S s.nclients = 3; s.c[0].recv_fail_at = 1; s.c[0].want = WANT_DROP;
		s.c[2].type = -1; s.c[2].want = WANT_BADTYPE; return run(s); }, 1 },
	{ "two_clients_scratch_no_crosstalk",  [](void)->int { S s.nclients = 2; s.c[0].scr = 1000; s.c[1].scr = 500; return run(s); }, 1 },
	{ "four_clients_ok",                   [](void)->int { S s.nclients = 4; for (int i = 0; i < 4; i++) s.c[i].scr = i * 300; return run(s); }, 1 },
	/* ---- crash group: forked, assert()/ASan report visible ---- */
	{ "crash_desc_len_zero_assert",        [](void)->int { S s.c[0].len_mode = LEN_ZERO; return run_forked(s); }, 1 },
	{ "crash_desc_len_gt_size_scratch_zero_assert", [](void)->int { S s.c[0].len_mode = LEN_BAD_SCR; return run_forked(s); }, 1 },
	{ NULL, NULL, 0 }
};

static const hsrv_test_case_t *cur_tc;

void construct_rdk_hal_server_func_input(const hsrv_test_case_t *tc)
{
	cur_tc = tc;
	hipc_exec_why[0] = 0;
}

int rdk_hal_server_func_run_current(void)
{
	return cur_tc->scenario();
}
