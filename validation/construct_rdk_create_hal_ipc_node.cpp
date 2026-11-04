/*
 * UNIT TEST (input constructor): construct_rdk_create_hal_ipc_node
 *
 * rdk_create_hal_ipc_node(type) returns &g_ipc_node[type] after filling in the
 * node: type, node_path ("/tmp/hal_sync_server" or "/tmp/hal_notification_client")
 * and, for the sync server only, a listener thread (pthread_create).  The other
 * node types are rejected with NULL.  The type is used as an array index (and
 * written through) before it is validated.
 *
 * pthread_create is a stub (records args, can fail); g_ipc_node[] is a
 * runner-owned slab whose tail is poisoned.  Inputs: all 5 valid enum values,
 * pthread_create ok/failing, stale / pre-filled node contents, repeated calls,
 * neighbouring nodes untouched, log text, and out-of-range types
 * (-1, max, max+1, 99, 255, 65536, INT_MAX, INT_MIN - run forked so the ASan
 * report is visible but does not stop the run).
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"

unsigned char hcre_gnode_slab[sizeof(hal_ipc_node_t) * hal_ipc_node_type_max + HIPC_PAD];
void (*hcre_poison_fn)(int on);

#define NODES ((hal_ipc_node_t *)hcre_gnode_slab)
#define SYNC_PATH  "/tmp/hal_sync_server"
#define NOTIF_PATH "/tmp/hal_notification_client"

static struct { int calls, fail; pthread_t *t; void *(*fn)(void *); void *arg; const pthread_attr_t *attr; } pc;

int hcre_stub_pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*fn)(void *), void *arg)
{
	pc.calls++; pc.t = t; pc.fn = fn; pc.arg = arg; pc.attr = attr;
	if (pc.fail) return EAGAIN;
	*t = (pthread_t)(0xABC0 + pc.calls);
	return 0;
}

#define FAIL_(...) do { snprintf(hipc_exec_why, 256, __VA_ARGS__); return 0; } while (0)

/* fill every node with a sentinel so untouched / stale state is detectable */
static void setup(int fail_pthread, int sentinel)
{
	memset(&pc, 0, sizeof(pc)); pc.fail = fail_pthread;
	memset(hcre_gnode_slab, 0, sizeof(hcre_gnode_slab));
	if (sentinel) memset(hcre_gnode_slab, 0x5A, sizeof(hal_ipc_node_t) * hal_ipc_node_type_max);
	memset(hipc_log_buf, 0, HIPC_LOG_USE);
	hipc_exec_why[0] = 0;
}

static hal_ipc_node_t *call(int type)
{
	hal_ipc_node_t *n;
	if (hcre_poison_fn) hcre_poison_fn(1);
	n = rdk_create_hal_ipc_node((hal_ipc_node_type_t)type);
	if (hcre_poison_fn) hcre_poison_fn(0);
	return n;
}

static int others_untouched(int type)
{
	for (int i = 0; i < hal_ipc_node_type_max; i++) {
		if (i == type) continue;
		for (size_t k = 0; k < sizeof(hal_ipc_node_t); k++)
			if (((unsigned char *)&NODES[i])[k] != 0x5A) { snprintf(hipc_exec_why, 256, "node[%d] byte %zu modified by a call for type %d", i, k, type); return 0; }
	}
	return 1;
}

/* a valid server/client type */
static int ok_type(int type, const char *path, int threads, int fail_pthread, int sentinel)
{
	hal_ipc_node_t *n;
	setup(fail_pthread, sentinel);
	n = call(type);
	if (n != &NODES[type]) FAIL_("returned %p, expected &g_ipc_node[%d]=%p", (void *)n, type, (void *)&NODES[type]);
	if (n->type != type) FAIL_("node->type=%d", (int)n->type);
	if (strcmp(n->node_path, path)) FAIL_("node_path='%s'", n->node_path);
	if (pc.calls != threads) FAIL_("pthread_create called %d times, expected %d", pc.calls, threads);
	if (threads) {
		if (pc.t != &n->listener_tid) FAIL_("thread id not stored in node->listener_tid");
		if (pc.arg != n) FAIL_("start arg is not the node");
		if (pc.fn != hcre_server_func_addr()) FAIL_("start routine is not rdk_hal_server_func");
		if (pc.attr != NULL) FAIL_("attr not NULL");
		if (n->listener_tid != (pthread_t)(0xABC0 + 1)) FAIL_("listener_tid not set");
	}
	if (sentinel && !others_untouched(type)) return 0;
	return 1;
}

static int rejected(int type, int sentinel)
{
	setup(0, sentinel);
	hal_ipc_node_t *n = call(type);
	if (n != NULL) FAIL_("type %d accepted, returned %p", type, (void *)n);
	if (pc.calls) FAIL_("pthread_create called for rejected type %d", type);
	if (!strstr(hipc_log_buf, "Invalid node type")) FAIL_("no 'Invalid node type' log: '%s'", hipc_log_buf);
	if (sentinel && type >= 0 && type < hal_ipc_node_type_max) {
		if (strlen(NODES[type].node_path) && NODES[type].node_path[0] != 0x5A) FAIL_("node_path written for rejected type");
		if (!others_untouched(type)) return 0;
	}
	return 1;
}

static int run_forked_type(int type)                        /* ASan report stays visible, run continues */
{
	int st; pid_t pid;
	setup(0, 1);
	fflush(stdout);
	if (hcre_poison_fn) hcre_poison_fn(1);
	pid = fork();
	if (pid == 0) { hal_ipc_node_t *n = rdk_create_hal_ipc_node((hal_ipc_node_type_t)type); _exit(n == NULL ? 0 : 3); }
	waitpid(pid, &st, 0);
	if (hcre_poison_fn) hcre_poison_fn(0);
	if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) { snprintf(hipc_exec_why, 256, "type %d: child %s (ASan abort / accepted)", type, WIFEXITED(st) ? "accepted it" : "died"); return 0; }
	return 1;
}

hcre_test_case_t rdk_create_hal_ipc_node_suite[] = {
	/* ---- every valid enum value ---- */
	{ "type_sync_call_server",              [](void)->int { return ok_type(hal_ipc_node_type_sync_call_server, SYNC_PATH, 1, 0, 1); }, 1 },
	{ "type_notification_client",           [](void)->int { return ok_type(hal_ipc_node_type_notification_client, NOTIF_PATH, 0, 0, 1); }, 1 },
	{ "type_notification_server_rejected",  [](void)->int { return rejected(hal_ipc_node_type_notification_server, 1); }, 1 },
	{ "type_sync_call_sm_client_rejected",  [](void)->int { return rejected(hal_ipc_node_type_sync_call_sm_client, 1); }, 1 },
	{ "type_sync_call_bm_client_rejected",  [](void)->int { return rejected(hal_ipc_node_type_sync_call_bm_client, 1); }, 1 },
	{ "type_sync_server_zeroed_nodes",      [](void)->int { return ok_type(hal_ipc_node_type_sync_call_server, SYNC_PATH, 1, 0, 0); }, 1 },
	{ "type_notification_client_zeroed",    [](void)->int { return ok_type(hal_ipc_node_type_notification_client, NOTIF_PATH, 0, 0, 0); }, 1 },
	{ "type_notification_server_zeroed",    [](void)->int { return rejected(hal_ipc_node_type_notification_server, 0); }, 1 },
	{ "type_sm_client_zeroed",              [](void)->int { return rejected(hal_ipc_node_type_sync_call_sm_client, 0); }, 1 },
	{ "type_bm_client_zeroed",              [](void)->int { return rejected(hal_ipc_node_type_sync_call_bm_client, 0); }, 1 },
	/* ---- listener thread creation ---- */
	{ "sync_server_thread_args", [](void)->int { setup(0, 1); hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server);
		return n && pc.calls == 1 && pc.arg == n && pc.t == &n->listener_tid && pc.fn == hcre_server_func_addr(); }, 1 },
	{ "sync_server_pthread_fails_returns_null", [](void)->int { setup(1, 1); hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server);
		if (n) { FAIL_("returned node although pthread_create failed"); }
		if (pc.calls != 1) { FAIL_("pthread calls %d", pc.calls); }
		return strstr(hipc_log_buf, "Failed to create") != NULL; }, 1 },
	{ "sync_server_pthread_fails_log_text", [](void)->int { setup(1, 0); call(hal_ipc_node_type_sync_call_server);
		return strstr(hipc_log_buf, "rdk_create_hal_ipc_node") != NULL && hipc_log_buf[strlen(hipc_log_buf) - 1] == '\n'; }, 1 },
	{ "notification_client_pthread_failure_irrelevant", [](void)->int { return ok_type(hal_ipc_node_type_notification_client, NOTIF_PATH, 0, 1, 1); }, 1 },
	{ "rejected_types_never_start_thread", [](void)->int { int n = 0;
		for (int t = 0; t < hal_ipc_node_type_max; t++) { setup(0, 0); call(t); n += pc.calls; } return n == 1; }, 1 },
	{ "sync_server_listener_tid_set", [](void)->int { setup(0, 0); hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server); return n && n->listener_tid == (pthread_t)(0xABC1); }, 1 },
	{ "notification_client_no_listener_tid", [](void)->int { setup(0, 0); hal_ipc_node_t *n = call(hal_ipc_node_type_notification_client); return n && n->listener_tid == 0; }, 1 },
	/* ---- pre-filled / stale node content ---- */
	{ "stale_path_63_x_overwritten", [](void)->int { setup(0, 0); memset(NODES[hal_ipc_node_type_sync_call_server].node_path, 'x', 63);
		hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server); return n && !strcmp(n->node_path, SYNC_PATH); }, 1 },
	{ "stale_path_64_x_unterminated_overwritten", [](void)->int { setup(0, 0); memset(NODES[hal_ipc_node_type_notification_client].node_path, 'x', 64);
		hal_ipc_node_t *n = call(hal_ipc_node_type_notification_client); return n && !strcmp(n->node_path, NOTIF_PATH); }, 1 },
	{ "stale_type_overwritten", [](void)->int { setup(0, 0); NODES[hal_ipc_node_type_sync_call_server].type = (hal_ipc_node_type_t)77;
		hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server); return n && n->type == hal_ipc_node_type_sync_call_server; }, 1 },
	{ "path_fits_in_node_path_64", [](void)->int { return strlen(SYNC_PATH) < 64 && strlen(NOTIF_PATH) < 64; }, 1 },
	{ "path_nul_terminated_inside_array", [](void)->int { setup(0, 1); hal_ipc_node_t *n = call(hal_ipc_node_type_notification_client);
		return n && memchr(n->node_path, 0, sizeof(n->node_path)) != NULL; }, 1 },
	/* ---- repeated calls / combinations ---- */
	{ "sync_server_twice_same_node", [](void)->int { setup(0, 0); hal_ipc_node_t *a = call(hal_ipc_node_type_sync_call_server), *b = call(hal_ipc_node_type_sync_call_server);
		return a && a == b && pc.calls == 2; }, 1 },
	{ "client_then_server_distinct_nodes", [](void)->int { setup(0, 0); hal_ipc_node_t *a = call(hal_ipc_node_type_notification_client), *b = call(hal_ipc_node_type_sync_call_server);
		return a && b && a != b && !strcmp(a->node_path, NOTIF_PATH) && !strcmp(b->node_path, SYNC_PATH); }, 1 },
	{ "server_fail_then_retry_ok", [](void)->int { setup(1, 0); call(hal_ipc_node_type_sync_call_server); pc.fail = 0;
		hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server); return n && !strcmp(n->node_path, SYNC_PATH); }, 1 },
	{ "rejected_then_valid", [](void)->int { setup(0, 0); call(hal_ipc_node_type_notification_server);
		hal_ipc_node_t *n = call(hal_ipc_node_type_sync_call_server); return n && n == &NODES[2]; }, 1 },
	{ "rejected_nodes_have_empty_path", [](void)->int { setup(0, 0); call(hal_ipc_node_type_notification_server); call(hal_ipc_node_type_sync_call_sm_client); call(hal_ipc_node_type_sync_call_bm_client);
		return NODES[0].node_path[0] == 0 && NODES[3].node_path[0] == 0 && NODES[4].node_path[0] == 0; }, 1 },
	{ "all_five_types_in_order", [](void)->int { setup(0, 0); int ok = 0; for (int t = 0; t < hal_ipc_node_type_max; t++) ok += call(t) != NULL; return ok == 2 && pc.calls == 1; }, 1 },
	{ "log_empty_on_success", [](void)->int { setup(0, 0); call(hal_ipc_node_type_notification_client); return hipc_log_buf[0] == 0; }, 1 },
	{ "log_text_rejected", [](void)->int { setup(0, 0); call(hal_ipc_node_type_notification_server); return strstr(hipc_log_buf, "Invalid node type") != NULL; }, 1 },
	{ "node_array_index_equals_type", [](void)->int { setup(0, 0); for (int t = 0; t < hal_ipc_node_type_max; t++) { hal_ipc_node_t *n = call(t); if (n && n != &NODES[t]) return 0; } return 1; }, 1 },
	/* ---- crash group (forked): type used as an index before it is validated ---- */
	{ "crash_type_max",       [](void)->int { return run_forked_type(hal_ipc_node_type_max); }, 1 },
	{ "crash_type_neg1",      [](void)->int { return run_forked_type(-1); }, 1 },
	{ "crash_type_max_plus1", [](void)->int { return run_forked_type(hal_ipc_node_type_max + 1); }, 1 },
	{ "crash_type_99",        [](void)->int { return run_forked_type(99); }, 1 },
	{ "crash_type_255",       [](void)->int { return run_forked_type(255); }, 1 },
	{ "crash_type_65536",     [](void)->int { return run_forked_type(65536); }, 1 },
	{ "crash_type_int_max",   [](void)->int { return run_forked_type(INT_MAX); }, 1 },
	{ "crash_type_int_min",   [](void)->int { return run_forked_type(INT_MIN); }, 1 },
	{ NULL, NULL, 0 }
};

static const hcre_test_case_t *cur_tc;
void construct_rdk_create_hal_ipc_node_input(const hcre_test_case_t *tc) { cur_tc = tc; hipc_exec_why[0] = 0; }
int rdk_create_hal_ipc_node_run_current(void) { return cur_tc->scenario(); }
