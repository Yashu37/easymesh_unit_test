/*
 * TEST RUNNER: ipc_client_notification_input_test
 *
 * The runner builds the request via the suite row's setup(), POISONS the runner-owned buffers,
 * calls ipc_client_notification_input(), UNPOISONS, then checks the return value, the leak counter
 * and the row's verify():
 *   hcn_desc_slab    : [0, HCN_PAD) and [HCN_PAD + sizeof(desc), end)   - around the descriptor
 *   hcn_arg_slab[i]  : [hcn_arg_len[i], HCN_ARG_SZ)                     - past each argument's valid bytes
 *   hcn_log_buf      : [HCN_LOG_USE, HCN_LOG_SZ)                        - unused part of the log slot
 * Rows flagged `forked` are expected to crash the unfixed function: they run in a child so the
 * ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hcn_defs.h"
#include <sanitizer/asan_interface.h>

#define SZ  (sizeof(hal_ipc_processor_desc_t))

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hcn_desc_slab, HCN_PAD);
	fn(&hcn_desc_slab[HCN_PAD + SZ], HCN_PAD);
	for (int i = 0; i < 5; i++) fn(&hcn_arg_slab[i][hcn_arg_len[i]], HCN_ARG_SZ - hcn_arg_len[i]);
	fn(&hcn_log_buf[HCN_LOG_USE], HCN_LOG_SZ - HCN_LOG_USE);
}

static char why[256];

static int call(hcn_req_t *r)
{
	return ipc_client_notification_input_entry(r->d, r->a[0], r->a[1], r->a[2], r->a[3], r->a[4]);
}

static int run_case(const hcn_case_t *t)
{
	hcn_req_t r;
	int ret;

	why[0] = 0;
	memset(hcn_desc_slab, 0, sizeof(hcn_desc_slab));
	r.d = (hal_ipc_processor_desc_t *)(hcn_desc_slab + HCN_PAD);
	t->setup(&r);

	if (t->forked) {                                         /* ASan abort stays visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = call(&r); _exit(ret == t->exp_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (r.d && r.d->scratch_buf) hcn_free(r.d->scratch_buf);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (ASan abort / signal %d)", WIFSIGNALED(st) ? WTERMSIG(st) : 0); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child returned the wrong value (expected %d)", t->exp_ret); return 0; }
		return 1;
	}

	poison_all(1);
	ret = call(&r);
	poison_all(0);

	if (ret != t->exp_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->exp_ret); if (ret == 0 && r.d->len > SZ) hcn_free(r.d->scratch_buf); return 0; }
	if (t->verify && !t->verify(r.d, ret)) { snprintf(why, sizeof(why), "descriptor content wrong (len=%u scratch=%u)", r.d->len, r.d->scratch_buf_size); if (ret == 0 && r.d->len > SZ) hcn_free(r.d->scratch_buf); return 0; }
	if (ret == 0 && r.d->len > SZ) hcn_free(r.d->scratch_buf);   /* the scratch buffer is released after it has been sent */
	if (hcn_outstanding != 0) { snprintf(why, sizeof(why), "%d allocation(s) leaked", hcn_outstanding); return 0; }
	return 1;
}

void run_all_tests_ipc_client_notification_input(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; ipc_client_notification_input_suite[i].test_name != NULL; i++) {
		hcn_case_t *test = &ipc_client_notification_input_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nipc_client_notification_input: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
