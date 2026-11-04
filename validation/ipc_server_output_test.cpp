/*
 * TEST RUNNER: ipc_server_output_test
 *
 * The runner builds the request via the suite row's setup(), POISONS the runner-owned
 * buffers, calls ipc_server_output(), UNPOISONS, then checks the return value, the leak
 * counter and the row's verify():
 *   hso_desc_slab : [0, HSO_PAD)                                  - head, before the descriptor
 *                   [HSO_PAD + sizeof(desc), end)                 - tail, after the descriptor
 *   hso_log_buf   : [HSO_LOG_USE, HSO_LOG_SZ)                     - unused part of the log slot
 * (client / response scratch buffers and the function's temporary arrays are real heap blocks
 * guarded by ASan's heap red-zones.)  Rows flagged `forked` are expected to crash the unfixed
 * function: they run in a child so the ASan report is visible but the run continues.
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hso_hal_ipc.h"
#include <sanitizer/asan_interface.h>

unsigned char hso_desc_slab[sizeof(hal_ipc_processor_desc_t) + 2 * HSO_PAD];

#define SZ  (sizeof(hal_ipc_processor_desc_t))

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hso_desc_slab, HSO_PAD);
	fn(&hso_desc_slab[HSO_PAD + SZ], HSO_PAD);
	fn(&hso_log_buf[HSO_LOG_USE], HSO_LOG_SZ - HSO_LOG_USE);
}

static char why[256];

static int run_case(const hso_case_t *t)
{
	hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)(hso_desc_slab + HSO_PAD);
	int ret;

	why[0] = 0;
	memset(hso_desc_slab, 0, sizeof(hso_desc_slab));
	t->setup(d);

	if (t->forked) {                                         /* ASan abort stays visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = ipc_server_output_entry(d); _exit(ret == t->exp_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (d->scratch_buf) hso_free(d->scratch_buf);          /* the client buffer built by setup() in the parent */
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (ASan abort / signal %d)", WIFSIGNALED(st) ? WTERMSIG(st) : 0); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child returned the wrong value (expected %d)", t->exp_ret); return 0; }
		return 1;
	}

	poison_all(1);
	ret = ipc_server_output_entry(d);
	poison_all(0);

	if (ret != t->exp_ret) { snprintf(why, sizeof(why), "returned %d, expected %d (desc.ret=%d)", ret, t->exp_ret, d->ret); if (ret == 0 && d->len > SZ) hso_free(d->scratch_buf); return 0; }
	if (t->verify && !t->verify(d, ret)) { snprintf(why, sizeof(why), "response content wrong (len=%u scratch=%u)", d->len, d->scratch_buf_size); if (ret == 0 && d->len > SZ) hso_free(d->scratch_buf); return 0; }
	if (ret == 0 && d->len > SZ) hso_free(d->scratch_buf);     /* what rdk_hal_server_func does after sending the reply */
	if (hso_outstanding != 0) { snprintf(why, sizeof(why), "%d allocation(s) leaked", hso_outstanding); return 0; }
	return 1;
}

void run_all_tests_ipc_server_output(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; ipc_server_output_suite[i].test_name != NULL; i++) {
		hso_case_t *test = &ipc_server_output_suite[i];

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
	printf("\nipc_server_output: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
