/*
 * TEST RUNNER: cleanup_desc_scratch_buf_test
 *
 * The runner itself builds the descriptor from the suite row, POISONS the
 * runner-owned buffers, calls the function, UNPOISONS and verifies:
 *   hcd_desc_slab : [desc_offset + sizeof(hal_ipc_processor_desc_t), end)  - tail past the descriptor
 *                   (the head [0, desc_offset) is poisoned too, so an access before the struct is caught)
 *   hipc_log_buf  : [HIPC_LOG_USE, HIPC_LOG_SZ)
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

#define SZ (sizeof(hal_ipc_processor_desc_t))

static void poison_all(int on, int off)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (off) fn(hcd_desc_slab, off);
	fn(&hcd_desc_slab[off + SZ], sizeof(hcd_desc_slab) - off - SZ);
	fn(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);
}

static int run_case(const hcd_test_case_t *t)
{
	hal_ipc_processor_desc_t *d = (hal_ipc_processor_desc_t *)(hcd_desc_slab + t->desc_offset);
	unsigned char *heap = NULL, *want_ptr = NULL;
	unsigned char canary[SZ];
	int ok = 1;

	memset(hcd_desc_slab, 0, sizeof(hcd_desc_slab));
	hipc_exec_why[0] = 0;
	memset(d, 0, SZ);
	for (size_t i = 0; i < SZ; i++) ((unsigned char *)d)[i] = (unsigned char)(i * 13 + 5);   /* canary every byte */
	switch (t->buf_kind) {
	case HCD_BUF_HEAP:    heap = (unsigned char *)malloc(64); want_ptr = heap; break;
	case HCD_BUF_GARBAGE: want_ptr = (unsigned char *)(uintptr_t)0xDEADBEEF; break;
	case HCD_BUF_SLAB:    want_ptr = hcd_desc_slab; break;
	default: break;
	}
	d->scratch_buf = want_ptr;
	d->scratch_buf_size = t->size;
	memcpy(canary, d, SZ);

	if (t->null_desc) {                                         /* forked: SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1, 0);
		pid = fork();
		if (pid == 0) { cleanup_desc_scratch_buf_entry(NULL); _exit(0); }
		waitpid(pid, &st, 0);
		poison_all(0, 0);
		if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) { snprintf(hipc_exec_why, 256, "NULL desc: child died (SEGV)"); return 0; }
		return 1;
	}

	poison_all(1, t->desc_offset);
	for (int i = 0; i < t->calls; i++) cleanup_desc_scratch_buf_entry(d);
	poison_all(0, t->desc_offset);

	if (d->scratch_buf != NULL) { snprintf(hipc_exec_why, 256, "scratch_buf not NULL (%p)", (void *)d->scratch_buf); ok = 0; }
	else if (d->scratch_buf_size != 0) { snprintf(hipc_exec_why, 256, "scratch_buf_size = %u", d->scratch_buf_size); ok = 0; }
	else {
		size_t po = offsetof(hal_ipc_processor_desc_t, scratch_buf);              /* every byte before scratch_buf must be unchanged */
		if (memcmp(d, canary, po)) { snprintf(hipc_exec_why, 256, "fields before scratch_buf modified"); ok = 0; }
	}
	if (heap) free(heap);                                       /* still valid: the function must not have freed it */
	return ok;
}

void run_all_tests_cleanup_desc_scratch_buf(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; cleanup_desc_scratch_buf_suite[i].test_name != NULL; i++) {
		hcd_test_case_t *test = &cleanup_desc_scratch_buf_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == test->expected_result) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n",
			       test->test_name, test->expected_result, ret, hipc_exec_why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\ncleanup_desc_scratch_buf: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
