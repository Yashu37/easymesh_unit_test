/*
 * UNIT TEST (input constructor): construct_cleanup_client_data
 *
 * cleanup_client_data(unsigned char **client_scratch_buf, int client_data_len)
 * frees the client's scratch buffer and NULLs the caller's pointer, but only
 * when client_data_len > sizeof(hal_ipc_processor_desc_t) (a scratch buffer was
 * appended to the descriptor) and the pointer is non-NULL.  Note the comparison
 * is int vs size_t, so a negative length converts to a huge unsigned value
 * (callers pass desc->len, an unsigned int, through an int).
 *
 * The unsigned char * lives in the runner-owned hcc_slot_slab (tail poisoned);
 * the heap blocks are real malloc()s guarded by ASan's red-zones; free() is a
 * counting stub that still calls the real free (so a double / invalid free is
 * reported).  Inputs crossed (representative, capped at 50): 13 lengths
 * (INT_MIN .. sizeof-1 / sizeof / sizeof+1 .. INT_MAX) x {heap buffer, NULL
 * buffer}, block sizes 1 / 16 / 30000, repeated calls, and a NULL
 * pointer-to-pointer (forked, so the SEGV is visible but does not stop the run).
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"

unsigned char hcc_slot_slab[sizeof(unsigned char *) + HIPC_PAD];
int   hcc_free_calls;
void *hcc_free_last;
void (*hcc_poison_fn)(int on);

#define SLOT   ((unsigned char **)hcc_slot_slab)
#define SZ_DESC ((long)sizeof(hal_ipc_processor_desc_t))

void hcc_stub_free(void *p) { hcc_free_calls++; hcc_free_last = p; free(p); }

#define FAIL_(...) do { snprintf(hipc_exec_why, 256, __VA_ARGS__); return 0; } while (0)

/* callers pass desc->len (unsigned) through an int: negative == huge, so it frees */
static int expect_free(long len) { return (size_t)(int)len > sizeof(hal_ipc_processor_desc_t); }

static int run_len(long len, int with_buf, size_t blk)
{
	unsigned char *b = NULL;
	int want = with_buf && expect_free(len);

	hcc_free_calls = 0; hcc_free_last = NULL; hipc_exec_why[0] = 0;
	memset(hcc_slot_slab, 0, sizeof(hcc_slot_slab));
	if (with_buf) { b = (unsigned char *)malloc(blk); memset(b, 0xA5, blk); }
	*SLOT = b;

	if (hcc_poison_fn) hcc_poison_fn(1);
	cleanup_client_data_entry(SLOT, (int)len);
	if (hcc_poison_fn) hcc_poison_fn(0);

	if (want) {
		if (hcc_free_calls != 1 || hcc_free_last != b) FAIL_("len %ld: free calls=%d (expected 1 of the buffer)", len, hcc_free_calls);
		if (*SLOT != NULL) FAIL_("len %ld: caller pointer not NULLed", len);
	} else {
		if (hcc_free_calls != 0) FAIL_("len %ld: free called %d times (not expected)", len, hcc_free_calls);
		if (*SLOT != b) FAIL_("len %ld: caller pointer changed", len);
		if (b) { for (size_t i = 0; i < blk; i++) if (b[i] != 0xA5) FAIL_("buffer modified"); free(b); }
	}
	return 1;
}

static int run_twice(long len)                              /* second call must not double free */
{
	unsigned char *b = (unsigned char *)malloc(64);
	hcc_free_calls = 0; hipc_exec_why[0] = 0;
	memset(hcc_slot_slab, 0, sizeof(hcc_slot_slab)); *SLOT = b;
	if (hcc_poison_fn) hcc_poison_fn(1);
	cleanup_client_data_entry(SLOT, (int)len);
	cleanup_client_data_entry(SLOT, (int)len);
	if (hcc_poison_fn) hcc_poison_fn(0);
	if (hcc_free_calls != 1) FAIL_("free called %d times over two calls", hcc_free_calls);
	return *SLOT == NULL;
}

static int run_null_slot_forked(long len)
{
	int st; pid_t pid;
	hcc_free_calls = 0; hipc_exec_why[0] = 0;
	fflush(stdout);
	if (hcc_poison_fn) hcc_poison_fn(1);
	pid = fork();
	if (pid == 0) { cleanup_client_data_entry(NULL, (int)len); _exit(0); }
	waitpid(pid, &st, 0);
	if (hcc_poison_fn) hcc_poison_fn(0);
	if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) FAIL_("NULL client_scratch_buf, len %ld: child died (SEGV)", len);
	return 1;
}

#define L(n, v)  { "len_" n "_heap_buf", [](void)->int { return run_len((v), 1, 64); }, 1 }, \
                 { "len_" n "_null_buf", [](void)->int { return run_len((v), 0, 0); }, 1 }
hcc_test_case_t cleanup_client_data_suite[] = {
	L("int_min",        INT_MIN),
	L("minus_1000",     -1000),
	L("minus_1",        -1),
	L("zero",           0),
	L("one",            1),
	L("100",            100),
	L("sizeof_minus_1", SZ_DESC - 1),
	L("sizeof",         SZ_DESC),
	L("sizeof_plus_1",  SZ_DESC + 1),
	L("sizeof_plus_100",SZ_DESC + 100),
	L("10240",          10240),
	L("100000",         100000),
	L("int_max",        INT_MAX),
	/* ---- block sizes / repeat ---- */
	{ "free_1_byte_block",            [](void)->int { return run_len(SZ_DESC + 1, 1, 1); }, 1 },
	{ "free_16_byte_block",           [](void)->int { return run_len(SZ_DESC + 16, 1, 16); }, 1 },
	{ "free_30000_byte_block",        [](void)->int { return run_len(SZ_DESC + 30000, 1, 30000); }, 1 },
	{ "no_free_30000_block_len_sizeof", [](void)->int { return run_len(SZ_DESC, 1, 30000); }, 1 },
	{ "twice_no_double_free",         [](void)->int { return run_twice(SZ_DESC + 64); }, 1 },
	{ "twice_small_len_no_free",      [](void)->int { return run_twice(SZ_DESC) == 0 ? 1 : 0; }, 1 },
	/* ---- crash group (forked): pointer-to-pointer is NULL ---- */
	{ "crash_null_slot_len_big",      [](void)->int { return run_null_slot_forked(SZ_DESC + 100); }, 1 },
	{ "crash_null_slot_len_zero",     [](void)->int { return run_null_slot_forked(0); }, 1 },
	{ NULL, NULL, 0 }
};

static const hcc_test_case_t *cur_tc;
void construct_cleanup_client_data_input(const hcc_test_case_t *tc) { cur_tc = tc; hipc_exec_why[0] = 0; }
int cleanup_client_data_run_current(void) { return cur_tc->scenario(); }
