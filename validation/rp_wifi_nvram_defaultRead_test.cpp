/*
 * TEST RUNNER: rp_wifi_nvram_defaultRead_test
 *
 * Same shape as the other *_test.cpp runners: test_rp_wifi_nvram_defaultRead() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  The runner owns the output slot: a 64-byte canary slab (0x5A) with the output at offset 16 whose size is EXACTLY the expected
 * value plus its NUL (like a caller's right-sized buffer).  During the call the bytes before and after that slot are POISONED (a write beyond the value aborts under
 * ASan), together with the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The key is a heap string of exactly the requested length (an over-read of the
 * key aborts too).  Checks: return value; *out == expected value on success / still the canary otherwise; the command passed to _syscmd is exactly
 * "grep '<key>=' /nvram/wifi_defaults.txt" for keys that fit; one _syscmd call per function call; the guard slab.  Rows with last = 1 crash the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_nvd.h"
#include <sanitizer/asan_interface.h>

#define OFF 16
static unsigned char slab[64];
static char why[240];

static void poison(int on, const hwr_nvd_case_t *t, size_t out_sz)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->out_mode) {
		fn(&slab[0], OFF);
		fn(&slab[OFF + out_sz], sizeof(slab) - OFF - out_sz);
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_rp_wifi_nvram_defaultRead(const hwr_nvd_case_t *t, char *key, size_t out_sz)
{
	char *out = t->out_mode ? (char *)&slab[OFF] : NULL;
	int ret = 0;

	poison(1, t, out_sz);
	for (int i = 0; i < t->calls; i++) ret = hwr_rp_wifi_nvram_defaultRead(key, out);
	poison(0, t, out_sz);
	return ret;
}

static int check(const hwr_nvd_case_t *t, const char *key, int ret, size_t out_sz)
{
	const hwr_nvd_world_t *w = &hwr_nvd_world;
	char want[64];

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (w->calls != t->calls) { snprintf(why, sizeof(why), "_syscmd called %d times, expected %d", w->calls, t->calls); return 0; }
	if (strlen(key) + 33 <= 1023) {
		char *cmd = (char *)malloc(strlen(key) + 64);
		snprintf(cmd, strlen(key) + 64, "grep '%s=' /nvram/wifi_defaults.txt", key);
		int bad = strcmp(w->cmd, cmd) != 0;
		free(cmd);
		if (bad) { snprintf(why, sizeof(why), "wrong command passed to _syscmd (length %lu)", w->cmd_len); return 0; }
	} else if (w->cmd_len > 1023) { snprintf(why, sizeof(why), "command of %lu bytes does not fit cmd[1024]", w->cmd_len); return 0; }
	for (size_t k = 0; k < sizeof(slab); k++)
		if ((k < OFF || k >= OFF + out_sz) && slab[k] != 0x5A) { snprintf(why, sizeof(why), "canary byte %zu modified", k); return 0; }
	if (t->expected_ret == 0) {
		if (strcmp((char *)&slab[OFF], t->expected_out) != 0) { snprintf(why, sizeof(why), "out = '%s', expected '%s'", (char *)&slab[OFF], t->expected_out); return 0; }
	} else {
		memset(want, 0x5A, out_sz);
		if (memcmp(&slab[OFF], want, out_sz) != 0) { snprintf(why, sizeof(why), "out was modified on an error return"); return 0; }
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static int run_one(const hwr_nvd_case_t *t)
{
	size_t key_len = t->key_len >= 0 ? (size_t)t->key_len : strlen(t->key_text);
	char *key = (char *)malloc(key_len + 1);          /* exact-size heap key */
	size_t out_sz = t->expected_ret == 0 ? strlen(t->expected_out) + 1 : 8;
	int ok;

	printf("--- Running Test: %s ---\n", t->test_name);
	if (t->key_len >= 0) { memset(key, 'k', key_len); key[key_len] = 0; } else memcpy(key, t->key_text, key_len + 1);

	memset(&hwr_nvd_world, 0, sizeof(hwr_nvd_world));
	hwr_nvd_world.reply = t->reply;
	hwr_nvd_world.ret = t->syscmd_ret;
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(slab, 0x5A, sizeof(slab));

	why[0] = 0;
	int ret = test_rp_wifi_nvram_defaultRead(t, key, out_sz);
	ok = check(t, key, ret, out_sz);

	free(key);
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, ret, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_rp_wifi_nvram_defaultRead(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, crash rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; rp_wifi_nvram_defaultRead_suite[i].test_name != NULL; i++) {
			if (rp_wifi_nvram_defaultRead_suite[i].last != last) continue;
			if (run_one(&rp_wifi_nvram_defaultRead_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_nvram_defaultRead (raspberry-pi / wifi-emulator): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
