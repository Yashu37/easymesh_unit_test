/*
 * TEST RUNNER: wifi_hal_getApAssociatedDeviceRxStatsResult_test
 *
 * The runner owns the five arguments in separate slabs, POISONS their tails, calls the function, UNPOISONS
 * and checks the result (the stats array itself is allocated by the platform stub and freed by the runner):
 *   hwr_mac_slab    : [sizeof(mac_address_t), end)     hwr_arr_slab  : [sizeof(ptr), end)
 *   hwr_size_slab   : [sizeof(UINT), end)              hwr_handle_slab : [sizeof(ULLONG), end)
 *   hwr_log_buf     : [HWR_LOG_USE, HWR_LOG_SZ)
 * Out parameters are preset to 0xDEAD / NULL, so "platform failed but the wrapper said success" leaves the
 * caller with garbage.  Rows flagged `forked` are expected to crash the unfixed function (NULL pointer):
 * they run in a child so the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_grx.h"
#include <sanitizer/asan_interface.h>

typedef wifi_associated_dev_rate_info_rx_stats_t entry_t;
#define PADB 64
static unsigned char hwr_mac_slab[sizeof(mac_address_t) + PADB];
static unsigned char hwr_arr_slab[sizeof(entry_t *) + PADB];
static unsigned char hwr_size_slab[sizeof(UINT) + PADB];
static unsigned char hwr_handle_slab[sizeof(ULLONG) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[sizeof(mac_address_t)], PADB);
	fn(&hwr_arr_slab[sizeof(entry_t *)], PADB);
	fn(&hwr_size_slab[sizeof(UINT)], PADB);
	fn(&hwr_handle_slab[sizeof(ULLONG)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_grx_case_t *t)
{
	mac_address_t *mac = t->null_mask & 1 ? NULL : (mac_address_t *)hwr_mac_slab;
	entry_t **arr = t->null_mask & 2 ? NULL : (entry_t **)hwr_arr_slab;
	UINT *size = t->null_mask & 4 ? NULL : (UINT *)hwr_size_slab;
	ULLONG *handle = t->null_mask & 8 ? NULL : (ULLONG *)hwr_handle_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, "\x02\x11\x22\x33\x44\x55", 6);
	memset(hwr_log_buf, 0, HWR_LOG_USE);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		memset(hwr_arr_slab, 0, sizeof(hwr_arr_slab)); memset(hwr_size_slab, 0, sizeof(hwr_size_slab)); memset(hwr_handle_slab, 0, sizeof(hwr_handle_slab));
		hwr_grx_configure(t->callee_ret, t->n_entries);
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getApAssociatedDeviceRxStatsResult(t->radio_index, mac, arr, size, handle); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on a NULL pointer)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for the NULL pointer"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		entry_t *got;
		memset(hwr_arr_slab, 0, sizeof(hwr_arr_slab)); memset(hwr_size_slab, 0, sizeof(hwr_size_slab)); memset(hwr_handle_slab, 0, sizeof(hwr_handle_slab));
		*(UINT *)hwr_size_slab = 0xDEAD; *(entry_t **)hwr_arr_slab = NULL;
		hwr_grx_configure(t->callee_ret, t->n_entries);
		poison_all(1);
		ret = hwr_wifi_hal_getApAssociatedDeviceRxStatsResult(t->radio_index, mac, arr, size, handle);
		poison_all(0);
		got = *(entry_t **)hwr_arr_slab;
		if (ret != t->expected_ret) {
			snprintf(why, sizeof(why), "call %d returned %d, platform returned %d%s", i, ret, t->callee_ret, ret == 0 && t->callee_ret != 0 ? " (failure reported as success; *output_array_size left as 0xDEAD)" : "");
			free(got); return 0;
		}
		if (hwr_grx_rec.calls != 1 || hwr_grx_rec.radio != t->radio_index || hwr_grx_rec.mac != mac || hwr_grx_rec.arr != arr || hwr_grx_rec.size != size || hwr_grx_rec.handle != handle) { snprintf(why, sizeof(why), "arguments not forwarded unchanged"); free(got); return 0; }
		if (t->callee_ret == 0) {
			if (*(UINT *)hwr_size_slab != t->n_entries) { snprintf(why, sizeof(why), "*output_array_size %u, expected %u", *(UINT *)hwr_size_slab, t->n_entries); free(got); return 0; }
			if ((got == NULL) != (t->n_entries == 0)) { snprintf(why, sizeof(why), "stats array pointer %p for %u entries", (void *)got, t->n_entries); free(got); return 0; }
			if (got && (((unsigned char *)got)[0] != 0x3C || ((unsigned char *)got)[t->n_entries * sizeof(entry_t) - 1] != 0x3C)) { snprintf(why, sizeof(why), "entries not filled"); free(got); return 0; }
			if (*(ULLONG *)hwr_handle_slab != 0x1234) { snprintf(why, sizeof(why), "handle %llx", *(unsigned long long *)hwr_handle_slab); free(got); return 0; }
		}
		free(got);
	}
	if (memcmp(hwr_mac_slab, "\x02\x11\x22\x33\x44\x55", 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_getApAssociatedDeviceRxStatsResult") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceRxStatsResult(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getApAssociatedDeviceRxStatsResult_suite[i].test_name != NULL; i++) {
		hwr_grx_case_t *test = &wifi_hal_getApAssociatedDeviceRxStatsResult_suite[i];

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
	printf("\nwifi_hal_getApAssociatedDeviceRxStatsResult: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
