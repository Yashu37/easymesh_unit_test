/*
 * TEST RUNNER: wifi_hal_getApAssociatedDeviceStats_test
 *
 * The runner builds the arguments in runner-owned slabs, POISONS their tails, calls the function, UNPOISONS
 * and checks the result:
 *   hwr_mac_slab    : [sizeof(mac_address_t), end)                       - the client MAC (6 bytes)
 *   hwr_stats_slab  : [sizeof(wifi_associated_dev_stats_t), end)         - the statistics output
 *   hwr_handle_slab : [sizeof(ULLONG), end)                              - the handle output
 *   hwr_log_buf     : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` are expected to crash the unfixed function (NULL output pointer): they run in a
 * child so the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gas.h"
#include <sanitizer/asan_interface.h>

void hwr_gas_configure(int callee_ret, unsigned long long handle_val);

#define PADB 64
static unsigned char hwr_mac_slab[sizeof(mac_address_t) + PADB];
static unsigned char hwr_stats_slab[sizeof(wifi_associated_dev_stats_t) + PADB];
static unsigned char hwr_handle_slab[sizeof(ULLONG) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[sizeof(mac_address_t)], PADB);
	fn(&hwr_stats_slab[sizeof(wifi_associated_dev_stats_t)], PADB);
	fn(&hwr_handle_slab[sizeof(ULLONG)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_gas_case_t *t)
{
	mac_address_t *mac = t->null_mask & 1 ? NULL : (mac_address_t *)hwr_mac_slab;
	wifi_associated_dev_stats_t *stats = t->null_mask & 2 ? NULL : (wifi_associated_dev_stats_t *)hwr_stats_slab;
	ULLONG *handle = t->null_mask & 4 ? NULL : (ULLONG *)hwr_handle_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, "\x02\x11\x22\x33\x44\x55", 6);
	memset(hwr_stats_slab, 0, sizeof(hwr_stats_slab));
	memset(hwr_handle_slab, 0, sizeof(hwr_handle_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	hwr_gas_configure(t->callee_ret, t->handle_val);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getApAssociatedDeviceStats(t->ap_index, mac, stats, handle); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on a NULL output pointer)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for the NULL pointer"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		poison_all(1);
		ret = hwr_wifi_hal_getApAssociatedDeviceStats(t->ap_index, mac, stats, handle);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, platform returned %d%s", i, ret, t->callee_ret, ret == 0 && t->callee_ret != 0 ? " (failure reported as success)" : ""); return 0; }
	}
	if (hwr_gas_rec.calls != t->calls) { snprintf(why, sizeof(why), "platform function called %d times", hwr_gas_rec.calls); return 0; }
	if (hwr_gas_rec.ap_index != t->ap_index || hwr_gas_rec.mac != mac || hwr_gas_rec.stats != stats || hwr_gas_rec.handle != handle) { snprintf(why, sizeof(why), "arguments not forwarded unchanged"); return 0; }
	if (*handle != t->handle_val) { snprintf(why, sizeof(why), "handle %llx", (unsigned long long)*handle); return 0; }
	if (memcmp(hwr_mac_slab, "\x02\x11\x22\x33\x44\x55", 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (hwr_stats_slab[0] != 0x3C || hwr_stats_slab[sizeof(wifi_associated_dev_stats_t) - 1] != 0x3C) { snprintf(why, sizeof(why), "stats not filled"); return 0; }
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_getApAssociatedDeviceStats") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getApAssociatedDeviceStats(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getApAssociatedDeviceStats_suite[i].test_name != NULL; i++) {
		hwr_gas_case_t *test = &wifi_hal_getApAssociatedDeviceStats_suite[i];

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
	printf("\nwifi_hal_getApAssociatedDeviceStats: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
