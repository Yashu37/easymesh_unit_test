/*
 * TEST RUNNER: wifi_hal_getSSIDNumberOfEntries_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radios, interface maps, interfaces) in
 * runner-owned slabs, POISONS their tails, calls the function, UNPOISONS and checks the result:
 *   hwr_radio_slab : [num_radios * sizeof(radio), end)        - radios past the used ones
 *   hwr_iface_slab : [used interfaces * sizeof(iface), end)   - interfaces past the used ones
 *   hwr_map_slab   : [num_radios * sizeof(map), end)
 *   hwr_out_slab   : [sizeof(ULONG), end)                     - *numEntries is the only 8 bytes it may write
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` are expected to crash the unfixed function (NULL numEntries): they run in a child so
 * the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_ssid.h"
#include <sanitizer/asan_interface.h>

static hwr_radio_t    hwr_radio_slab[HWR_MAX_RADIOS + 4];
static hwr_iface_t    hwr_iface_slab[HWR_MAX_IFACES + 4];
static hwr_hash_map_t hwr_map_slab[HWR_MAX_RADIOS + 2];
static unsigned long  hwr_out_slab[8];
static int used_ifaces, used_radios;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], (sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_radio_t)));
	fn(&hwr_iface_slab[used_ifaces], (sizeof(hwr_iface_slab) - used_ifaces * sizeof(hwr_iface_t)));
	fn(&hwr_map_slab[used_radios], (sizeof(hwr_map_slab) - used_radios * sizeof(hwr_hash_map_t)));
	fn(&hwr_out_slab[1], sizeof(hwr_out_slab) - sizeof(hwr_out_slab[0]));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static void build(const hwr_ssid_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_iface_slab, 0, sizeof(hwr_iface_slab));
	memset(hwr_map_slab, 0, sizeof(hwr_map_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_ifaces = 0; used_radios = t->nradios;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].rdk_radio_index = t->r[r].rdk_index;
		hwr_radio_slab[r].interface_map = &hwr_map_slab[r];
		for (int k = 0; k < t->r[r].n; k++) {
			hwr_iface_t *f = &hwr_iface_slab[used_ifaces++];
			f->vap_info.vap_index = t->r[r].ifs[k].vap_index;
			f->vap_info.vap_mode = (wifi_vap_mode_t)(t->r[r].ifs[k].mode == 0 ? wifi_vap_mode_ap : t->r[r].ifs[k].mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor);
			hwr_map_slab[r].items[hwr_map_slab[r].n++] = f;
		}
	}
	hwr_g_wifi_hal.num_radios = t->nradios;
	hwr_g_wifi_hal.radio_info = hwr_radio_slab;
	hwr_out_slab[0] = t->preset_garbage ? 0xDEADBEEFUL : 0;
}

static int run_case(const hwr_ssid_case_t *t)
{
	INT ret = 0;

	why[0] = 0;
	build(t);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getSSIDNumberOfEntries(t->null_out ? NULL : &hwr_out_slab[0]); _exit(ret == -1 ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on NULL numEntries)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for NULL numEntries"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		poison_all(1);
		ret = hwr_wifi_hal_getSSIDNumberOfEntries(&hwr_out_slab[0]);
		poison_all(0);
		if (ret != 0) { snprintf(why, sizeof(why), "call %d returned %d", i, ret); return 0; }
		if (hwr_out_slab[0] != t->expected) { snprintf(why, sizeof(why), "call %d: count %lu, expected %lu", i, hwr_out_slab[0], t->expected); return 0; }
	}
	if (t->check_log) {
		char want[40]; snprintf(want, sizeof(want), "Num of SSIDs: %lu", t->expected);
		if (!strstr(hwr_log_buf, want)) { snprintf(why, sizeof(why), "log lacks '%s': '%s'", want, hwr_log_buf); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getSSIDNumberOfEntries(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getSSIDNumberOfEntries_suite[i].test_name != NULL; i++) {
		hwr_ssid_case_t *test = &wifi_hal_getSSIDNumberOfEntries_suite[i];

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
	printf("\nwifi_hal_getSSIDNumberOfEntries: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
