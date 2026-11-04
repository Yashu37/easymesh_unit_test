/*
 * TEST RUNNER: wifi_hal_getSSIDRadioIndex_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radios, interface maps, interfaces with the REAL
 * wifi_vap_info_t) in runner-owned slabs, POISONS their tails, calls the function, UNPOISONS and checks:
 *   hwr_iface_slab : [used interfaces * sizeof(iface), end)   - interfaces past the used ones
 *   hwr_radio_slab / hwr_map_slab : the radios / maps past the used ones
 *   hwr_out_slab   : [sizeof(INT), end)                      - *radioIndex is the only 4 bytes it may write
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * *radioIndex is preset to 0xA5A5A5A5 so "written" / "untouched" is visible.  Rows flagged `forked` are expected to
 * crash the unfixed function (NULL radioIndex): they run in a child so the ASan report is visible but the
 * run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gsr.h"
#include <sanitizer/asan_interface.h>

static hwr_gsr_radio_t hwr_radio_slab[HWR_GSR_MAX_RADIOS + 2];
static hwr_gsr_map_t   hwr_map_slab[HWR_GSR_MAX_RADIOS + 2];
static hwr_gsr_iface_t hwr_iface_slab[HWR_GSR_MAX_IFACES];
static unsigned char   hwr_out_slab[64];
static int used_ifaces, used_radios;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_gsr_radio_t));
	fn(&hwr_map_slab[used_radios], sizeof(hwr_map_slab) - used_radios * sizeof(hwr_gsr_map_t));
	fn(&hwr_iface_slab[used_ifaces], sizeof(hwr_iface_slab) - used_ifaces * sizeof(hwr_gsr_iface_t));
	fn(&hwr_out_slab[sizeof(INT)], sizeof(hwr_out_slab) - sizeof(INT));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static void build(const hwr_gsr_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_map_slab, 0, sizeof(hwr_map_slab));
	memset(hwr_iface_slab, 0, sizeof(hwr_iface_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_ifaces = 0; used_radios = t->nradios;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].interface_map = &hwr_map_slab[r];
		for (int k = 0; k < t->r[r].n; k++) {
			hwr_gsr_iface_t *f = &hwr_iface_slab[used_ifaces++];
			const hwr_gsr_if_t *s = &t->r[r].ifs[k];
			f->vap_info.vap_index = s->vap_index;
			f->vap_info.vap_mode = (wifi_vap_mode_t)(s->mode == 0 ? wifi_vap_mode_ap : s->mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor);
			f->vap_info.radio_index = s->radio_index;
			hwr_map_slab[r].items[hwr_map_slab[r].n++] = f;
		}
	}
	hwr_gsr_world.num_radios = t->nradios;
	hwr_gsr_world.radio_info = hwr_radio_slab;
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
}

static int run_case(const hwr_gsr_case_t *t)
{
	INT *out = t->null_out ? NULL : (INT *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	build(t);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getSSIDRadioIndex(t->query, out); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on NULL radioIndex)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for NULL radioIndex"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		poison_all(1);
		ret = hwr_wifi_hal_getSSIDRadioIndex(t->query, out);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (t->expected_out == LLONG_MIN) {
			if (!t->null_out && *(INT *)hwr_out_slab != (INT)0xA5A5A5A5) { snprintf(why, sizeof(why), "*radioIndex written (%d) although the call failed", *(INT *)hwr_out_slab); return 0; }
		} else if (*(INT *)hwr_out_slab != (INT)t->expected_out) { snprintf(why, sizeof(why), "*radioIndex = %d, expected %lld", *(INT *)hwr_out_slab, t->expected_out); return 0; }
		for (int k = sizeof(INT); k < 8 + (int)sizeof(INT); k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %d behind *radioIndex modified", k); return 0; }
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getSSIDRadioIndex") || !strstr(hwr_log_buf, "Enter") && !strstr(hwr_log_buf, "not found"))) { snprintf(why, sizeof(why), "log lacks function name / message: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getSSIDRadioIndex(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getSSIDRadioIndex_suite[i].test_name != NULL; i++) {
		hwr_gsr_case_t *test = &wifi_hal_getSSIDRadioIndex_suite[i];

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
	printf("\nwifi_hal_getSSIDRadioIndex: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
