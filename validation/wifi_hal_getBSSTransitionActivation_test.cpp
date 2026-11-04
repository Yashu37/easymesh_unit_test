/*
 * TEST RUNNER: wifi_hal_getBSSTransitionActivation_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radios, interface maps, interfaces with the REAL
 * wifi_vap_info_t) in runner-owned slabs, POISONS their tails, calls the function, UNPOISONS and checks:
 *   hwr_iface_slab : [used interfaces * sizeof(iface), end)   - interfaces past the used ones
 *   hwr_radio_slab / hwr_map_slab : the radios / maps past the used ones
 *   hwr_out_slab   : [1 byte (the BOOL), end)                 - *activate is the only byte it may write
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * *activate is preset to 0xA5 so "written" / "untouched" is visible.  Rows flagged `forked` are expected to
 * crash the unfixed function (NULL activate): they run in a child so the ASan report is visible but the
 * run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gbt.h"
#include <sanitizer/asan_interface.h>

static hwr_gbt_radio_t hwr_radio_slab[HWR_GBT_MAX_RADIOS + 2];
static hwr_gbt_map_t   hwr_map_slab[HWR_GBT_MAX_RADIOS + 2];
static hwr_gbt_iface_t hwr_iface_slab[HWR_GBT_MAX_IFACES];
static unsigned char   hwr_out_slab[64];
static int used_ifaces, used_radios;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_gbt_radio_t));
	fn(&hwr_map_slab[used_radios], sizeof(hwr_map_slab) - used_radios * sizeof(hwr_gbt_map_t));
	fn(&hwr_iface_slab[used_ifaces], sizeof(hwr_iface_slab) - used_ifaces * sizeof(hwr_gbt_iface_t));
	fn(&hwr_out_slab[sizeof(BOOL)], sizeof(hwr_out_slab) - sizeof(BOOL));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static void build(const hwr_gbt_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_map_slab, 0, sizeof(hwr_map_slab));
	memset(hwr_iface_slab, 0, sizeof(hwr_iface_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_ifaces = 0; used_radios = t->nradios;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].interface_map = &hwr_map_slab[r];
		for (int k = 0; k < t->r[r].n; k++) {
			hwr_gbt_iface_t *f = &hwr_iface_slab[used_ifaces++];
			const hwr_gbt_if_t *s = &t->r[r].ifs[k];
			f->vap_info.vap_index = s->vap_index;
			f->vap_info.vap_mode = (wifi_vap_mode_t)(s->mode == 0 ? wifi_vap_mode_ap : s->mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor);
			memset(&f->vap_info.u, s->fill, sizeof(f->vap_info.u));                 /* union bytes, then the member that is valid for the mode */
			if (s->mode == 0) f->vap_info.u.bss_info.bssTransitionActivated = (BOOL)s->enabled;
			hwr_map_slab[r].items[hwr_map_slab[r].n++] = f;
		}
	}
	hwr_gbt_world.num_radios = t->nradios;
	hwr_gbt_world.radio_info = hwr_radio_slab;
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
}

static int run_case(const hwr_gbt_case_t *t)
{
	BOOL *out = t->null_out ? NULL : (BOOL *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	build(t);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getBSSTransitionActivation((UINT)t->query, out); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on NULL activate)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for NULL activate"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		poison_all(1);
		ret = hwr_wifi_hal_getBSSTransitionActivation((UINT)t->query, out);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (t->expected_out < 0) {
			if (!t->null_out && hwr_out_slab[0] != 0xA5) { snprintf(why, sizeof(why), "*activate written (0x%02x) although the call failed", hwr_out_slab[0]); return 0; }
		} else if (hwr_out_slab[0] != (unsigned)t->expected_out) { snprintf(why, sizeof(why), "*activate = 0x%02x, expected %d", hwr_out_slab[0], t->expected_out); return 0; }
		for (int k = 1; k < 8; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %d behind *activate modified", k); return 0; }
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getBSSTransitionActivation") || !strstr(hwr_log_buf, "Enter") && !strstr(hwr_log_buf, "not found"))) { snprintf(why, sizeof(why), "log lacks function name / message: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getBSSTransitionActivation(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getBSSTransitionActivation_suite[i].test_name != NULL; i++) {
		hwr_gbt_case_t *test = &wifi_hal_getBSSTransitionActivation_suite[i];

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
	printf("\nwifi_hal_getBSSTransitionActivation: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
