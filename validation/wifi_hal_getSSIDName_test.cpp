/*
 * TEST RUNNER: wifi_hal_getSSIDName_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radios, interface maps, interfaces with the REAL
 * wifi_vap_info_t and the SSID bytes / union fill of the row) in runner-owned slabs, POISONS their tails, calls
 * the function, UNPOISONS and checks:
 *   hwr_iface_slab : [used interfaces * sizeof(iface), end)   - interfaces past the used ones
 *   hwr_radio_slab / hwr_map_slab : the radios / maps past the used ones
 *   hwr_out_slab   : [HAL_IPC_MAX_STRING_LEN, end)            - the caller's buffer is 64 bytes, nothing behind it
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output buffer is preset to 0xA5.  Rows flagged `forked` are expected to crash the unfixed function (buffer
 * overflow, NULL output): they run in a child so the ASan report is visible but the run continues.  The function
 * is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gsm.h"
#include <sanitizer/asan_interface.h>

#define OUT_CAP HAL_IPC_MAX_STRING_LEN
static hwr_gsm_radio_t hwr_radio_slab[HWR_GSM_MAX_RADIOS + 2];
static hwr_gsm_map_t   hwr_map_slab[HWR_GSM_MAX_RADIOS + 2];
static hwr_gsm_iface_t hwr_iface_slab[HWR_GSM_MAX_IFACES];
static unsigned char   hwr_out_slab[OUT_CAP + 64];
static int used_ifaces, used_radios;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_gsm_radio_t));
	fn(&hwr_map_slab[used_radios], sizeof(hwr_map_slab) - used_radios * sizeof(hwr_gsm_map_t));
	fn(&hwr_iface_slab[used_ifaces], sizeof(hwr_iface_slab) - used_ifaces * sizeof(hwr_gsm_iface_t));
	fn(&hwr_out_slab[OUT_CAP], sizeof(hwr_out_slab) - OUT_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[240];

static void build(const hwr_gsm_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_map_slab, 0, sizeof(hwr_map_slab));
	memset(hwr_iface_slab, 0, sizeof(hwr_iface_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_ifaces = 0; used_radios = t->nradios;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].interface_map = &hwr_map_slab[r];
		for (int k = 0; k < t->r[r].n; k++) {
			hwr_gsm_iface_t *f = &hwr_iface_slab[used_ifaces++];
			const hwr_gsm_if_t *s = &t->r[r].ifs[k];
			size_t field = s->mode == 1 ? sizeof(f->vap_info.u.sta_info.ssid) : sizeof(f->vap_info.u.bss_info.ssid);
			size_t n = strlen(s->ssid);
			f->vap_info.vap_index = s->vap_index;
			f->vap_info.vap_mode = (wifi_vap_mode_t)(s->mode == 0 ? wifi_vap_mode_ap : s->mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor);
			memset(&f->vap_info.u, s->fill, sizeof(f->vap_info.u));                 /* the bytes behind the SSID */
			memcpy(f->vap_info.u.bss_info.ssid, s->ssid, n < field ? n + 1 : field); /* NUL copied only if it fits */
			hwr_map_slab[r].items[hwr_map_slab[r].n++] = f;
		}
	}
	hwr_gsm_world.num_radios = t->nradios;
	hwr_gsm_world.radio_info = hwr_radio_slab;
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
}

static int run_case(const hwr_gsm_case_t *t)
{
	CHAR *out = t->null_out ? NULL : (CHAR *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	build(t);

	if (t->forked) {                                         /* ASan report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) {
			ret = hwr_wifi_hal_getSSIDName(t->query, out);
			if (ret != t->expected_ret) _exit(2);
			if (t->expected_out && strcmp((char *)hwr_out_slab, t->expected_out)) _exit(3);
			_exit(0);
		}
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (%s)", t->null_out ? "SEGV on NULL output_string" : "overflow of the 64 byte output buffer"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (%s)", t->null_out ? "SEGV on NULL output_string" : "overflow of the 64 byte output buffer"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child returned wrong result / output (exit %d)", WEXITSTATUS(st)); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		poison_all(1);
		ret = hwr_wifi_hal_getSSIDName(t->query, out);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (t->expected_out == NULL) {
			for (int k = 0; k < OUT_CAP && !t->null_out; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "output byte %d written although the call failed", k); return 0; }
		} else {
			size_t want = strlen(t->expected_out);
			if (strcmp((char *)hwr_out_slab, t->expected_out)) { snprintf(why, sizeof(why), "output '%.40s' (len %zu), expected '%.40s' (len %zu)", (char *)hwr_out_slab, strlen((char *)hwr_out_slab), t->expected_out, want); return 0; }
			for (size_t k = want + 1; k < sizeof(hwr_out_slab); k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %zu behind the string modified", k); return 0; }
		}
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getSSIDName") || (!strstr(hwr_log_buf, "Enter") && !strstr(hwr_log_buf, "not found")))) { snprintf(why, sizeof(why), "log lacks function name / message: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getSSIDName(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getSSIDName_suite[i].test_name != NULL; i++) {
		hwr_gsm_case_t *test = &wifi_hal_getSSIDName_suite[i];

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
	printf("\nwifi_hal_getSSIDName: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
