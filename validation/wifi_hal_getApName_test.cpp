/*
 * TEST RUNNER: wifi_hal_getApName_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radio_info[], the interface index map) in
 * runner-owned slabs, POISONS their tails, calls the function, UNPOISONS and checks:
 *   hwr_radio_slab : [num_radios * sizeof(radio), end)            - radios past the used ones
 *   hwr_gan_map    : [map entries * sizeof(entry), end)            - map entries past the used ones
 *   hwr_out_slab   : [HAL_IPC_MAX_STRING_LEN, end)                 - the caller's buffer is 64 bytes, nothing behind it
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output buffer is preset to 0xA5.  Rows flagged `forked` are expected to crash the unfixed helpers (NULL
 * radio): they run in a child so the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gan.h"
#include <sanitizer/asan_interface.h>

#define OUT_CAP HAL_IPC_MAX_STRING_LEN
static hwr_gan_radio_t hwr_radio_slab[HWR_GAN_MAX_RADIOS];
static unsigned char   hwr_out_slab[OUT_CAP + 64];
static int used_radios, used_map;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_gan_radio_t));
	fn(&hwr_gan_map[used_map], sizeof(hwr_gan_map) - used_map * sizeof(hwr_gan_map[0]));
	fn(&hwr_out_slab[OUT_CAP], sizeof(hwr_out_slab) - OUT_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[240];

static void build(const hwr_gan_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_gan_map, 0, sizeof(hwr_gan_map));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_radios = t->nradios; used_map = t->nmap;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].rdk_radio_index = t->r[r].rdk_index;
		hwr_radio_slab[r].capab.maxNumberVAPs = t->r[r].max_vaps;
	}
	for (int k = 0; k < t->nmap; k++) {
		hwr_gan_map[k].index = t->m[k].index;
		strncpy(hwr_gan_map[k].interface_name, t->m[k].name, sizeof(hwr_gan_map[k].interface_name) - 1);
	}
	hwr_gan_map_size = t->nmap;
	hwr_gan_world.num_radios = t->nradios;
	hwr_gan_world.radio_info = hwr_radio_slab;
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
}

static int run_case(const hwr_gan_case_t *t)
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
			ret = hwr_wifi_hal_getApName(t->query, out);
			if (ret != t->expected_ret) _exit(2);
			if (t->expected_out && strcmp((char *)hwr_out_slab, t->expected_out)) _exit(3);
			_exit(0);
		}
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV: NULL radio from get_radio_by_rdk_index)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child returned wrong result / output (exit %d)", WEXITSTATUS(st)); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		poison_all(1);
		ret = hwr_wifi_hal_getApName(t->query, out);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (t->expected_out == NULL) {
			for (int k = 0; k < OUT_CAP && !t->null_out; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "output byte %d written although the call failed", k); return 0; }
		} else {
			size_t want = strlen(t->expected_out);
			if (strcmp((char *)hwr_out_slab, t->expected_out)) { snprintf(why, sizeof(why), "output '%.40s', expected '%.40s'", (char *)hwr_out_slab, t->expected_out); return 0; }
			for (size_t k = want + 1; k < sizeof(hwr_out_slab); k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %zu behind the string modified", k); return 0; }
		}
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getApName") || !strstr(hwr_log_buf, "Requested index") )) { snprintf(why, sizeof(why), "log lacks function name / request line: '%s'", hwr_log_buf); return 0; }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "Wrong vap_index")) { snprintf(why, sizeof(why), "log lacks the wrong-index line: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getApName(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getApName_suite[i].test_name != NULL; i++) {
		hwr_gan_case_t *test = &wifi_hal_getApName_suite[i];

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
	printf("\nwifi_hal_getApName: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
