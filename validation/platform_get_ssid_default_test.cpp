/*
 * TEST RUNNER: platform_get_ssid_default_test
 *
 * The runner writes the case's serial file to a temporary directory (the function's fopen is redirected there, see the handler), owns the
 * ssid buffer in a slab and POISONS its tail during the call:
 *   hwr_ssid_slab : [33, end)   everything behind the 33 bytes of an SSID (32 + NUL); the buffer is preset to 0xA5
 *   hwr_log_buf   : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` crash the unfixed function (NULL ssid): they run in a child so the ASan report is visible but the run continues;
 * the child also checks the result.  Checks: return value, the SSID (expected string, bytes behind it unchanged or zero padding), that a -1
 * leaves the buffer untouched, no control characters in the SSID, and the number of JSON source calls.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_psd.h"
#include <sanitizer/asan_interface.h>

#define SSID_CAP 33
static unsigned char hwr_ssid_slab[256];
static char tmpdir[128], why[220];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_ssid_slab[SSID_CAP], sizeof(hwr_ssid_slab) - SSID_CAP);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check_result(const hwr_psd_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->null_ssid) return 1;
	if (t->expected_ssid == NULL) {
		for (size_t k = 0; k < SSID_CAP; k++) if (hwr_ssid_slab[k] != 0xA5) { snprintf(why, sizeof(why), "ssid byte %zu written although the call failed", k); return 0; }
	} else {
		size_t want = strlen(t->expected_ssid);
		for (size_t k = 0; k < SSID_CAP && hwr_ssid_slab[k]; k++)
			if (hwr_ssid_slab[k] < 0x20 || hwr_ssid_slab[k] == 0x7f) { snprintf(why, sizeof(why), "control character 0x%02x in the SSID at %zu", hwr_ssid_slab[k], k); return 0; }
		if (strcmp((char *)hwr_ssid_slab, t->expected_ssid)) { snprintf(why, sizeof(why), "ssid '%.34s', expected '%.34s'", (char *)hwr_ssid_slab, t->expected_ssid); return 0; }
		for (size_t k = want + 1; k < SSID_CAP; k++) if (hwr_ssid_slab[k] != 0xA5 && hwr_ssid_slab[k] != 0) { snprintf(why, sizeof(why), "byte %zu behind the ssid modified", k); return 0; }
	}
	if (hwr_psd_rec.json_calls != t->expected_json_calls) { snprintf(why, sizeof(why), "%d JSON source calls, expected %d", hwr_psd_rec.json_calls, t->expected_json_calls); return 0; }
	return 1;
}

static int run_case(const hwr_psd_case_t *t)
{
	char *ssid;
	int ret;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(hwr_ssid_slab, 0xA5, sizeof(hwr_ssid_slab));
	memset(&hwr_psd_rec, 0, sizeof(hwr_psd_rec));
	hwr_psd_rec.mesh_sta_index = t->mesh_sta_index; hwr_psd_rec.json_ret = t->json_ret; hwr_psd_rec.json_val = t->json_val ? t->json_val : "";
	unlink(hwr_psd_path);
	if (t->file) { FILE *f = fopen(hwr_psd_path, "w"); fwrite(t->file, 1, t->file_len ? t->file_len : strlen(t->file), f); fclose(f); }
	ssid = t->null_ssid ? NULL : (char *)hwr_ssid_slab;

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { ret = hwr_platform_get_ssid_default(ssid, t->vap_index); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (NULL ssid written)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	ret = hwr_platform_get_ssid_default(ssid, t->vap_index);
	poison(0);
	return check_result(t, ret);
}

extern "C" void run_all_tests_platform_get_ssid_default(void)
{
	int pass = 0, fail = 0;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/hwr_psd_XXXXXX");
	if (!mkdtemp(tmpdir)) { printf("mkdtemp failed\n"); return; }
	snprintf(hwr_psd_path, sizeof(hwr_psd_path), "%s/serial_number.txt", tmpdir);

	for (int i = 0; platform_get_ssid_default_suite[i].test_name != NULL; i++) {
		hwr_psd_case_t *test = &platform_get_ssid_default_suite[i];

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
	unlink(hwr_psd_path); rmdir(tmpdir);
	printf("\nplatform_get_ssid_default: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
