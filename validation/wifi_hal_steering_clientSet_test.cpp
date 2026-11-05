/*
 * TEST RUNNER: wifi_hal_steering_clientSet_test
 *
 * The runner owns the client MAC, the config and the station entry the stub hands out, POISONS their tails,
 * calls the function, UNPOISONS and checks the result:
 *   hwr_mac_slab : [sizeof(mac_address_t), end)                       hwr_cfg_slab : [sizeof(wifi_steering_clientConfig_t), end)
 *   hwr_sta_slab : [sizeof(bm_sta_list_t), end)  (the entry the function writes into)
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * The station entry is preset to 0xA5 so "config copied" / "config not copied" is visible.  Rows flagged `forked`
 * crash the unfixed function (NULL pointer): they run in a child so the ASan report is visible but the run
 * continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gcs.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_mac_slab[sizeof(mac_address_t) + PADB];
static unsigned char hwr_cfg_slab[sizeof(wifi_steering_clientConfig_t) + PADB];
static unsigned char hwr_sta_slab[sizeof(hwr_bm_sta_list_t) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[sizeof(mac_address_t)], PADB);
	fn(&hwr_cfg_slab[sizeof(wifi_steering_clientConfig_t)], PADB);
	fn(&hwr_sta_slab[sizeof(hwr_bm_sta_list_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static int run_case(const hwr_gcs_case_t *t)
{
	unsigned char *mac = (t->null_mask & 1) ? NULL : hwr_mac_slab;
	wifi_steering_clientConfig_t *cfg = (t->null_mask & 2) ? NULL : (wifi_steering_clientConfig_t *)hwr_cfg_slab;
	hwr_bm_sta_list_t *sta = (hwr_bm_sta_list_t *)hwr_sta_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, t->mac, 6);
	memset(hwr_cfg_slab, 0, sizeof(hwr_cfg_slab)); { wifi_steering_clientConfig_t c; memcpy(&c, t->cfg, sizeof(c)); memcpy(hwr_cfg_slab, &c, sizeof(c)); }
	memset(hwr_log_buf, 0, HWR_LOG_USE);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		memset(hwr_sta_slab, 0xA5, sizeof(hwr_sta_slab));
		hwr_gcs_configure(sta, t->add_fail, t->del_ret);
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_steering_clientSet(t->group, t->ap, mac, cfg); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on a NULL pointer)"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV: NULL %s dereferenced%s)", (t->null_mask & 1) ? "client_mac" : "config", (t->null_mask & 1) ? "" : " by memcpy"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result (exit %d)", WEXITSTATUS(st)); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_sta_slab, 0xA5, sizeof(hwr_sta_slab));
		hwr_gcs_configure(sta, t->add_fail, t->del_ret);
		poison_all(1);
		ret = hwr_wifi_hal_steering_clientSet(t->group, t->ap, mac, cfg);
		poison_all(0);

		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (hwr_gcs_rec.add_calls != t->expect_add) { snprintf(why, sizeof(why), "steering_add_stalist called %d times, expected %d", hwr_gcs_rec.add_calls, t->expect_add); return 0; }
		if (hwr_gcs_rec.del_calls != t->expect_del) { snprintf(why, sizeof(why), "wifi_steering_del_mac_list called %d times, expected %d", hwr_gcs_rec.del_calls, t->expect_del); return 0; }
		if (t->expect_add) {
			if (hwr_gcs_rec.add_if == NULL || hwr_gcs_rec.add_if->vap_index != t->ap) { snprintf(why, sizeof(why), "wrong interface passed to steering_add_stalist"); return 0; }
			if (hwr_gcs_rec.add_ssid != NULL || hwr_gcs_rec.add_type != BM_STA_TYPE_CLIENT_SET) { snprintf(why, sizeof(why), "ssid / type arguments wrong (type %d)", hwr_gcs_rec.add_type); return 0; }
			if (memcmp(hwr_gcs_rec.add_mac, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC not forwarded"); return 0; }
		}
		if (t->expect_del && (hwr_gcs_rec.del_vap != (uint32_t)t->ap || hwr_gcs_rec.del_sta != sta)) { snprintf(why, sizeof(why), "wifi_steering_del_mac_list arguments wrong"); return 0; }
		if (t->expected_ret == 0) {
			if (memcmp(&sta->bm_client_cfg, t->cfg, sizeof(wifi_steering_clientConfig_t))) { snprintf(why, sizeof(why), "bm_client_cfg != config"); return 0; }
			if (((unsigned char *)sta)[0] != 0xA5 || ((unsigned char *)sta)[offsetof(hwr_bm_sta_list_t, bm_client_cfg) - 1] != 0xA5) { snprintf(why, sizeof(why), "station entry fields before bm_client_cfg modified"); return 0; }
		} else {
			unsigned char *p = (unsigned char *)sta;
			for (size_t k = 0; k < sizeof(hwr_bm_sta_list_t); k++) if (p[k] != 0xA5) { snprintf(why, sizeof(why), "station entry modified although the call failed (byte %zu)", k); return 0; }
		}
	}
	if (memcmp(hwr_mac_slab, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (memcmp(hwr_cfg_slab, t->cfg, sizeof(wifi_steering_clientConfig_t))) { snprintf(why, sizeof(why), "config modified"); return 0; }
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "Wi-Fi steering group:6 for vap:1 and client:02:11:22:33:44:55") || !strstr(hwr_log_buf, "rssiProbe HWM:5-LWM:6 rssiAuthHWM:7-LWM:8"))) { snprintf(why, sizeof(why), "log lacks the group / rssi lines: '%.120s'", hwr_log_buf); return 0; }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "Remove MAC=02:11:22:33:44:55 from maclist for vap:1")) { snprintf(why, sizeof(why), "log lacks the Remove MAC line: '%.120s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_steering_clientSet(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_steering_clientSet_suite[i].test_name != NULL; i++) {
		hwr_gcs_case_t *test = &wifi_hal_steering_clientSet_suite[i];

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
	printf("\nwifi_hal_steering_clientSet: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
