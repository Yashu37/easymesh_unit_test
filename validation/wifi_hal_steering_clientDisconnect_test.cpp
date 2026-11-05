/*
 * TEST RUNNER: wifi_hal_steering_clientDisconnect_test
 *
 * The runner owns the client MAC, the interface the AP lookup returns (real wifi_vap_info_t + the u.ap / u.sta
 * union) and the hostapd conf it points to, POISONS their tails, calls the function, UNPOISONS and checks the
 * result:
 *   hwr_mac_slab : [sizeof(mac_address_t), end)      hwr_if_slab   : [sizeof(hwr_gsd_if_t), end)
 *   hwr_conf_slab: [sizeof(hwr_gsd_conf), end)       hwr_log_buf   : [HWR_LOG_USE, HWR_LOG_SZ)
 * The interface of a STA VAP has its union filled with 0xA5 (no hostapd there).  After the call the runner also
 * checks that hapd_lock is released.  Rows flagged `forked` crash the unfixed function: they run in a child so
 * the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gsd.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_mac_slab[sizeof(mac_address_t) + PADB];
static unsigned char hwr_if_slab[sizeof(hwr_gsd_if_t) + PADB];
static unsigned char hwr_conf_slab[sizeof(hwr_gsd_conf) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[sizeof(mac_address_t)], PADB);
	fn(&hwr_if_slab[sizeof(hwr_gsd_if_t)], PADB);
	fn(&hwr_conf_slab[sizeof(hwr_gsd_conf)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static int run_case(const hwr_gsd_case_t *t)
{
	unsigned char *mac = (t->null_mask & 1) ? NULL : hwr_mac_slab;
	hwr_gsd_if_t *ifc = (hwr_gsd_if_t *)hwr_if_slab;
	hwr_gsd_conf *conf = (hwr_gsd_conf *)hwr_conf_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, t->mac, 6);
	memset(hwr_log_buf, 0, HWR_LOG_USE);

	for (int i = 0; i < (t->forked ? 1 : t->calls); i++) {
		memset(hwr_if_slab, 0, sizeof(hwr_if_slab)); memset(hwr_conf_slab, 0, sizeof(hwr_conf_slab));
		strcpy(conf->iface, "wlan0");
		ifc->vap_index = t->ap;
		if (t->sta_mode) { ifc->vap_info.vap_mode = wifi_vap_mode_sta; memset(&ifc->u, 0xA5, sizeof(ifc->u)); }
		else { ifc->vap_info.vap_mode = wifi_vap_mode_ap; ifc->u.ap.hapd.conf = conf; }
		hwr_gsd_configure(ifc);

		if (t->forked) {                                     /* SEGV report visible, run continues */
			int st; pid_t pid;
			fflush(stdout);
			poison_all(1);
			pid = fork();
			if (pid == 0) { ret = hwr_wifi_hal_steering_clientDisconnect(t->group, t->ap, mac, (wifi_disconnectType_t)t->type, t->reason); _exit(ret == t->expected_ret ? 0 : 2); }
			waitpid(pid, &st, 0);
			poison_all(0);
			if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on the STA VAP's union bytes used as hostapd_data)"); return 0; }
			if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV: STA VAP's u.ap.hapd used as hostapd_data)"); return 0; }
			if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result (exit %d)", WEXITSTATUS(st)); return 0; }
			return 1;
		}

		poison_all(1);
		ret = hwr_wifi_hal_steering_clientDisconnect(t->group, t->ap, mac, (wifi_disconnectType_t)t->type, t->reason);
		poison_all(0);

		if (ret != t->expected_ret) {
			snprintf(why, sizeof(why), "call %d returned %d, expected %d%s", i, ret, t->expected_ret,
			         (ret == 0 && (t->null_mask & 1)) ? " (NULL client_mac: nothing was disconnected but success reported)" : "");
			return 0;
		}
		if (hwr_gsd_rec.calls != t->expect_call) { snprintf(why, sizeof(why), "ap_sta_disconnect called %d times, expected %d", hwr_gsd_rec.calls, t->expect_call); return 0; }
		if (t->expect_call) {
			if (hwr_gsd_rec.hapd != &ifc->u.ap.hapd || hwr_gsd_rec.sta != NULL) { snprintf(why, sizeof(why), "hapd / sta arguments wrong"); return 0; }
			if (hwr_gsd_rec.addr_null || memcmp(hwr_gsd_rec.addr, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC not forwarded"); return 0; }
			if (hwr_gsd_rec.reason != (uint16_t)t->reason) { snprintf(why, sizeof(why), "reason %u forwarded, expected %u", hwr_gsd_rec.reason, (uint16_t)t->reason); return 0; }
			if (!hwr_gsd_rec.locked_in_call) { snprintf(why, sizeof(why), "ap_sta_disconnect called without hapd_lock"); return 0; }
		}
		if (pthread_mutex_trylock(&hwr_gsd_world.hapd_lock) != 0) { snprintf(why, sizeof(why), "hapd_lock left locked"); return 0; }
		pthread_mutex_unlock(&hwr_gsd_world.hapd_lock);
	}
	if (memcmp(hwr_mac_slab, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_steering_clientDisconnect") || !strstr(hwr_log_buf, "Enter") || !strstr(hwr_log_buf, "apIndex:1 steeringgroupIndex:6 type:2 reason:15"))) { snprintf(why, sizeof(why), "log lacks Enter / parameters: '%.150s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_steering_clientDisconnect(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_steering_clientDisconnect_suite[i].test_name != NULL; i++) {
		hwr_gsd_case_t *test = &wifi_hal_steering_clientDisconnect_suite[i];

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
	printf("\nwifi_hal_steering_clientDisconnect: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
