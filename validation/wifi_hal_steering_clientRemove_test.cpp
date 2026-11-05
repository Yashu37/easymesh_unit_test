/*
 * TEST RUNNER: wifi_hal_steering_clientRemove_test
 *
 * The runner owns the client MAC and the two station entries kept in the AP's table, POISONS their tails,
 * calls the function, UNPOISONS and checks the result:
 *   hwr_mac_slab   : [sizeof(mac_address_t), end)
 *   hwr_sta_slab   : [sizeof(bm_sta_list_t), end)   hwr_other_slab : [sizeof(bm_sta_list_t), end)
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * The steering_del_stalist stub poisons a removed ("freed") entry completely, so a later use of it is an ASan
 * error; the runner unpoisons it afterwards.  Rows flagged `forked` crash the unfixed function (NULL client_mac):
 * they run in a child so the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_grm.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_mac_slab[sizeof(mac_address_t) + PADB];
static unsigned char hwr_sta_slab[sizeof(hwr_bm_sta_list_t) + PADB];
static unsigned char hwr_other_slab[sizeof(hwr_bm_sta_list_t) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[sizeof(mac_address_t)], PADB);
	fn(&hwr_sta_slab[sizeof(hwr_bm_sta_list_t)], PADB);
	fn(&hwr_other_slab[sizeof(hwr_bm_sta_list_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	if (!on) { __asan_unpoison_memory_region(hwr_sta_slab, sizeof(hwr_bm_sta_list_t)); __asan_unpoison_memory_region(hwr_other_slab, sizeof(hwr_bm_sta_list_t)); }
}

static char why[220];

static int run_case(const hwr_grm_case_t *t)
{
	unsigned char *mac = (t->null_mask & 1) ? NULL : hwr_mac_slab;
	hwr_bm_sta_list_t *sta = (hwr_bm_sta_list_t *)hwr_sta_slab, *other = (hwr_bm_sta_list_t *)hwr_other_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, t->mac, 6);
	memset(hwr_log_buf, 0, HWR_LOG_USE);

	for (int i = 0; i < (t->forked ? 1 : t->calls); i++) {
		memset(hwr_sta_slab, 0xA5, sizeof(hwr_sta_slab)); memset(hwr_other_slab, 0xA5, sizeof(hwr_other_slab));
		memcpy(sta->mac_addr, t->mac, 6); sta->type = t->entry_type;
		static const unsigned char omac[6] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
		memcpy(other->mac_addr, omac, 6); other->type = 0x04;
		hwr_grm_configure(t->ap, t->map_null, t->entry_type ? sta : NULL, t->mac, t->other_entry ? other : NULL, t->kick_ret, t->del_ret);

		if (t->forked) {                                     /* SEGV report visible, run continues */
			int st; pid_t pid;
			fflush(stdout);
			poison_all(1);
			pid = fork();
			if (pid == 0) { ret = hwr_wifi_hal_steering_clientRemove(t->group, t->ap, mac); _exit(ret == t->expected_ret ? 0 : 2); }
			waitpid(pid, &st, 0);
			poison_all(0);
			if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on a NULL pointer)"); return 0; }
			if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV: NULL client_mac read by to_mac_str)"); return 0; }
			if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result (exit %d)", WEXITSTATUS(st)); return 0; }
			return 1;
		}

		poison_all(1);
		ret = hwr_wifi_hal_steering_clientRemove(t->group, t->ap, mac);
		poison_all(0);

		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (hwr_grm_rec.del_calls != t->expect_del || hwr_grm_rec.sl_calls != t->expect_del) { snprintf(why, sizeof(why), "del_mac_list called %d / del_stalist %d times, expected %d", hwr_grm_rec.del_calls, hwr_grm_rec.sl_calls, t->expect_del); return 0; }
		if (hwr_grm_rec.kick_calls != t->expect_kick) { snprintf(why, sizeof(why), "kick_device called %d times, expected %d", hwr_grm_rec.kick_calls, t->expect_kick); return 0; }
		if (t->expect_del) {
			if (hwr_grm_rec.del_vap != (uint32_t)t->ap || hwr_grm_rec.del_sta != sta || memcmp(hwr_grm_rec.del_mac, t->mac, 6)) { snprintf(why, sizeof(why), "wifi_steering_del_mac_list arguments wrong"); return 0; }
			if (hwr_grm_rec.sl_if == NULL || hwr_grm_rec.sl_if->vap_index != t->ap || hwr_grm_rec.sl_type != BM_STA_TYPE_CLIENT_SET || memcmp(hwr_grm_rec.sl_mac, t->mac, 6)) { snprintf(why, sizeof(why), "steering_del_stalist arguments wrong (type %d)", hwr_grm_rec.sl_type); return 0; }
			if (hwr_grm_rec.del_seq > hwr_grm_rec.sl_seq) { snprintf(why, sizeof(why), "entry deleted before the MAC list was cleaned"); return 0; }
		}
		if (t->expect_kick && (hwr_grm_rec.kick_if == NULL || hwr_grm_rec.kick_if->vap_index != t->ap || memcmp(hwr_grm_rec.kick_mac, t->mac, 6))) { snprintf(why, sizeof(why), "kick_device arguments wrong"); return 0; }
		if ((hwr_grm_rec.freed == sta) != (t->expect_removed != 0)) { snprintf(why, sizeof(why), "entry %s, expected %s", t->expect_removed ? "not removed" : "removed", t->expect_removed ? "removed" : "kept"); return 0; }
		if (t->entry_type && !t->expect_removed && t->expect_del && sta->type != (t->entry_type & ~BM_STA_TYPE_CLIENT_SET)) { snprintf(why, sizeof(why), "entry type 0x%x after the call", sta->type); return 0; }
		if (t->other_entry && (hwr_grm_rec.freed == other || other->type != 0x04)) { snprintf(why, sizeof(why), "another client's entry was modified or removed"); return 0; }
	}
	if (memcmp(hwr_mac_slab, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (t->check_log && !strstr(hwr_log_buf, "remove client info:02:11:22:33:44:55 vap:1")) { snprintf(why, sizeof(why), "log lacks the remove client line: '%.120s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_steering_clientRemove(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_steering_clientRemove_suite[i].test_name != NULL; i++) {
		hwr_grm_case_t *test = &wifi_hal_steering_clientRemove_suite[i];

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
	printf("\nwifi_hal_steering_clientRemove: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
