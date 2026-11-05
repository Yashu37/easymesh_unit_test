/*
 * TEST RUNNER: wifi_hal_getAssociationReqIEs_test
 *
 * The runner owns every buffer the function touches, POISONS their tails, calls the function, UNPOISONS and
 * checks the result:
 *   hwr_mac_slab    : [6, end)                                  the client MAC
 *   hwr_out_slab    : [min(req_ies_size, cap), end)             the caller's buffer: nothing behind req_ies_size may be written
 *   hwr_len_slab    : [sizeof(UINT), end)                       *req_ies_len
 *   hwr_ies_slab    : [assoc_len, end)  hwr_ies2_slab : [20, end)   the stations' association request IEs (over-read)
 *   hwr_sta_slab / hwr_sta2_slab, hwr_conf_slab, hwr_if_slab : tails behind the stub structures
 *   hwr_log_buf     : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output buffer is preset to 0xA5 and *req_ies_len to 0xDEAD.  A STA VAP's interface has its union filled with
 * 0xA5 (no hostapd there).  After the call hapd_lock must be released.  Rows flagged `forked` crash the unfixed
 * function: they run in a child so the ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gai.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
#define OUT_CAP 2048
#define IES_CAP 1024
static unsigned char hwr_mac_slab[6 + PADB];
static unsigned char hwr_out_slab[OUT_CAP + PADB];
static unsigned char hwr_len_slab[sizeof(UINT) + PADB];
static unsigned char hwr_ies_slab[IES_CAP + PADB];
static unsigned char hwr_ies2_slab[20 + PADB];
static unsigned char hwr_sta_slab[sizeof(hwr_gai_sta_info) + PADB];
static unsigned char hwr_sta2_slab[sizeof(hwr_gai_sta_info) + PADB];
static unsigned char hwr_conf_slab[sizeof(hwr_gai_conf) + PADB];
static unsigned char hwr_if_slab[sizeof(hwr_gai_if_t) + PADB];
static unsigned cur_out_from, cur_ies_from;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[6], PADB);
	fn(&hwr_out_slab[cur_out_from], sizeof(hwr_out_slab) - cur_out_from);
	fn(&hwr_len_slab[sizeof(UINT)], PADB);
	fn(&hwr_ies_slab[cur_ies_from], sizeof(hwr_ies_slab) - cur_ies_from);
	fn(&hwr_ies2_slab[20], PADB);
	fn(&hwr_sta_slab[sizeof(hwr_gai_sta_info)], PADB);
	fn(&hwr_sta2_slab[sizeof(hwr_gai_sta_info)], PADB);
	fn(&hwr_conf_slab[sizeof(hwr_gai_conf)], PADB);
	fn(&hwr_if_slab[sizeof(hwr_gai_if_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[240];

static void build(const hwr_gai_case_t *t)
{
	hwr_gai_if_t *ifc = (hwr_gai_if_t *)hwr_if_slab;
	hwr_gai_conf *conf = (hwr_gai_conf *)hwr_conf_slab;
	hwr_gai_sta_info *sa = (hwr_gai_sta_info *)hwr_sta_slab, *sb = (hwr_gai_sta_info *)hwr_sta2_slab;
	static const unsigned char omac[6] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, t->mac, 6);
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
	memset(hwr_len_slab, 0, sizeof(hwr_len_slab)); *(UINT *)hwr_len_slab = 0xDEAD;
	memset(hwr_ies_slab, 0, sizeof(hwr_ies_slab)); memset(hwr_ies2_slab, 0x77, sizeof(hwr_ies2_slab));
	for (unsigned i = 0; i < t->assoc_len; i++) hwr_ies_slab[i] = (unsigned char)(i * 7 + 3);
	memset(hwr_sta_slab, 0, sizeof(hwr_sta_slab)); memset(hwr_sta2_slab, 0, sizeof(hwr_sta2_slab));
	sa->assoc_req = t->assoc_len ? hwr_ies_slab : NULL; sa->assoc_req_len = t->assoc_len;
	sb->assoc_req = hwr_ies2_slab; sb->assoc_req_len = 20;
	memset(hwr_conf_slab, 0, sizeof(hwr_conf_slab));
	if (t->client == 1) { memcpy(conf->mac[conf->n], t->mac, 6); conf->sta[conf->n++] = sa; }
	if (t->other_present || t->client == 2) { memcpy(conf->mac[conf->n], omac, 6); conf->sta[conf->n++] = sb; }
	memset(hwr_if_slab, 0, sizeof(hwr_if_slab));
	ifc->vap_index = t->ap;
	if (t->sta_mode) { ifc->vap_info.vap_mode = wifi_vap_mode_sta; memset(&ifc->u, 0xA5, sizeof(ifc->u)); }
	else { ifc->vap_info.vap_mode = wifi_vap_mode_ap; ifc->u.ap.hapd.conf = conf; }
	hwr_gai_configure(ifc);
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	cur_out_from = t->req_size < OUT_CAP ? t->req_size : OUT_CAP;
	cur_ies_from = t->assoc_len;
}

static int check_result(const hwr_gai_case_t *t, INT ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (pthread_mutex_trylock(&hwr_gai_world.hapd_lock) != 0) { snprintf(why, sizeof(why), "hapd_lock left locked"); return 0; }
	pthread_mutex_unlock(&hwr_gai_world.hapd_lock);
	if (t->expected_ret == 0) {
		if (*(UINT *)hwr_len_slab != t->assoc_len) { snprintf(why, sizeof(why), "*req_ies_len %u, expected %u", *(UINT *)hwr_len_slab, t->assoc_len); return 0; }
		for (unsigned i = 0; i < t->assoc_len; i++) if (hwr_out_slab[i] != (unsigned char)(i * 7 + 3)) { snprintf(why, sizeof(why), "IE byte %u wrong", i); return 0; }
		for (unsigned i = t->assoc_len; i < cur_out_from; i++) if (hwr_out_slab[i] != 0xA5) { snprintf(why, sizeof(why), "byte %u behind the IEs modified", i); return 0; }
	} else {
		if (*(UINT *)hwr_len_slab != 0xDEAD) { snprintf(why, sizeof(why), "*req_ies_len modified (%u) although the call failed", *(UINT *)hwr_len_slab); return 0; }
		for (unsigned i = 0; i < cur_out_from; i++) if (hwr_out_slab[i] != 0xA5) { snprintf(why, sizeof(why), "output byte %u written although the call failed", i); return 0; }
	}
	return 1;
}

static int run_case(const hwr_gai_case_t *t)
{
	why[0] = 0;
	for (int i = 0; i < (t->forked ? 1 : t->calls); i++) {
		unsigned char *mac = (t->null_mask & 1) ? NULL : hwr_mac_slab;
		CHAR *ies = (t->null_mask & 2) ? NULL : (CHAR *)hwr_out_slab;
		UINT *plen = (t->null_mask & 4) ? NULL : (UINT *)hwr_len_slab;
		INT ret;

		build(t);
		if (t->forked) {                                     /* ASan report visible, run continues */
			int st; pid_t pid;
			fflush(stdout);
			poison_all(1);
			pid = fork();
			if (pid == 0) { ret = hwr_wifi_hal_getAssociationReqIEs(t->ap, (const mac_address_t *)mac, ies, t->req_size, plen); poison_all(0); _exit(ret != t->expected_ret ? 2 : check_result(t, ret) ? 0 : 3); }
			waitpid(pid, &st, 0);
			poison_all(0);
			const char *what = t->sta_mode ? "STA VAP's u.ap.hapd used as hostapd_data" : t->client != 1 ? "NULL station returned by ap_get_sta dereferenced" : (t->null_mask & 1) ? "NULL clientMacAddress hashed by ap_get_sta" : (t->null_mask & 2) ? "memcpy into a NULL req_ies" : "write through a NULL req_ies_len";
			if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV: %s)", what); return 0; }
			if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV: %s)", what); return 0; }
			if (WEXITSTATUS(st) == 3) { snprintf(why, sizeof(why), "child: hapd_lock left locked or buffer / *req_ies_len modified although the call failed"); return 0; }
			if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result (exit %d)", WEXITSTATUS(st)); return 0; }
			return 1;
		}
		poison_all(1);
		ret = hwr_wifi_hal_getAssociationReqIEs(t->ap, (const mac_address_t *)mac, ies, t->req_size, plen);
		poison_all(0);
		if (!check_result(t, ret)) return 0;
	}
	if (memcmp(hwr_mac_slab, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getAssociationReqIEs") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%.100s'", hwr_log_buf); return 0; }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "req_ies_size 39 is too small (should be at least 40)")) { snprintf(why, sizeof(why), "log lacks the too-small message: '%.140s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getAssociationReqIEs(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getAssociationReqIEs_suite[i].test_name != NULL; i++) {
		hwr_gai_case_t *test = &wifi_hal_getAssociationReqIEs_suite[i];

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
	printf("\nwifi_hal_getAssociationReqIEs: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
