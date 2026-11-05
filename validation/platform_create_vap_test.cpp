/*
 * TEST RUNNER: platform_create_vap_test
 *
 * The runner owns every memory object the function reads or writes and POISONS the tails during the call:
 *   hwr_map_slab  : sizeof(wifi_vap_info_map_t) + 1024 bytes; the bytes behind the map (vap_array[8] and beyond) are poisoned
 *   hwr_pcv_if[]  : the interface slab; the interfaces that are not part of the case (and the gap behind the last one) are poisoned
 *   hwr_pcv_link[][]: the link slab; links that are not in the case's MLD list are poisoned
 *   hwr_log_buf   : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` crash the unfixed function (NULL map, num_vaps > 8: read of vap_array behind the map, hapd->mld NULL):
 * they run in a child so the ASan report is visible but the run continues; the child also checks the result.  Checks: return
 * value, the sequence of link ids ieee802_11_set_beacon was called with, number of error lines in the log, map unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_pcv.h"
#include <sanitizer/asan_interface.h>

#define TAIL 1024
static unsigned char hwr_map_slab[sizeof(wifi_vap_info_map_t) + TAIL];
static int n_if_case;
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_map_slab[sizeof(wifi_vap_info_map_t)], TAIL);
	for (int i = n_if_case; i < HWR_MAX_IF; i++) fn(&hwr_pcv_if[i], sizeof(hwr_pcv_if[i]));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}
/* links of interface i that are not in its list are poisoned too */
static void poison_links(int on, const hwr_pcv_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	for (int k = 0; k < t->nvap; k++)
		for (int l = t->v[k].nlinks; l < HWR_MAX_LINK; l++) fn(&hwr_pcv_link[k][l], sizeof(hwr_pcv_link[k][l]));
}

static void build(const hwr_pcv_case_t *t)
{
	wifi_vap_info_map_t *map = (wifi_vap_info_map_t *)hwr_map_slab;

	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(hwr_map_slab, 0xA5, sizeof(hwr_map_slab));
	memset(hwr_pcv_if, 0, sizeof(hwr_pcv_if)); memset(hwr_pcv_if_used, 0, sizeof(hwr_pcv_if_used));
	memset(hwr_pcv_mld, 0, sizeof(hwr_pcv_mld)); memset(hwr_pcv_link, 0, sizeof(hwr_pcv_link));
	memset(hwr_pcv_called, 0, sizeof(hwr_pcv_called));
	hwr_pcv_beacon_calls = 0; hwr_pcv_fail_at = t->fail_at;
	memset(map, 0, sizeof(*map));
	map->num_vaps = t->num_vaps;
	n_if_case = 0;
	for (int k = 0; k < t->nvap; k++) {
		const hwr_pcv_vap_t *v = &t->v[k];
		wifi_interface_info_t *ifc = &hwr_pcv_if[k];

		map->vap_array[k].vap_mode = (wifi_vap_mode_t)v->mode;
		map->vap_array[k].vap_index = v->vap_index;
		if (!v->has_if) continue;
		hwr_pcv_if_used[k] = 1;
		snprintf(ifc->name, sizeof(ifc->name), "wifi%d", v->vap_index);
		ifc->vap_info.vap_index = v->vap_index;
		ifc->vap_info.vap_mode = (wifi_vap_mode_t)v->if_mode;
		ifc->vap_info.u.bss_info.enabled = v->enabled;
		ifc->vap_info.u.bss_info.mld_info.common_info.mld_enable = v->mld_en;
		ifc->u.ap.conf.disable_11be = v->dis11be;
		hwr_pcv_mld[k].links.next = hwr_pcv_mld[k].links.prev = &hwr_pcv_mld[k].links;
		for (int l = 0; l < v->nlinks; l++) {
			struct hostapd_data *lk = &hwr_pcv_link[k][l];
			struct dl_list *head = &hwr_pcv_mld[k].links;

			lk->mld = &hwr_pcv_mld[k]; lk->mld_link_id = v->vap_index * 10 + l;
			lk->link.next = head; lk->link.prev = head->prev; head->prev->next = &lk->link; head->prev = &lk->link;
		}
		ifc->u.ap.hapd.mld = v->mld_null ? NULL : &hwr_pcv_mld[k];
		ifc->u.ap.hapd.mld_link_id = v->vap_index * 10;
	}
	n_if_case = t->nvap;
}

static int check_result(const hwr_pcv_case_t *t, int ret)
{
	char got[160] = "";
	int errs = 0;
	const char *p;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int i = 0; i < hwr_pcv_beacon_calls && i < 32; i++) {
		char one[16]; snprintf(one, sizeof(one), "%s%d", i ? " " : "", hwr_pcv_called[i]); strncat(got, one, sizeof(got) - strlen(got) - 1);
	}
	if (strcmp(got, t->expected_calls)) { snprintf(why, sizeof(why), "set_beacon links '%s', expected '%s'", got, t->expected_calls); return 0; }
	for (p = hwr_log_buf; *p; p++) if (*p == '\n') errs++;
	if (errs != t->expected_errs) { snprintf(why, sizeof(why), "%d log lines, expected %d", errs, t->expected_errs); return 0; }
	return 1;
}

static int run_case(const hwr_pcv_case_t *t)
{
	wifi_vap_info_map_t *map = t->map_null ? NULL : (wifi_vap_info_map_t *)hwr_map_slab;
	int ret;

	why[0] = 0;
	build(t);
	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1); poison_links(1, t);
		pid = fork();
		if (pid == 0) { ret = hwr_platform_create_vap(0, map); poison(0); poison_links(0, t); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0); poison_links(0, t);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1); poison_links(1, t);
	ret = hwr_platform_create_vap(0, map);
	poison(0); poison_links(0, t);
	return check_result(t, ret);
}

extern "C" void run_all_tests_platform_create_vap(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_create_vap_suite[i].test_name != NULL; i++) {
		hwr_pcv_case_t *test = &platform_create_vap_suite[i];

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
	printf("\nplatform_create_vap: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
