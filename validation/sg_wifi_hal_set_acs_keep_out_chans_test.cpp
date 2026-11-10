/*
 * TEST RUNNER: sg_wifi_hal_set_acs_keep_out_chans_test
 *
 * test_sg_wifi_hal_set_acs_keep_out_chans() POISONS what the function must not touch, calls the handler and unpoisons: every channels_list[j] of every bandwidth entry beyond its num_channels_list (all of
 * them for an entry with num_channels_list 0 or negative), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The parameter is a heap block of exactly sizeof(wifi_radio_operationParam_t), so a list
 * pointer computed beyond the last channels_list array and read by the hook is a heap-buffer-overflow; buff is a stack array, so a hook that appends past it is a stack-buffer-overflow.  run_all_tests compares the
 * result with a reference model of the CORRECT behaviour (see the construct file): return value, number of hook calls and the (bandwidth, num_channels) each received, number of set calls, the string passed to the
 * set function (the chanspecs "0x%04x," of every list in order, trailing comma removed) or NULL, the guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wak.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_radio_operationParam_t *prm;
static char want_str[HWR_WAK_STR];
#define CAP (256 * 7 + 2)

static int lists_of(const hwr_wak_case_t *t, int i) { return t->nlist[i] > 0 ? (t->nlist[i] < MAX_CHANNELS ? t->nlist[i] : MAX_CHANNELS) : 0; }

static void poison(int on, const hwr_wak_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (prm) for (int i = 0; i < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; i++)
		for (int j = lists_of(t, i); j < MAX_CHANNELS; j++) fn(&prm->channels_per_bandwidth[i].channels_list[j], sizeof(prm->channels_per_bandwidth[i].channels_list[j]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_set_acs_keep_out_chans(const hwr_wak_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_set_acs_keep_out_chans(t->null_param ? NULL : prm, t->radio_index);
	poison(0, t);
}

/* reference model: returns the expected result; fills want_str, *want_gets, *want_sets (set_null: *want_null) */
static int model(const hwr_wak_case_t *t, int *want_gets, int *want_sets, int *want_null)
{
	int len = 0, gets = 0;

	*want_gets = 0; *want_sets = 0; *want_null = 0; want_str[0] = 0;
	if (t->null_param) { *want_sets = 1; *want_null = 1; return t->set_ret; }
	for (int i = 0; i < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; i++) {
		if (t->nlist[i] == 0) continue;
		if (t->nlist[i] > MAX_CHANNELS) { *want_gets = gets; return RETURN_ERR; }
		for (int j = 0; j < t->nlist[i]; j++) {
			if (len + 7 * t->nch[i] + 1 > CAP) { *want_gets = gets; return RETURN_ERR; }
			gets++;
			if (t->fail_at == gets) { *want_gets = gets; return RETURN_ERR; }
			for (int c = 0; c < t->nch[i]; c++) { len += snprintf(want_str + len, sizeof(want_str) - len, "0x%04x,", (unsigned)((((1 << i) << 8) | ((1 + c) & 0xff)) & 0xffff)); }
		}
	}
	*want_gets = gets; *want_sets = 1;
	if (len > 0) want_str[len - 1] = 0;
	return t->set_ret;
}

static int check(const hwr_wak_case_t *t)
{
	const hwr_wak_world_t *w = &hwr_wak_world;
	int gets, sets, isnull, want = model(t, &gets, &sets, &isnull);

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->get_calls != gets) { snprintf(why, sizeof(why), "the chanspec hook ran %d times, expected %d", w->get_calls, gets); return 0; }
	if (w->set_calls != sets) { snprintf(why, sizeof(why), "wifi_drv_set_acs_exclusion_list ran %d times, expected %d", w->set_calls, sets); return 0; }
	if (sets) {
		if (w->set_null != isnull) { snprintf(why, sizeof(why), "set got %s, expected %s", w->set_null ? "NULL" : "a string", isnull ? "NULL" : "a string"); return 0; }
		if (!isnull && strcmp(w->set_str, want_str) != 0) { snprintf(why, sizeof(why), "set got \"%.60s\"%s, expected \"%.60s\"", w->set_str, strlen(w->set_str) > 60 ? "..." : "", want_str); return 0; }
		if (w->set_radio != t->radio_index) { snprintf(why, sizeof(why), "set got radio %d, expected %d", w->set_radio, t->radio_index); return 0; }
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wak_case_t *t)
{
	memset(&hwr_wak_world, 0, sizeof(hwr_wak_world));
	hwr_wak_world.fail_at = t->fail_at; hwr_wak_world.set_ret = t->set_ret;
	prm = (wifi_radio_operationParam_t *)calloc(1, sizeof(wifi_radio_operationParam_t));
	for (int i = 0; i < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; i++) {
		wifi_channels_list_per_bandwidth_t *b = &prm->channels_per_bandwidth[i];
		b->chanwidth = (wifi_channelBandwidth_t)(1 << i);
		b->num_channels_list = t->nlist[i];
		for (int j = 0; j < lists_of(t, i); j++) {
			b->channels_list[j].num_channels = t->nch[i];
			for (int c = 0; c < MAX_CHANNELS; c++) b->channels_list[j].channels_list[c] = 1 + c;
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_set_acs_keep_out_chans(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_set_acs_keep_out_chans_suite[i].test_name != NULL; i++) {
			hwr_wak_case_t *test = &sg_wifi_hal_set_acs_keep_out_chans_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_set_acs_keep_out_chans(test);

			int ok = check(test);
			free(prm); prm = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_set_acs_keep_out_chans: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
