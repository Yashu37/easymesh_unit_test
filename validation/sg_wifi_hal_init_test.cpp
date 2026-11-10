/*
 * TEST RUNNER: sg_wifi_hal_init_test
 *
 * test_sg_wifi_hal_init() POISONS what the function must not touch (the stand-in radio slots beyond the configured count, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and unpoisons.  run_all_tests compares the result with a reference model of the CORRECT behaviour: the expected return value
 * and the exact order of the helper calls (call trace; e.g. "D L I E P R O T A U0 U1 F G0 G1 S"), the stored nl_event_fd close on eloop / EAP failure, the netlink socket map
 * created, the platform flags written by the hook, and a radio without an RDK-index match skipped.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_whi.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static const char *netmap_sentinel_unset = NULL;

static void poison(int on, const hwr_whi_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	for (unsigned r = t->nrad < HWR_WHI_MAXR ? t->nrad : HWR_WHI_MAXR; r < HWR_WHI_MAXR; r++) fn(&hwr_whi_world.hal.radio_info[r], sizeof(hwr_whi_world.hal.radio_info[r]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned */
static int test_sg_wifi_hal_init(const hwr_whi_case_t *t)
{
	int ret;

	poison(1, t);
	ret = hwr_sg_wifi_hal_init();
	poison(0, t);
	return ret;
}

static void add(char *tr, const char *s) { size_t n = strlen(tr); snprintf(tr + n, 256 - n, "%s ", s); }
static void addi(char *tr, const char *s, int i) { char b[32]; snprintf(b, sizeof(b), "%s%d", s, i); add(tr, b); }

/* reference model: returns the expected return value, fills the expected trace */
static int model(const hwr_whi_case_t *t, char *tr)
{
	tr[0] = '\0';
	add(tr, "D");
	if (t->drv_null) return -1;
	for (int i = 0; i <= t->lsmod_false; i++) add(tr, "L");
	add(tr, "M"); add(tr, "I");
	if (t->init_ret != 0) return -1;
	add(tr, "E");
	add(tr, "P"); if (t->prim_ret != 0) return -1;
	add(tr, "R"); if (t->rinfo_ret != 0) return -1;
	add(tr, "O"); if (t->eloop_ret < 0) { addi(tr, "C", 77); return -1; }
	add(tr, "T"); if (t->pthr_ret != 0) return -1;
	add(tr, "A"); if (t->eap_ret != 0) { addi(tr, "C", 77); return -1; }
	for (unsigned i = 0; i < t->nrad; i++) {
		int k = (int)i - t->shift;                      /* position of the radio whose RDK index is i */
		if (k < 0 || k >= (int)t->nrad) continue;       /* no such radio: skipped */
		if (!((t->present >> k) & 1)) continue;         /* sleeping in ECO mode */
		addi(tr, "U", k);
		if (k == t->upd_fail_radio) return -1;
	}
	add(tr, "F"); if (t->chan_ret != 0) return -1;
	if (t->caps_fn) for (unsigned i = 0; i < t->nrad; i++) addi(tr, "G", i);
	if (t->flags_fn) add(tr, "S");
	return 0;
}

static int check(const hwr_whi_case_t *t, int ret, const char *want_tr, int want_ret)
{
	if (ret != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d; trace \"%s\" expected \"%s\"", ret, want_ret, hwr_whi_world.trace, want_tr); return 0; }
	if (strcmp(hwr_whi_world.trace, want_tr) != 0) { snprintf(why, sizeof(why), "call trace \"%s\", expected \"%s\"", hwr_whi_world.trace, want_tr); return 0; }
	if (want_ret == 0 && t->flags_fn && hwr_whi_world.hal.platform_flags != 0x1f) { snprintf(why, sizeof(why), "platform flags not stored"); return 0; }
	if (strstr(want_tr, "M") && hwr_whi_world.hal.netlink_socket_map == netmap_sentinel_unset) { snprintf(why, sizeof(why), "netlink socket map not created"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_whi_case_t *t)
{
	hwr_whi_world_t *w = &hwr_whi_world;

	memset(w, 0, sizeof(*w));
	w->hal.num_radios = t->nrad;
	w->hal.nl_event_fd = 77;
	for (unsigned r = 0; r < HWR_WHI_MAXR; r++) {
		w->hal.radio_info[r].index = r; w->hal.radio_info[r].rdk_radio_index = r + t->shift; w->hal.radio_info[r].radio_presence = (t->present >> r) & 1;
	}
	w->drv_null = t->drv_null; w->lsmod_false = t->lsmod_false; w->init_ret = t->init_ret; w->eco_ret = t->eco_ret; w->prim_ret = t->prim_ret;
	w->rinfo_ret = t->rinfo_ret; w->eloop_ret = t->eloop_ret; w->pthr_ret = t->pthr_ret; w->eap_ret = t->eap_ret; w->upd_fail_radio = t->upd_fail_radio;
	w->chan_ret = t->chan_ret; w->caps_fn = t->caps_fn; w->flags_fn = t->flags_fn;
}

extern "C" void run_all_tests_sg_wifi_hal_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_init_suite[i].test_name != NULL; i++) {
		hwr_whi_case_t *test = &sg_wifi_hal_init_suite[i];
		char want_tr[256];

		printf("--- Running Test: %s ---\n", test->test_name);

		int want_ret = model(test, want_tr);
		setup(test);
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_init(test);

		if (check(test, ret, want_tr, want_ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, want_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
