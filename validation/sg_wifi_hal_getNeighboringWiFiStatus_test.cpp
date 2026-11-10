/*
 * TEST RUNNER: sg_wifi_hal_getNeighboringWiFiStatus_test
 *
 * test_sg_wifi_hal_getNeighboringWiFiStatus() POISONS what the function must not touch, calls the handler and unpoisons: the radio / interface slots other than the addressed one (all of them when the call must
 * be rejected before the radio is used), the interface's pad bytes after its last member, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the result with a reference
 * model of the CORRECT behaviour (see the construct file): return value, errno, scan_state and scan_has_results afterwards, copy_scan_results calls (and that both mutexes were held during it), both mutexes
 * released, output pointer / size written only on success, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "hwr_wnw.h"
#include <sanitizer/asan_interface.h>

#define NONE 0
#define ERR 1
#define RUN 2
#define ABT 3
static char why[240];
static int ret_val, errno_val;
static wifi_neighbor_ap2_t *out_arr;
static unsigned int out_size;
static wifi_neighbor_ap2_t canary;
static const unsigned int CANARY_SIZE = 0xABCD;

static int arg_bad(const hwr_wnw_case_t *t) { return t->arr_null || t->size_null; }
static int idx_bad(const hwr_wnw_case_t *t) { return t->index < 0 || t->index >= MAX_NUM_RADIOS; }
static int rejects_early(const hwr_wnw_case_t *t) { return arg_bad(t) || idx_bad(t); }
static int slot_of(const hwr_wnw_case_t *t) { return t->index >= 0 && t->index < HWR_WNW_MAXR ? t->index : 0; }
static int iface_used(const hwr_wnw_case_t *t) { return !rejects_early(t) && !t->no_radio && !t->no_iface; }

/* the reference model of the correct behaviour */
struct model { int ret, err, state_after; unsigned has_after; int copy; };
static model run_model(const hwr_wnw_case_t *t)
{
	model m = { 0, 0, t->state, t->has, 0 };
	if (arg_bad(t) || idx_bad(t)) { m.ret = WIFI_HAL_INVALID_ARGUMENTS; return m; }
	if (t->no_radio || t->no_iface) { m.ret = WIFI_HAL_ERROR; return m; }
	if (t->state == ABT || t->state == ERR) { m.ret = WIFI_HAL_ERROR; m.state_after = NONE; return m; }
	int go = (t->has & 1) || (t->test_api && (t->has & 2));
	if (!go) {
		if (t->state == NONE) { m.ret = WIFI_HAL_ERROR; return m; }
		if (t->state == RUN) { m.ret = WIFI_HAL_NOT_READY; m.err = EAGAIN; return m; }
	}
	m.copy = 1;
	if (t->test_api) { if (t->state == RUN) m.has_after &= ~2u; }
	else m.has_after &= ~1u;
	m.ret = t->copy_ret ? WIFI_HAL_ERROR : WIFI_HAL_SUCCESS;
	return m;
}

static void poison(int on, const hwr_wnw_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wnw_world_t *w = &hwr_wnw_world;
	int s = slot_of(t);

	for (int i = 0; i < HWR_WNW_MAXR; i++)
		if (rejects_early(t) || t->no_radio || i != s) { fn(&w->radios[i], sizeof(w->radios[i])); fn(&w->ifs[i], sizeof(w->ifs[i])); }
	if (!rejects_early(t) && !t->no_radio) fn(w->ifs[s].pad, sizeof(w->ifs[s].pad));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_getNeighboringWiFiStatus(const hwr_wnw_case_t *t)
{
	wifi_neighbor_ap2_t **pa = t->arr_null ? NULL : &out_arr;
	unsigned int *ps = t->size_null ? NULL : &out_size;

	poison(1, t);
	errno = 0;
	ret_val = t->test_api ? hwr_sg_wifi_hal_getNeighboringWiFiStatus_test(t->index, pa, ps) : hwr_sg_wifi_hal_getNeighboringWiFiStatus(t->index, pa, ps);
	errno_val = errno;
	poison(0, t);
}

static int check(const hwr_wnw_case_t *t)
{
	const hwr_wnw_world_t *w = &hwr_wnw_world;
	model m = run_model(t);
	int s = slot_of(t);

	if (ret_val != m.ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, m.ret); return 0; }
	if (m.err && errno_val != m.err) { snprintf(why, sizeof(why), "errno %d, expected %d", errno_val, m.err); return 0; }
	if (w->copy_calls != m.copy) { snprintf(why, sizeof(why), "copy_scan_results ran %d times, expected %d", w->copy_calls, m.copy); return 0; }
	if (m.copy && !w->mutex_ok_at_copy) { snprintf(why, sizeof(why), "mutexes not held during the copy"); return 0; }
	if (iface_used(t)) {
		const wifi_interface_info_t *f = &w->ifs[s];
		if (f->scan_state != m.state_after) { snprintf(why, sizeof(why), "scan_state is %d, expected %d", f->scan_state, m.state_after); return 0; }
		if (f->scan_has_results != (uint8_t)m.has_after) { snprintf(why, sizeof(why), "scan_has_results is 0x%x, expected 0x%x", f->scan_has_results, m.has_after); return 0; }
		/* both mutexes must be free again */
		pthread_mutex_t *mx[2] = { (pthread_mutex_t *)&f->scan_state_mutex, (pthread_mutex_t *)&f->scan_info_ap_mutex };
		for (int k = 0; k < 2; k++) {
			if (pthread_mutex_trylock(mx[k]) != 0) { snprintf(why, sizeof(why), "mutex %d still locked", k); return 0; }
			pthread_mutex_unlock(mx[k]);
		}
	}
	if (m.ret == WIFI_HAL_SUCCESS) {
		if (out_arr != &hwr_wnw_marker || out_size != HWR_WNW_MARK_SIZE) { snprintf(why, sizeof(why), "outputs not written on success"); return 0; }
	} else if (out_arr != &canary || out_size != CANARY_SIZE) { snprintf(why, sizeof(why), "outputs modified on failure"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wnw_case_t *t)
{
	hwr_wnw_world_t *w = &hwr_wnw_world;

	memset(w, 0, sizeof(*w));
	w->no_radio = t->no_radio; w->no_iface = t->no_iface; w->copy_ret = t->copy_ret;
	for (int i = 0; i < HWR_WNW_MAXR; i++) {
		w->radios[i].index = i; snprintf(w->radios[i].name, sizeof(w->radios[i].name), "wl%d", i);
		pthread_mutex_init(&w->ifs[i].scan_state_mutex, NULL); pthread_mutex_init(&w->ifs[i].scan_info_ap_mutex, NULL);
	}
	{ int s = slot_of(t); w->ifs[s].scan_state = t->state; w->ifs[s].scan_has_results = (uint8_t)t->has; }
	out_arr = &canary; out_size = CANARY_SIZE; errno_val = 0;
}

extern "C" void run_all_tests_sg_wifi_hal_getNeighboringWiFiStatus(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_getNeighboringWiFiStatus_suite[i].test_name != NULL; i++) {
			hwr_wnw_case_t *test = &sg_wifi_hal_getNeighboringWiFiStatus_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_getNeighboringWiFiStatus(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_getNeighboringWiFiStatus: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
