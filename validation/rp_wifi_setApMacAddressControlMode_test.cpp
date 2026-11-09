/*
 * TEST RUNNER: rp_wifi_setApMacAddressControlMode_test
 *
 * Same shape as the other *_test.cpp runners: test_rp_wifi_setApMacAddressControlMode() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the interface object.  During the call the WHOLE object is POISONED except the three fields the
 * function may use (vap_info.vap_mode, vap_info.u.bss_info.mac_filter_enable, vap_info.u.bss_info.mac_filter_mode), so a read or write of any other byte aborts
 * under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.
 * Checks: return value (RETURN_ERR without interface, RETURN_OK otherwise); mac_filter_enable / mac_filter_mode as expected (0 -> FALSE/black, 1 -> TRUE/white,
 * 2 -> TRUE/black for an AP VAP, unchanged otherwise); all other bytes of the interface unchanged; one lookup per call with the same index; the log text; the guard slab.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "hwr_rmc.h"
#include <sanitizer/asan_interface.h>

static rmc_iface_t iface_obj, iface_ref;
static char log_before[HWR_LOG_SZ];
static char why[200];

#define F_MODE   (offsetof(rmc_iface_t, vap_info) + offsetof(wifi_vap_info_t, vap_mode))
#define F_ENABLE (offsetof(rmc_iface_t, vap_info) + offsetof(wifi_vap_info_t, u.bss_info.mac_filter_enable))
#define F_FMODE  (offsetof(rmc_iface_t, vap_info) + offsetof(wifi_vap_info_t, u.bss_info.mac_filter_mode))

static void poison_but_fields(void (*fn)(void const volatile *, size_t))
{
	unsigned char keep[sizeof(rmc_iface_t)];
	size_t i = 0;

	memset(keep, 0, sizeof(keep));
	memset(keep + F_MODE, 1, sizeof(iface_obj.vap_info.vap_mode));
	memset(keep + F_ENABLE, 1, sizeof(iface_obj.vap_info.u.bss_info.mac_filter_enable));
	memset(keep + F_FMODE, 1, sizeof(iface_obj.vap_info.u.bss_info.mac_filter_mode));
	while (i < sizeof(keep)) {
		size_t j = i;
		while (j < sizeof(keep) && keep[j] == keep[i]) j++;
		if (!keep[i]) fn((char *)&iface_obj + i, j - i);
		i = j;
	}
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	poison_but_fields(fn);
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_rp_wifi_setApMacAddressControlMode(const hwr_rmc_case_t *t)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_rp_wifi_setApMacAddressControlMode(t->ap_index, t->filter_mode);
	poison(0);
	return ret;
}

static int check(const hwr_rmc_case_t *t, int ret)
{
	hwr_rmc_world_t *w = &hwr_rmc_world;
	int found = t->has_iface == 1;
	int expect_ret = found ? RETURN_OK : RETURN_ERR;
	int en = t->pre_enable, md = t->pre_mode;
	char want[96];

	if (found && t->vap_mode == 0) {
		if (t->filter_mode == 0)      { en = 0; md = 0; }
		else if (t->filter_mode == 1) { en = 1; md = 1; }
		else if (t->filter_mode == 2) { en = 1; md = 0; }
	}
	if (ret != expect_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, expect_ret); return 0; }
	if (w->lookups != t->calls || w->last_lookup != t->ap_index) { snprintf(why, sizeof(why), "%d lookups (last %d), expected %d for %d", w->lookups, w->last_lookup, t->calls, t->ap_index); return 0; }
	if (found) {
		if ((int)iface_obj.vap_info.u.bss_info.mac_filter_enable != en) { snprintf(why, sizeof(why), "mac_filter_enable %d, expected %d", (int)iface_obj.vap_info.u.bss_info.mac_filter_enable, en); return 0; }
		if ((int)iface_obj.vap_info.u.bss_info.mac_filter_mode != md) { snprintf(why, sizeof(why), "mac_filter_mode %d, expected %d", (int)iface_obj.vap_info.u.bss_info.mac_filter_mode, md); return 0; }
		iface_ref.vap_info.u.bss_info.mac_filter_enable = (BOOL)en;
		iface_ref.vap_info.u.bss_info.mac_filter_mode = (wifi_mac_filter_mode_t)md;
	}
	if (memcmp(&iface_obj, &iface_ref, sizeof(iface_obj)) != 0) { snprintf(why, sizeof(why), "a byte of the interface other than the filter fields was modified"); return 0; }
	if (!found && t->prefill + 60 < HWR_LOG_USE - 1) {
		snprintf(want, sizeof(want), "interface for ap index:%d not found", t->ap_index);
		if (strstr(hwr_log_buf + t->prefill, want) == NULL) { snprintf(why, sizeof(why), "'%s' not logged", want); return 0; }
	}
	if (found && memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, sizeof(why), "the log was modified (the function logs nothing when the interface exists)"); return 0; }
	if (t->prefill >= HWR_LOG_USE - 1 && memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, sizeof(why), "log modified although the slot is full"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_rp_wifi_setApMacAddressControlMode(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rp_wifi_setApMacAddressControlMode_suite[i].test_name != NULL; i++) {
		hwr_rmc_case_t *t = &rp_wifi_setApMacAddressControlMode_suite[i];

		printf("--- Running Test: %s ---\n", t->test_name);

		memset(&hwr_rmc_world, 0, sizeof(hwr_rmc_world));
		memset(&iface_obj, 0x77, sizeof(iface_obj));
		iface_obj.vap_info.vap_mode = (wifi_vap_mode_t)t->vap_mode;
		iface_obj.vap_info.u.bss_info.mac_filter_enable = (BOOL)t->pre_enable;
		iface_obj.vap_info.u.bss_info.mac_filter_mode = (wifi_mac_filter_mode_t)t->pre_mode;
		memcpy(&iface_ref, &iface_obj, sizeof(iface_obj));
		if (t->has_iface) {
			hwr_rmc_world.iface = &iface_obj;
			hwr_rmc_world.iface_vap = t->has_iface == 1 ? t->ap_index : (int)((unsigned)t->ap_index + 1u);
		}
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', t->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		why[0] = 0;
		int ret = test_rp_wifi_setApMacAddressControlMode(t);

		if (check(t, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (got=%d) %s =====\n", t->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_setApMacAddressControlMode (raspberry-pi): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
