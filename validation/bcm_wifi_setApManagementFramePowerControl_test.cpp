/*
 * TEST RUNNER: bcm_wifi_setApManagementFramePowerControl_test
 *
 * Same shape as the other *_test.cpp runners: test_bcm_wifi_setApManagementFramePowerControl() POISONS what the function must not touch, calls the
 * handler and unpoisons; run_all_tests compares the result.  During the call it POISONS the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).
 * The runner restores libnl's default message size after every call (the stub shrinks it for the "request too small" rows).
 * Checks: return value; whether the command reached the "driver" (exactly once per call when expected, never otherwise); the request the driver saw
 * (interface index, wiphy, vendor id, sub-command, vendor-data nest, a 4-byte power attribute equal to the dBm argument).
 * The suite has no invalid-input rows (the arguments are plain integers), so there is no crash row.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hwr_bsp.h"
#include <sanitizer/asan_interface.h>

static bsp_iface_t iface_obj;
static char why[200];

/* poison, call, unpoison -- returns what the function returned */
int test_bcm_wifi_setApManagementFramePowerControl(const bsp_case_t *t)
{
	__asan_poison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	int ret = hwr_bcm_wifi_setApManagementFramePowerControl(t->ap_index, t->dbm);
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	__asan_unpoison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	return ret;
}

static void setup(const bsp_case_t *t)
{
	bsp_world_t *w = &hwr_bsp_world;

	memset(w, 0, sizeof(*w));
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&iface_obj, 0, sizeof(iface_obj));
	iface_obj.index = 7; iface_obj.phy_index = 1;
	iface_obj.vap_index = (t->has_iface == 2) ? (unsigned)t->ap_index + 1u : (unsigned)t->ap_index;
	w->iface = t->has_iface ? &iface_obj : NULL;
	w->cmd_fail = t->cmd_fail; w->send_rc = t->send_rc; w->room = t->room;
}

#define CHK(cond, ...) do { if (!(cond)) { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } } while (0)

static int one_call(const bsp_case_t *t, int *got)
{
	bsp_world_t *w = &hwr_bsp_world;
	int ret = test_bcm_wifi_setApManagementFramePowerControl(t);

	nlmsg_set_default_size((size_t)sysconf(_SC_PAGESIZE));
	*got = ret;
	CHK(ret == t->expected_ret, "returned %d, expected %d", ret, t->expected_ret);
	CHK(w->send_calls == (t->expect_sent ? 1 : 0), "%d command(s) sent, expected %d", w->send_calls, t->expect_sent ? 1 : 0);
	if (t->expect_sent) {
		CHK(w->req_ok, "request not parsable");
		CHK(w->got_ifindex == 7 && w->got_phy == 1, "request interface %u / wiphy %u wrong", w->got_ifindex, w->got_phy);
		CHK(w->got_vendor == 0x001018u, "vendor id 0x%x wrong", w->got_vendor);
		CHK(w->got_subcmd == 7u, "vendor sub-command %u wrong", w->got_subcmd);
		CHK(w->got_have_nest, "no vendor-data nest in the request");
		CHK(w->got_len == 4, "power attribute length %d, expected 4", w->got_len);
		CHK(w->got_pwr == t->dbm, "power on the wire %d, expected %d", w->got_pwr, t->dbm);
	}
	return 1;
}

static int run_one(const bsp_case_t *t)
{
	int ok, got = 0;

	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	ok = one_call(t, &got);
	if (ok && t->calls > 1) { int r2; setup(t); ok = one_call(t, &r2); }
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, got, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_bcm_wifi_setApManagementFramePowerControl(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; bcm_wifi_setApManagementFramePowerControl_suite[i].test_name != NULL; i++)
		if (run_one(&bcm_wifi_setApManagementFramePowerControl_suite[i])) pass++; else fail++;
	printf("\nwifi_setApManagementFramePowerControl (broadcom): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
