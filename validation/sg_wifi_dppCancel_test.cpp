/*
 * TEST RUNNER: sg_wifi_dppCancel_test
 *
 * test_sg_wifi_dppCancel() POISONS what the function must not touch, calls the handler and unpoisons: the instance's group / hashfcn pointers and its group_num / digestlen / noncelen / nid counters, its
 * k1 / k2 / ke / rauth / iauth / initiator / responder / enrollee nonce arrays (the function only frees the pointer members), the context's config object, channels_list, received_frame, session union and
 * sta_mac, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  (The instance block itself is freed by the function, so its poison is only removed when it was NOT freed.)  setup() builds a real
 * P-256 instance in a malloc'ed block with every member allocated; after each case a LeakSanitizer pass checks that everything the instance owned was freed and run_all_tests compares the result with a
 * reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wdk.h"
#include <sanitizer/asan_interface.h>
#include <sanitizer/lsan_interface.h>

static char why[300];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t *g_inst;
static EC_GROUP *g_group;
static int g_ret, g_ret2;
static wifi_device_dpp_context_t *g_ctx_arg;
static int g_leaked;

static void poison_inst(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	if (!g_inst) return;
	fn(&g_inst->group, 2 * sizeof(void *));
	fn(&g_inst->group_num, 4 * sizeof(int));
	fn(g_inst->initiator_nonce, sizeof(g_inst->initiator_nonce)); fn(g_inst->responder_nonce, sizeof(g_inst->responder_nonce)); fn(g_inst->enrollee_nonce, sizeof(g_inst->enrollee_nonce));
	fn(g_inst->k1, sizeof(g_inst->k1)); fn(g_inst->k2, sizeof(g_inst->k2)); fn(g_inst->ke, sizeof(g_inst->ke)); fn(g_inst->rauth, sizeof(g_inst->rauth)); fn(g_inst->iauth, sizeof(g_inst->iauth));
}

static void poison_ctx(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&g_ctx.config, sizeof(g_ctx.config)); fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(&g_ctx.received_frame, sizeof(g_ctx.received_frame));
	fn(&g_ctx.session_data.u, sizeof(g_ctx.session_data.u)); fn(g_ctx.session_data.sta_mac, sizeof(g_ctx.session_data.sta_mac));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void setup(const hwr_wdk_case_t *t)
{
	g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	memset(&g_ctx, 0, sizeof(g_ctx));
	g_ctx.session_data.session = t->session ? wifi_dpp_session_type_reconfig : wifi_dpp_session_type_config;
	g_inst = NULL;
	if (t->nul != 2) {
		g_inst = (wifi_dpp_instance_t *)calloc(1, sizeof(*g_inst));
		g_inst->group = g_group; g_inst->hashfcn = EVP_sha256(); g_inst->group_num = 19; g_inst->digestlen = 32; g_inst->noncelen = 16; g_inst->nid = NID_X9_62_prime256v1;
		int sk = t->skip, all = (sk == 12);
		if (!all && sk != 1) g_inst->N = EC_POINT_new(g_group);
		if (!all && sk != 2) g_inst->M = EC_POINT_new(g_group);
		if (!all && sk != 3) g_inst->responder_proto_pt = EC_POINT_new(g_group);
		if (t->session && !all && sk != 4) g_inst->responder_connector = EC_POINT_new(g_group);
		if (!all && sk != 5) { g_inst->initiator_proto_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_inst->initiator_proto_key); }
		if (!all && sk != 6) g_inst->bnctx = BN_CTX_new();
		if (!all && sk != 7) g_inst->prime = BN_new();
		if (!all && sk != 8) g_inst->n = BN_new();
		if (!all && sk != 9) g_inst->m = BN_new();
		if (!all && sk != 10) g_inst->y = BN_new();
		if (!all && sk != 11) g_inst->x = BN_new();
	}
	g_ctx.session_data.instance = g_inst;
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;
}

static void cleanup(void)
{
	EC_GROUP_free(g_group);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_dppCancel(const hwr_wdk_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		if (g_ctx_arg) { poison_ctx(1); if (g_ctx.session_data.instance) poison_inst(1); }
		int r = hwr_sg_wifi_dppCancel(g_ctx_arg);
		if (g_ctx_arg) { poison_ctx(0); if (g_ctx.session_data.instance) poison_inst(0); }
		if (n == 0) g_ret = r; else g_ret2 = r;
	}
}

#define FAIL(...) do { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } while (0)

static int check(const hwr_wdk_case_t *t)
{
	int want = (t->nul == 1) ? RETURN_ERR : RETURN_OK;

	if (g_ret != want) FAIL("returned %d, expected %d", g_ret, want);
	if (t->calls == 2 && g_ret2 != RETURN_OK) FAIL("second call returned %d, expected %d", g_ret2, RETURN_OK);
	if (t->nul != 1 && g_ctx.session_data.instance != NULL) FAIL("session_data.instance not cleared");
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) FAIL("guard byte %d modified", g);
	/* the group is only borrowed by the instance: it must still be usable after the cancel */
	if (EC_GROUP_get_curve_name(g_group) != NID_X9_62_prime256v1) FAIL("the borrowed EC_GROUP was damaged");
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppCancel(void)
{
	int pass = 0, fail = 0;

	g_leaked = 0;
	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppCancel_suite[i].test_name != NULL; i++) {
			hwr_wdk_case_t *test = &sg_wifi_dppCancel_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppCancel(test);

			int ok = check(test);
			cleanup();
			if (ok && !g_leaked && __lsan_do_recoverable_leak_check()) { g_leaked = 1; snprintf(why, sizeof(why), "memory leaked (LeakSanitizer)"); ok = 0; }
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_dppCancel: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
