/*
 * TEST RUNNER: sg_wifi_dppProcessConfigResult_test
 *
 * test_sg_wifi_dppProcessConfigResult() POISONS what the function must not touch, calls the handler and unpoisons: the instance's k1 / k2 / rauth / iauth / responder_nonce / initiator_nonce arrays
 * (the function only uses ke, digestlen and, for the enrollee nonce, enrollee_nonce), the context's config object, channels_list, session union and sta_mac, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The frame lives in a heap block of EXACTLY the declared length, so ASan also reports every read outside the frame.  setup() builds the frame with the same AES-SIV
 * key the function derives from instance->ke.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file) and checks the frame bytes, ke and the guard
 * slab are unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "hwr_wcr.h"
#include <sanitizer/asan_interface.h>

#define FRAME_HDR 6
#define PLAIN_SZ 128                       /* unsigned char plain[128] in the function */
#define ENONCE_LEN 16

static char why[240];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t g_inst;
static unsigned char *g_frame;
static unsigned int g_declared;
static std::vector<unsigned char> g_frame_copy;
static unsigned char g_ke_copy[64];
static int g_ret;
static wifi_device_dpp_context_t *g_ctx_arg;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(g_inst.k1, sizeof(g_inst.k1)); fn(g_inst.k2, sizeof(g_inst.k2)); fn(g_inst.rauth, sizeof(g_inst.rauth)); fn(g_inst.iauth, sizeof(g_inst.iauth));
	fn(g_inst.responder_nonce, sizeof(g_inst.responder_nonce)); fn(g_inst.initiator_nonce, sizeof(g_inst.initiator_nonce));
	fn(&g_ctx.config, sizeof(g_ctx.config)); fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(&g_ctx.session_data.u, sizeof(g_ctx.session_data.u)); fn(g_ctx.session_data.sta_mac, sizeof(g_ctx.session_data.sta_mac));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void put_tlv(std::vector<unsigned char> &v, unsigned short type, unsigned short declared, const unsigned char *data, size_t actual)
{
	size_t o = v.size();
	v.resize(o + 4 + actual);
	memcpy(&v[o], &type, 2); memcpy(&v[o + 2], &declared, 2);
	if (actual) memcpy(&v[o + 4], data, actual);
}

static void setup(const hwr_wcr_case_t *t)
{
	memset(&g_ctx, 0, sizeof(g_ctx)); memset(&g_inst, 0, sizeof(g_inst));
	g_inst.digestlen = t->digest;
	for (int i = 0; i < 64; i++) g_inst.ke[i] = (unsigned char)(0x40 + i);
	for (int i = 0; i < ENONCE_LEN; i++) g_inst.enrollee_nonce[i] = (unsigned char)(0xE0 + i);
	g_inst.noncelen = ENONCE_LEN;
	memcpy(g_ke_copy, g_inst.ke, 64);
	g_ctx.session_data.session = wifi_dpp_session_type_config;
	g_ctx.session_data.instance = (t->nul == 2) ? NULL : &g_inst;
	g_ctx.enrollee_status = RESPONDER_STATUS_BAD_CODE;           /* sentinel: every outcome must overwrite it */

	std::vector<unsigned char> f(FRAME_HDR, 0);
	f[0] = 0x50; f[1] = 0x6F; f[2] = 0x9A; f[3] = 0x1A; f[4] = 1; f[5] = 11;      /* frame type: configuration result */
	for (int k = 0; k < t->before; k++) { unsigned char b = (unsigned char)(0x31 + k); put_tlv(f, k ? wifi_dpp_attrib_id_proto_version : wifi_dpp_attrib_id_transaction_id, 1, &b, 1); }

	if (t->wrap) {
		size_t non_wrapped = f.size() - FRAME_HDR;
		(void)non_wrapped;
		std::vector<unsigned char> plain;
		unsigned char sv, en[ENONCE_LEN], pad[200];
		memset(pad, 0x77, sizeof(pad));
		for (int i = 0; i < ENONCE_LEN; i++) en[i] = (unsigned char)(0xE0 + i);
		if (t->enonce == 2) en[5] ^= 0xFF;
		sv = (t->status == 2) ? 1 : (t->status == 3) ? 0xFF : 0;
		unsigned char sv2[2] = { 0, 0 };
		if (t->wrap != 5) {
			for (int pass = 0; pass < 2; pass++) {
				int isst = (t->enonce_first ? pass == 1 : pass == 0);
				if (isst) {
					if (t->status == 4) put_tlv(plain, wifi_dpp_attrib_id_status, 2, sv2, 2);
					else if (t->status == 5) put_tlv(plain, wifi_dpp_attrib_id_status, 0, NULL, 0);
					else if (t->status) put_tlv(plain, wifi_dpp_attrib_id_status, 1, &sv, 1);
				} else if (t->enonce) put_tlv(plain, wifi_dpp_attrib_id_enrollee_nonce, ENONCE_LEN, en, ENONCE_LEN);
			}
			if (t->wrap == 6 || t->wrap == 7) {
				size_t target = (t->wrap == 6) ? PLAIN_SZ : PLAIN_SZ + 1;
				put_tlv(plain, wifi_dpp_attrib_id_reserved_1, (unsigned short)(target - plain.size() - 4), pad, target - plain.size() - 4);
			}
		}
		if (t->wrap == 3) {
			unsigned char junk[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
			put_tlv(f, wifi_dpp_attrib_id_wrapped_data, 8, junk, 8);
		} else if (t->wrap == 4) {
			unsigned char junk[20]; memset(junk, 0x33, sizeof(junk));
			put_tlv(f, wifi_dpp_attrib_id_wrapped_data, 200, junk, sizeof(junk));
		} else {
			size_t wl = plain.size(), off = f.size();
			f.resize(off + 4 + 16 + wl);
			wifi_tlv_t *w = (wifi_tlv_t *)&f[off];
			w->type = wifi_dpp_attrib_id_wrapped_data; w->length = (unsigned short)(wl + 16);
			unsigned char key[64];
			for (int i = 0; i < 64; i++) key[i] = (t->wrap == 8) ? (unsigned char)(0x90 + i) : g_inst.ke[i];
			siv_ctx sc; siv_init(&sc, key, (t->digest == 48) ? SIV_384 : (t->digest == 64) ? SIV_512 : SIV_256);
			wifi_dppPublicActionFrameBody_t *body = (wifi_dppPublicActionFrameBody_t *)f.data();
			siv_encrypt(&sc, plain.data(), &w->value[16], (int)wl, w->value, 1, body, FRAME_HDR);
			if (t->wrap == 2) w->value[16 + 3] ^= 0x01;
		}
	}
	g_declared = (t->flen >= 0) ? (unsigned int)t->flen : (unsigned int)f.size();
	size_t alloc = g_declared ? g_declared : 1;
	g_frame = (unsigned char *)malloc(alloc);
	memset(g_frame, 0, alloc);
	memcpy(g_frame, f.data(), alloc < f.size() ? alloc : f.size());
	g_frame_copy.assign(g_frame, g_frame + alloc);
	g_ctx.received_frame.frame = (t->nul == 3) ? NULL : g_frame;
	g_ctx.received_frame.length = g_declared;
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;
}

static void cleanup(void)
{
	free(g_frame); g_frame = NULL;
}

/* poison, call, unpoison */
static void test_sg_wifi_dppProcessConfigResult(const hwr_wcr_case_t *t)
{
	(void)t;
	if (g_ctx_arg) poison(1);
	g_ret = hwr_sg_wifi_dppProcessConfigResult(g_ctx_arg);
	if (g_ctx_arg) poison(0);
}

/* reference model of the CORRECT behaviour */
static int model(const hwr_wcr_case_t *t)
{
	if (t->nul || t->flen >= 0) return RETURN_ERR;
	if (t->digest != 32 && t->digest != 48 && t->digest != 64) return RETURN_ERR;
	if (t->wrap != 1 && t->wrap != 6) return RETURN_ERR;
	if (t->status != 1) return RETURN_ERR;
	if (t->enonce != 1) return RETURN_ERR;
	return RETURN_OK;
}

static int check(const hwr_wcr_case_t *t)
{
	int want = model(t);
	size_t alloc = g_declared ? g_declared : 1;

	if (g_ret != want) { snprintf(why, sizeof(why), "returned %d, expected %d", g_ret, want); return 0; }
	if (t->nul != 1) {
		int ws = (want == RETURN_OK) ? RESPONDER_STATUS_OK : RESPONDER_STATUS_CONFIGURATION_FAILURE;
		if (g_ctx.enrollee_status != ws) { snprintf(why, sizeof(why), "enrollee_status %d, expected %d", (int)g_ctx.enrollee_status, ws); return 0; }
	}
	if (memcmp(g_frame, g_frame_copy.data(), alloc) != 0) { snprintf(why, sizeof(why), "frame modified"); return 0; }
	if (memcmp(g_inst.ke, g_ke_copy, 64) != 0) { snprintf(why, sizeof(why), "ke modified"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppProcessConfigResult(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppProcessConfigResult_suite[i].test_name != NULL; i++) {
			hwr_wcr_case_t *test = &sg_wifi_dppProcessConfigResult_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppProcessConfigResult(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
			cleanup();
		}
	printf("\nwifi_dppProcessConfigResult: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
