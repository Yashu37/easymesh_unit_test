/*
 * TEST RUNNER: sg_wifi_dppSendReconfigAuthCnf_test
 *
 * test_sg_wifi_dppSendReconfigAuthCnf() POISONS what the function must not touch, calls the handler and unpoisons: the instance's k1 / k2 / rauth / iauth / enrollee_nonce arrays and its M / N / m / n / l /
 * initiator_proto_key / responder_proto_pt pointers, the context's config object (everything except the credentials.keyManagement the function prints), channels_list and received_frame, the session union
 * except match_tran_id (the only member of it the function reads and writes), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The mock wifi_sendActionFrame captures the frame;
 * run_all_tests decrypts it with the same AES-SIV key (AAD = the 6-byte DPP frame body), checks every attribute and compares the result with a reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "hwr_wsx.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t g_inst;
static int g_ret;
static wifi_device_dpp_context_t *g_ctx_arg;
static unsigned char g_sta[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_dpp_reconfig_data_t *rd = &g_ctx.session_data.u.reconfig_data;
	size_t mt = (size_t)((char *)&rd->match_tran_id - (char *)&g_ctx.session_data.u);

	fn(g_inst.k1, sizeof(g_inst.k1)); fn(g_inst.k2, sizeof(g_inst.k2)); fn(g_inst.rauth, sizeof(g_inst.rauth)); fn(g_inst.iauth, sizeof(g_inst.iauth));
	fn(g_inst.enrollee_nonce, sizeof(g_inst.enrollee_nonce));
	fn(&g_inst.M, 2 * sizeof(void *)); fn(&g_inst.m, 3 * sizeof(void *)); fn(&g_inst.initiator_proto_key, sizeof(void *)); fn(&g_inst.responder_proto_pt, sizeof(void *));
	fn(g_ctx.config.discovery, sizeof(g_ctx.config.discovery)); fn(&g_ctx.config.credentials.creds, sizeof(g_ctx.config.credentials.creds));
	fn(&g_ctx.config.reconfigCtx, 2 * sizeof(void *));
	fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(&g_ctx.received_frame, sizeof(g_ctx.received_frame));
	fn((char *)&g_ctx.session_data.u, mt & ~(size_t)7);
	fn((char *)&g_ctx.session_data.u + ((mt + 8) & ~(size_t)7), sizeof(g_ctx.session_data.u) - ((mt + 8) & ~(size_t)7));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void setup(const hwr_wsx_case_t *t)
{
	memset(&g_ctx, 0, sizeof(g_ctx)); memset(&g_inst, 0, sizeof(g_inst));
	g_inst.digestlen = t->digest; g_inst.noncelen = t->noncelen;
	for (int i = 0; i < 64; i++) g_inst.ke[i] = (unsigned char)(0x40 + i);
	for (int i = 0; i < 32; i++) { g_inst.initiator_nonce[i] = (unsigned char)(0xA0 + i); g_inst.responder_nonce[i] = (unsigned char)(0xB0 + i); }
	g_ctx.ap_index = t->ap; g_ctx.configurator_version = (unsigned char)t->ver;
	g_ctx.enrollee_status = RESPONDER_STATUS_BAD_CODE;                   /* sentinel */
	g_ctx.config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
	g_ctx.session_data.session = wifi_dpp_session_type_reconfig;
	g_ctx.session_data.instance = (t->nul == 2) ? NULL : &g_inst;
	memcpy(g_ctx.session_data.sta_mac, g_sta, 6);
	g_ctx.session_data.channel = t->channel;
	g_ctx.session_data.u.reconfig_data.match_tran_id = (unsigned char)t->tran;
	memset(&hwr_wsx_cap, 0, sizeof(hwr_wsx_cap));
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;
}

/* poison, call, unpoison */
static void test_sg_wifi_dppSendReconfigAuthCnf(const hwr_wsx_case_t *t)
{
	(void)t;
	if (g_ctx_arg) poison(1);
	g_ret = hwr_sg_wifi_dppSendReconfigAuthCnf(g_ctx_arg);
	if (g_ctx_arg) poison(0);
}

static unsigned short freq_of(int ch)
{
	if (ch <= 14) return 2412 + 5 * (ch - 1);
	if (ch >= 36 && ch <= 64) return 5180 + 5 * (ch - 36);
	if (ch >= 100 && ch <= 140) return 5500 + 5 * (ch - 100);
	if (ch >= 149 && ch <= 165) return 5745 + 5 * (ch - 149);
	return 0;
}

#define FAIL(...) do { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } while (0)

static int check_frame(const hwr_wsx_case_t *t)
{
	const hwr_wsx_cap_t *c = &hwr_wsx_cap;
	const unsigned int H = sizeof(wifi_dppPublicActionFrame_t);
	if (c->calls != 1) FAIL("wifi_sendActionFrame called %d times", c->calls);
	if (c->ap != t->ap) FAIL("ap_index %d, expected %d", c->ap, t->ap);
	if (memcmp(c->sta, g_sta, 6) != 0) FAIL("sta mac differs");
	if (c->freq != freq_of(t->channel)) FAIL("frequency %lu, expected %u for channel %d", c->freq, freq_of(t->channel), t->channel);
	if (c->len < H + 4 + 16 || c->len > sizeof(c->frame)) FAIL("frame length %u", c->len);
	const wifi_dppPublicActionFrame_t *f = (const wifi_dppPublicActionFrame_t *)c->frame;
	if (f->public_action_hdr.cat != 4 || f->public_action_hdr.action != 9) FAIL("public action header");
	if (f->public_action_body.dpp_oui.oui[0] != 0x50 || f->public_action_body.dpp_oui.oui[1] != 0x6f || f->public_action_body.dpp_oui.oui[2] != 0x9a || f->public_action_body.dpp_oui.oui_type != 0x1a) FAIL("DPP OUI");
	if (f->public_action_body.crypto != 1 || f->public_action_body.frame_type != wifi_dpp_public_action_frame_type_recfg_auth_cnf) FAIL("crypto / frame type");
	wifi_tlv_t w; memcpy(&w, f->public_action_body.attrib, 4);
	if (w.type != wifi_dpp_attrib_id_wrapped_data || w.length < 16) FAIL("wrapped data TLV type 0x%x length %u", w.type, w.length);
	if (c->len != H + 4 + w.length) FAIL("frame length %u, expected %u", c->len, H + 4 + w.length);
	const unsigned char *wv = f->public_action_body.attrib + 4;
	int P = w.length - 16;
	int want = 5 + 5 + 2 * (4 + t->noncelen) + 8;
	if (P != want) FAIL("plaintext length %d, expected %d", P, want);
	std::vector<unsigned char> plain(P + 1);
	siv_ctx sc; siv_init(&sc, g_inst.ke, t->digest == 48 ? SIV_384 : t->digest == 64 ? SIV_512 : SIV_256);
	if (siv_decrypt(&sc, wv + 16, plain.data(), P, (unsigned char *)wv, 1, (unsigned char *)&f->public_action_body, (int)sizeof(wifi_dppPublicActionFrameBody_t)) < 1) FAIL("wrapped data does not decrypt (AAD = DPP frame body)");
	const unsigned char *p = plain.data();
	wifi_tlv_t a;
	memcpy(&a, p, 4); if (a.type != wifi_dpp_attrib_id_transaction_id || a.length != 1 || p[4] != (unsigned char)t->tran) FAIL("transaction id attribute"); p += 5;
	memcpy(&a, p, 4); if (a.type != wifi_dpp_attrib_id_proto_version || a.length != 1 || p[4] != (unsigned char)t->ver) FAIL("protocol version attribute"); p += 5;
	memcpy(&a, p, 4); if (a.type != wifi_dpp_attrib_id_initiator_nonce || a.length != t->noncelen || memcmp(p + 4, g_inst.initiator_nonce, t->noncelen)) FAIL("initiator nonce attribute"); p += 4 + t->noncelen;
	memcpy(&a, p, 4); if (a.type != wifi_dpp_attrib_id_responder_nonce || a.length != t->noncelen || memcmp(p + 4, g_inst.responder_nonce, t->noncelen)) FAIL("responder nonce attribute"); p += 4 + t->noncelen;
	memcpy(&a, p, 4); if (a.type != wifi_dpp_attrib_id_reconfig_flags || a.length != 4 || p[4] || p[5] || p[6] || p[7]) FAIL("reconfig flags attribute");
	return 1;
}

static int check(const hwr_wsx_case_t *t)
{
	int ok = (t->nul == 0 && (t->digest == 32 || t->digest == 48 || t->digest == 64));

	if (g_ret != (ok ? RETURN_OK : RETURN_ERR)) FAIL("returned %d, expected %d", g_ret, ok ? RETURN_OK : RETURN_ERR);
	if (ok) {
		if (!check_frame(t)) return 0;
		if (g_ctx.session_data.u.reconfig_data.match_tran_id != 0) FAIL("match_tran_id not cleared");
		if (g_ctx.session_data.channel != 2437) FAIL("session channel %u, expected the frequency 2437 of radio channel 6", g_ctx.session_data.channel);
		if (g_ctx.enrollee_status != RESPONDER_STATUS_BAD_CODE) FAIL("enrollee_status modified on success");
	} else {
		if (hwr_wsx_cap.calls != 0) FAIL("a frame was sent for a failed call");
		if (t->nul != 1 && g_ctx.enrollee_status != RESPONDER_STATUS_CONFIGURATION_FAILURE) FAIL("enrollee_status %d, expected RESPONDER_STATUS_CONFIGURATION_FAILURE", (int)g_ctx.enrollee_status);
		if (t->nul == 0 && g_ctx.session_data.u.reconfig_data.match_tran_id != (unsigned char)t->tran) FAIL("match_tran_id modified on failure");
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) FAIL("guard byte %d modified", g);
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppSendReconfigAuthCnf(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppSendReconfigAuthCnf_suite[i].test_name != NULL; i++) {
			hwr_wsx_case_t *test = &sg_wifi_dppSendReconfigAuthCnf_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppSendReconfigAuthCnf(test);

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
	printf("\nwifi_dppSendReconfigAuthCnf: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
