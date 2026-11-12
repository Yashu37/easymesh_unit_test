/*
 * TEST RUNNER: sg_wifi_dppProcessReconfigAuthResponse_test
 *
 * test_sg_wifi_dppProcessReconfigAuthResponse() POISONS what the function must not touch, calls the handler and unpoisons: the instance's k1 / k2 / rauth / iauth / enrollee_nonce arrays, the context's
 * channels_list, the session union's iPubKey and the union tail after reconfig_data, the tran_id table entries after index dpp_init_retries (the loop reads 0..retries only), the guard slab and the log
 * slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The frame lives in a heap block of EXACTLY the declared length, so ASan also reports every read outside the frame.  setup() builds a real P-256 session: the reconfig
 * key, the responder protocol key point P, the connector point C and a wrapped-data attribute AES-SIV encrypted with the key ke = HKDF(priv * (P + C)) the function derives (computed here with the
 * verbatim compute_reconfig_encryption_key (hwr_wra_ copy) on a reference instance).  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "hwr_wra.h"
#include <sanitizer/asan_interface.h>

#define FRAME_HDR 6
#define TBL(k) ((unsigned char)(0x10 + (k)))

static char why[240];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t g_inst;
static wifi_dpp_reconfig_instance_t g_recfg;
static EC_GROUP *g_group;
static BN_CTX *g_bn;
static EC_KEY *g_rk, *g_pk, *g_ck;                  /* reconfig key, responder protocol key, connector key */
static unsigned char *g_frame;
static unsigned int g_declared;
static int g_ret;
static wifi_device_dpp_context_t *g_ctx_arg;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_dpp_reconfig_data_t *rd = &g_ctx.session_data.u.reconfig_data;
	size_t from = ((size_t)g_ctx.dpp_init_retries + 1 + 7) & ~(size_t)7;
	size_t ulen = sizeof(g_ctx.session_data.u);

	fn(g_inst.k1, sizeof(g_inst.k1)); fn(g_inst.k2, sizeof(g_inst.k2)); fn(g_inst.rauth, sizeof(g_inst.rauth));
	fn(g_inst.iauth, sizeof(g_inst.iauth)); fn(g_inst.enrollee_nonce, sizeof(g_inst.enrollee_nonce));
	fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(rd->iPubKey, sizeof(rd->iPubKey));
	fn((char *)&g_ctx.session_data.u + ((sizeof(*rd) + 7) & ~(size_t)7), ulen - ((sizeof(*rd) + 7) & ~(size_t)7));
	if (from < sizeof(rd->tran_id)) fn(&rd->tran_id[from], sizeof(rd->tran_id) - from);
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static std::string b64u(const unsigned char *d, int n)
{
	std::vector<unsigned char> o(4 * n / 3 + 8);
	int k = EVP_EncodeBlock(o.data(), d, n);
	std::string s((char *)o.data(), k);
	for (size_t i = 0; i < s.size(); i++) { if (s[i] == '+') s[i] = '-'; else if (s[i] == '/') s[i] = '_'; }
	while (!s.empty() && s.back() == '=') s.pop_back();
	return s;
}

static void coords(EC_KEY *k, unsigned char *x, unsigned char *y)
{
	BIGNUM *bx = BN_new(), *by = BN_new();
	EC_POINT_get_affine_coordinates_GFp(g_group, EC_KEY_get0_public_key(k), bx, by, g_bn);
	BN_bn2binpad(bx, x, 32); BN_bn2binpad(by, y, 32);
	BN_free(bx); BN_free(by);
}

static void put_tlv(std::vector<unsigned char> &v, unsigned short type, unsigned short declared, const void *data, size_t actual)
{
	size_t o = v.size();
	v.resize(o + 4 + actual);
	memcpy(&v[o], &type, 2); memcpy(&v[o + 2], &declared, 2);
	if (actual) memcpy(&v[o + 4], data, actual);
}

static std::string conn_string(int mode, const unsigned char *cx, const unsigned char *cy)
{
	std::string x = b64u(cx, 32), y = b64u(cy, 32), body;
	unsigned char big[400];
	for (int i = 0; i < (int)sizeof(big); i++) big[i] = (unsigned char)(i * 7 + 3);
	const std::string pre = "eyJ0eXAiOiJkcHBDb24ifQ.", post = ".c2lnbmF0dXJl";

	switch (mode) {
	case 2: return "headerbodysignature";
	case 4: return "h.!!!!.s";
	case 5: body = b64u((const unsigned char *)"notjson", 7); return pre + body + post;
	case 6: body = "{\"foo\":1}"; break;
	case 7: body = "{\"netAccessKey\":{\"y\":\"" + y + "\"}}"; break;
	case 8: body = "{\"netAccessKey\":{\"x\":\"" + x + "\"}}"; break;
	case 9: body = "{\"netAccessKey\":{\"x\":\"***\",\"y\":\"" + y + "\"}}"; break;
	case 10: return std::string(1024, 'A');
	case 12: body = "{\"netAccessKey\":{\"x\":\"" + b64u(big, 65) + "\",\"y\":\"" + y + "\"}}"; break;
	case 13: body = "{\"netAccessKey\":{\"x\":\"" + x + "\",\"y\":\"" + b64u(big, 200) + "\"}}"; break;
	case 16: body = "{\"netAccessKey\":{\"x\":1,\"y\":2}}"; break;
	default: body = "{\"netAccessKey\":{\"x\":\"" + x + "\",\"y\":\"" + y + "\"}}"; break;
	}
	return pre + b64u((const unsigned char *)body.data(), (int)body.size()) + post;
}

/* builds the real context + frame for the case */
static void setup(const hwr_wra_case_t *t)
{
	memset(&g_ctx, 0, sizeof(g_ctx)); memset(&g_inst, 0, sizeof(g_inst)); memset(&g_recfg, 0, sizeof(g_recfg));
	g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	g_bn = BN_CTX_new();
	g_rk = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_rk);
	g_pk = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_pk);
	g_ck = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_ck);

	g_inst.group = g_group; g_inst.hashfcn = EVP_sha256(); g_inst.digestlen = 32; g_inst.noncelen = 16; g_inst.nid = NID_X9_62_prime256v1;
	g_inst.bnctx = g_bn; g_inst.prime = BN_new();
	EC_GROUP_get_curve_GFp(g_group, g_inst.prime, NULL, NULL, g_bn);
	g_inst.x = BN_new(); g_inst.y = BN_new(); g_inst.m = BN_new(); g_inst.n = BN_new(); g_inst.l = BN_new();
	g_inst.M = EC_POINT_new(g_group); g_inst.N = EC_POINT_new(g_group);
	g_inst.responder_proto_pt = EC_POINT_new(g_group); g_inst.responder_connector = EC_POINT_new(g_group);
	for (int i = 0; i < (int)sizeof(g_inst.initiator_nonce); i++) g_inst.initiator_nonce[i] = (unsigned char)(0xA0 + i);
	if (t->nul == 4) { BN_free(g_inst.x); g_inst.x = NULL; }
	if (t->nul == 5) { BN_free(g_inst.y); g_inst.y = NULL; }
	g_recfg.key = g_rk;

	g_ctx.session_data.session = wifi_dpp_session_type_reconfig;
	g_ctx.session_data.instance = (t->nul == 3) ? NULL : &g_inst;
	g_ctx.config.reconfigCtx = (t->nul == 2) ? NULL : &g_recfg;
	g_ctx.dpp_init_retries = t->retries;
	g_ctx.enrollee_status = RESPONDER_STATUS_OK;
	for (int k = 0; k <= t->retries; k++) g_ctx.session_data.u.reconfig_data.tran_id[k] = TBL(k);

	/* the key the function derives, computed on a reference instance */
	unsigned char px[32], py[32], cx[32], cy[32];
	coords(g_pk, px, py); coords(g_ck, cx, cy);
	wifi_dpp_instance_t ref; memset(&ref, 0, sizeof(ref));
	ref.group = g_group; ref.bnctx = g_bn; ref.prime = g_inst.prime; ref.hashfcn = EVP_sha256(); ref.digestlen = 32; ref.noncelen = 16;
	memcpy(ref.initiator_nonce, g_inst.initiator_nonce, sizeof(ref.initiator_nonce));
	ref.M = EC_POINT_new(g_group); ref.m = BN_new(); ref.n = BN_new();
	EC_POINT *N = EC_POINT_new(g_group);
	EC_POINT_add(g_group, N, EC_KEY_get0_public_key(g_pk), EC_KEY_get0_public_key(g_ck), g_bn);
	EC_POINT_mul(g_group, ref.M, NULL, N, EC_KEY_get0_private_key(g_rk), g_bn);
	hwr_wra_compute_reconfig_encryption_key(&ref);

	/* the frame */
	std::vector<unsigned char> f(FRAME_HDR, 0);
	f[0] = 0x50; f[1] = 0x6F; f[2] = 0x9A; f[3] = 0x1A; f[4] = 1; f[5] = 16;
	unsigned char tid = (t->tran == 5) ? TBL(0) : (t->tran == 2) ? 0xEE : TBL(t->retries), two[2] = { tid, 0 };
	unsigned char verv = 2, vv2[2] = { 2, 0 };
	if (t->tran == 1 || t->tran == 2 || t->tran == 5) put_tlv(f, wifi_dpp_attrib_id_transaction_id, 1, &tid, 1);
	else if (t->tran == 3) put_tlv(f, wifi_dpp_attrib_id_transaction_id, 2, two, 2);
	if (t->ver == 1) put_tlv(f, wifi_dpp_attrib_id_proto_version, 1, &verv, 1);
	else if (t->ver == 2) put_tlv(f, wifi_dpp_attrib_id_proto_version, 2, vv2, 2);
	if (t->conn == 15) { put_tlv(f, wifi_dpp_attrib_id_connector, 900, "abcdefghij", 10); }
	else if (t->conn) { std::string c = conn_string(t->conn, cx, cy); put_tlv(f, wifi_dpp_attrib_id_connector, (unsigned short)c.size(), c.data(), c.size()); }
	if (t->key) {
		unsigned char kb[64]; memcpy(kb, px, 32); memcpy(kb + 32, py, 32);
		if (t->key == 4) { memset(kb, 0x11, 32); memset(kb + 32, 0x22, 32); }
		size_t kl = (t->key == 2) ? 32 : 64;
		put_tlv(f, wifi_dpp_attrib_id_responder_protocol_key, (unsigned short)kl, kb, kl);
	}
	if (t->wrap) {
		size_t non_wrapped = f.size() - FRAME_HDR;
		std::vector<unsigned char> plain; unsigned char rn[40], in[40], cap = 2;
		for (int i = 0; i < 40; i++) { rn[i] = (unsigned char)(0xB0 + i); in[i] = (unsigned char)(0xA0 + i); }
		if (t->in == 2) in[15] ^= 0xFF;
		if (t->wrap == 1 || t->wrap == 2) {
			static const int rnl[] = { 0, 16, 32, 33, 8, 0 }, inl[] = { 0, 16, 16, 8, 33, 0 };
			if (t->rn) put_tlv(plain, wifi_dpp_attrib_id_responder_nonce, rnl[t->rn], rn, rnl[t->rn]);
			if (t->rcap) put_tlv(plain, wifi_dpp_attrib_id_responder_cap, 1, &cap, 1);
			if (t->in) put_tlv(plain, wifi_dpp_attrib_id_initiator_nonce, inl[t->in], in, inl[t->in]);
		}
		if (t->wrap == 3) {
			unsigned char junk[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
			put_tlv(f, wifi_dpp_attrib_id_wrapped_data, 8, junk, 8);
		} else if (t->wrap == 4) {
			unsigned char junk[20]; memset(junk, 0x33, sizeof(junk));
			put_tlv(f, wifi_dpp_attrib_id_wrapped_data, 200, junk, sizeof(junk));
		} else {
			size_t wl = plain.size();
			f.resize(f.size() + 4 + 16 + wl);
			wifi_tlv_t *w = (wifi_tlv_t *)&f[FRAME_HDR + non_wrapped];
			w->type = wifi_dpp_attrib_id_wrapped_data; w->length = (unsigned short)(wl + 16);
			siv_ctx sc; siv_init(&sc, ref.ke, SIV_256);
			wifi_dppPublicActionFrameBody_t *body = (wifi_dppPublicActionFrameBody_t *)f.data();
			siv_encrypt(&sc, plain.data(), &w->value[16], (int)wl, w->value, 2, body, FRAME_HDR, body->attrib, (int)non_wrapped);
			if (t->wrap == 2) w->value[16 + 3] ^= 0x01;
		}
	}
	g_declared = (t->flen >= 0) ? (unsigned int)t->flen : (unsigned int)f.size();
	size_t alloc = g_declared ? g_declared : 1;
	g_frame = (unsigned char *)malloc(alloc);
	memcpy(g_frame, f.data(), alloc < f.size() ? alloc : f.size());
	g_ctx.received_frame.frame = (t->nul == 6) ? NULL : g_frame;
	g_ctx.received_frame.length = g_declared;
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;

	EC_POINT_free(N); EC_POINT_free(ref.M); BN_free(ref.m); BN_free(ref.n);
}

static void cleanup(void)
{
	free(g_frame); g_frame = NULL;
	BN_free(g_inst.x); BN_free(g_inst.y); BN_free(g_inst.m); BN_free(g_inst.n); BN_free(g_inst.l); BN_free(g_inst.prime);
	EC_POINT_free(g_inst.M); EC_POINT_free(g_inst.N); EC_POINT_free(g_inst.responder_proto_pt); EC_POINT_free(g_inst.responder_connector);
	EC_KEY_free(g_rk); EC_KEY_free(g_pk); EC_KEY_free(g_ck);
	BN_CTX_free(g_bn); EC_GROUP_free(g_group);
}

/* poison, call, unpoison */
static void test_sg_wifi_dppProcessReconfigAuthResponse(const hwr_wra_case_t *t)
{
	(void)t;
	if (g_ctx_arg) poison(1);
	g_ret = hwr_sg_wifi_dppProcessReconfigAuthResponse(g_ctx_arg);
	if (g_ctx_arg) poison(0);
}

/* reference model of the CORRECT behaviour: returns the expected result and sets *status (0 unchanged, 1 AUTH_FAILURE) */
static int model(const hwr_wra_case_t *t, int *status)
{
	*status = 0;
	if (t->nul) return RETURN_ERR;
	if (t->flen >= 0) return RETURN_ERR;
	if (t->tran != 1 && t->tran != 5) return RETURN_ERR;
	if (t->ver != 1) return RETURN_ERR;
	if (t->conn != 1) return RETURN_ERR;
	*status = 1;
	if (t->key != 1) return RETURN_ERR;
	if (t->wrap != 1) return RETURN_ERR;
	if (t->rn != 1) return RETURN_ERR;
	if (t->in != 1) return RETURN_ERR;
	*status = 0;
	return RETURN_OK;
}

static int check(const hwr_wra_case_t *t)
{
	int st, want = model(t, &st);

	if (g_ret != want) { snprintf(why, sizeof(why), "returned %d, expected %d", g_ret, want); return 0; }
	if (!t->nul || t->nul == 6 || t->nul == 3 || t->nul == 4 || t->nul == 5) {
		int got = (g_ctx.enrollee_status == RESPONDER_STATUS_AUTH_FAILURE);
		if (got != st) { snprintf(why, sizeof(why), "enrollee_status %d, expected %s", (int)g_ctx.enrollee_status, st ? "AUTH_FAILURE" : "untouched (OK)"); return 0; }
	}
	if (want == RETURN_OK) {
		unsigned char exp_tran = (t->tran == 5) ? TBL(0) : TBL(t->retries);
		if (g_ctx.enrollee_version != 2) { snprintf(why, sizeof(why), "enrollee_version %d, expected 2", g_ctx.enrollee_version); return 0; }
		if (g_ctx.session_data.u.reconfig_data.match_tran_id != exp_tran) { snprintf(why, sizeof(why), "match_tran_id 0x%x, expected 0x%x", g_ctx.session_data.u.reconfig_data.match_tran_id, exp_tran); return 0; }
		for (int i = 0; i < 16; i++) if (g_inst.responder_nonce[i] != (unsigned char)(0xB0 + i)) { snprintf(why, sizeof(why), "responder nonce not copied"); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppProcessReconfigAuthResponse(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppProcessReconfigAuthResponse_suite[i].test_name != NULL; i++) {
			hwr_wra_case_t *test = &sg_wifi_dppProcessReconfigAuthResponse_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppProcessReconfigAuthResponse(test);

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
	printf("\nwifi_dppProcessReconfigAuthResponse: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
