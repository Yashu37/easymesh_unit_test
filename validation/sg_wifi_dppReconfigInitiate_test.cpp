/*
 * TEST RUNNER: sg_wifi_dppReconfigInitiate_test
 *
 * test_sg_wifi_dppReconfigInitiate() POISONS what the function must not touch, calls the handler and unpoisons: the context's config object (discovery, credentials union), channels_list, received_frame, the
 * unused tail of the session union, match_tran_id and every tran_id entry except the one at dpp_init_retries, the reconfig context's bnctx / prime / key / pt / crv members, the signing instance's bnctx / prime /
 * pt / bn pointers, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The context is a heap block of exactly sizeof(wifi_device_dpp_context_t) so ASan sees a write behind it.  setup() builds real
 * P-256 keys, the base64 SubjectPublicKeyInfo of the initiator bootstrap key, the configurator signing instance and the reconfig context; the mock wifi_sendActionFrame captures the frame; run_all_tests decodes
 * every attribute (connector header / body / signature included) and compares the result with a reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "hwr_wrz.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static wifi_device_dpp_context_t *g_ctx;
static wifi_device_dpp_context_t *g_ctx_arg;
static wifi_dpp_csign_instance_t g_sign;
static wifi_dpp_reconfig_instance_t *g_recfg;
static EC_GROUP *g_group;
static EC_KEY *g_rk, *g_ik;
static BN_CTX *g_bn;
static std::string g_kid;
static int g_ret, g_retries;
static unsigned char g_sta[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_dpp_reconfig_data_t *rd = &g_ctx->session_data.u.reconfig_data;

	fn(g_ctx->config.discovery, sizeof(g_ctx->config.discovery)); fn(&g_ctx->config.credentials.creds, sizeof(g_ctx->config.credentials.creds));
	fn(g_ctx->channels_list, sizeof(g_ctx->channels_list)); fn(&g_ctx->received_frame, sizeof(g_ctx->received_frame));
	fn((unsigned char *)rd + sizeof(*rd), sizeof(g_ctx->session_data.u) - sizeof(*rd));
	fn(&rd->match_tran_id, 1);
	if (g_retries >= 0 && g_retries < 120) {
		if (g_retries > 0) fn(rd->tran_id, g_retries);
		if (g_retries < 119) fn(&rd->tran_id[g_retries + 1], 119 - g_retries);
	}
	fn(&g_recfg->bnctx, sizeof(void *)); fn(&g_recfg->prime, sizeof(void *)); fn(&g_recfg->key, sizeof(void *)); fn(&g_recfg->pt, sizeof(void *)); fn(g_recfg->crv, sizeof(g_recfg->crv));
	fn(&g_sign.bnctx, sizeof(void *)); fn(&g_sign.prime, sizeof(void *)); fn(&g_sign.pt, sizeof(void *)); fn(&g_sign.bn, sizeof(void *));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static std::string spki_b64(EC_KEY *k)
{
	unsigned char *p = NULL; int n = i2d_EC_PUBKEY(k, &p);
	std::vector<unsigned char> o(4 * n / 3 + 8);
	int m = EVP_EncodeBlock(o.data(), p, n);
	OPENSSL_free(p);
	return std::string((char *)o.data(), m);
}

static std::string b64u_enc(const unsigned char *d, int n)
{
	std::vector<unsigned char> o(4 * n / 3 + 8);
	int m = EVP_EncodeBlock(o.data(), d, n);
	std::string s((char *)o.data(), m);
	for (auto &c : s) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
	while (!s.empty() && s.back() == '=') s.pop_back();
	return s;
}

static std::string b64u_dec(std::string s, int &ok)
{
	for (auto &c : s) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
	size_t pad = (4 - s.size() % 4) % 4; s.append(pad, '=');
	std::vector<unsigned char> o(s.size() + 4);
	int m = EVP_DecodeBlock(o.data(), (const unsigned char *)s.data(), s.size());
	ok = (m >= 0);
	if (m < 0) return "";
	m -= (int)pad;
	return std::string((char *)o.data(), m);
}

static void setup(const hwr_wrz_case_t *t)
{
	static const int nids[] = { NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1 };
	g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	g_bn = BN_CTX_new();
	g_rk = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_rk);
	g_ik = EC_KEY_new_by_curve_name(nids[t->curve]); EC_KEY_generate_key(g_ik);

	g_ctx = (wifi_device_dpp_context_t *)calloc(1, sizeof(*g_ctx));
	memset(&g_sign, 0, sizeof(g_sign));
	g_kid = t->kid ? std::string("0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ").substr(0, 63) : std::string("kid-0123456789");
	g_sign.key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_sign.key);
	g_sign.group = g_group; g_sign.x = BN_new(); g_sign.y = BN_new();
	EC_POINT_get_affine_coordinates_GFp(g_group, EC_KEY_get0_public_key(g_sign.key), g_sign.x, g_sign.y, g_bn);
	strncpy((char *)g_sign.kid, g_kid.c_str(), sizeof(g_sign.kid) - 1);
	strcpy(g_sign.alg, "ES256");
	g_recfg = (wifi_dpp_reconfig_instance_t *)calloc(1, sizeof(*g_recfg));
	g_recfg->x = BN_new(); g_recfg->y = BN_new();
	EC_POINT_get_affine_coordinates_GFp(g_group, EC_KEY_get0_public_key(g_rk), g_recfg->x, g_recfg->y, g_bn);

	g_ctx->ap_index = t->ap;
	g_ctx->configurator_version = (unsigned char)t->ver;
	g_ctx->activation_status = ActStatus_Idle;
	g_ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
	g_ctx->config.reconfigCtx = (t->csign == 2) ? NULL : (void *)g_recfg;
	g_ctx->config.cSignInstance = (t->csign == 1) ? NULL : (void *)&g_sign;
	g_ctx->session_data.session = wifi_dpp_session_type_reconfig;
	g_ctx->session_data.instance = NULL;
	memcpy(g_ctx->session_data.sta_mac, g_sta, 6);
	g_ctx->session_data.channel = t->channel;
	{
		unsigned char *ik = (unsigned char *)g_ctx->session_data.u.reconfig_data.iPubKey;
		std::string s = (t->ipub == 0) ? spki_b64(g_ik) : (t->ipub == 1) ? std::string("!!!!!!!!") : (t->ipub == 3) ? std::string("") : std::string("MAMBAgMA");
		strncpy((char *)ik, s.c_str(), 511);
	}
	if (t->retries < 0)
		g_retries = (int)(sizeof(*g_ctx) - ((unsigned char *)&g_ctx->session_data.u.reconfig_data.tran_id[0] - (unsigned char *)g_ctx));
	else g_retries = t->retries;
	g_ctx->dpp_init_retries = g_retries;
	memset(&hwr_wrz_cap, 0, sizeof(hwr_wrz_cap));
	g_ctx_arg = (t->nul == 1) ? NULL : g_ctx;
}

static void cleanup(const hwr_wrz_case_t *t)
{
	wifi_dpp_instance_t *in = (wifi_dpp_instance_t *)g_ctx->session_data.instance;
	if (in) {
		if (t->ipub == 0) {
			EC_POINT_free(in->N); EC_POINT_free(in->M); EC_POINT_clear_free(in->responder_proto_pt); EC_POINT_free(in->responder_connector);
			EC_KEY_free(in->initiator_proto_key); BN_CTX_free(in->bnctx); BN_free(in->prime); BN_free(in->n); BN_free(in->m); BN_free(in->y); BN_free(in->x);
		}
		free(in);   /* a failed create leaves a partly initialised block: only the block itself is released */
	}
	free(g_ctx); g_ctx = NULL;
	BN_free(g_recfg->x); BN_free(g_recfg->y); free(g_recfg);
	EC_KEY_free(g_sign.key); BN_free(g_sign.x); BN_free(g_sign.y);
	EC_KEY_free(g_rk); EC_KEY_free(g_ik); BN_CTX_free(g_bn); EC_GROUP_free(g_group);
}

/* poison, call, unpoison */
static void test_sg_wifi_dppReconfigInitiate(const hwr_wrz_case_t *t)
{
	(void)t;
	poison(1);
	g_ret = hwr_sg_wifi_dppReconfigInitiate(g_ctx_arg);
	poison(0);
}

#define FAIL(...) do { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } while (0)

static int check_frame(const hwr_wrz_case_t *t)
{
	const hwr_wrz_cap_t *c = &hwr_wrz_cap;
	const unsigned int H = sizeof(wifi_dppPublicActionFrame_t);
	wifi_dpp_instance_t *in = (wifi_dpp_instance_t *)g_ctx->session_data.instance;
	static const int nl[] = { 16, 24, 32 };
	if (c->calls != 1) FAIL("wifi_sendActionFrame called %d times", c->calls);
	if (c->ap != t->ap) FAIL("ap_index %d, expected %d", c->ap, t->ap);
	if (memcmp(c->sta, g_sta, 6) != 0) FAIL("sta mac differs");
	unsigned want_f = hwr_wrz_channel_to_frequency(t->channel);
	if (c->freq != want_f) FAIL("frequency %u, expected %u", c->freq, want_f);
	if (c->len < H || c->len > sizeof(c->frame)) FAIL("frame length %u", c->len);
	const wifi_dppPublicActionFrame_t *f = (const wifi_dppPublicActionFrame_t *)c->frame;
	if (f->public_action_hdr.cat != 4 || f->public_action_hdr.action != 9) FAIL("public action header");
	if (f->public_action_body.dpp_oui.oui[0] != 0x50 || f->public_action_body.dpp_oui.oui[1] != 0x6f || f->public_action_body.dpp_oui.oui[2] != 0x9a || f->public_action_body.dpp_oui.oui_type != 0x1a) FAIL("DPP OUI");
	if (f->public_action_body.crypto != 1 || f->public_action_body.frame_type != wifi_dpp_public_action_frame_type_recfg_auth_req) FAIL("crypto / frame type");
	if (in == NULL) FAIL("no session instance");
	if (in->noncelen != nl[t->curve]) FAIL("noncelen %d", in->noncelen);
	const unsigned char *a = f->public_action_body.attrib; unsigned int off = 0, end = c->len - H;
	wifi_tlv_t h;
	if (off + 4 > end) FAIL("frame ends before the transaction id");
	memcpy(&h, a + off, 4);
	if (h.type != wifi_dpp_attrib_id_transaction_id || h.length != 1 || off + 5 > end) FAIL("transaction id attribute");
	if (a[off + 4] != g_ctx->session_data.u.reconfig_data.tran_id[g_retries]) FAIL("transaction id %u != tran_id[%d] %u", a[off + 4], g_retries, g_ctx->session_data.u.reconfig_data.tran_id[g_retries]);
	off += 5;
	if (off + 4 > end) FAIL("frame ends before the protocol version");
	memcpy(&h, a + off, 4);
	if (h.type != wifi_dpp_attrib_id_proto_version || h.length != 1 || off + 5 > end || a[off + 4] != t->ver) FAIL("protocol version attribute");
	off += 5;
	if (off + 4 > end) FAIL("frame ends before the connector");
	memcpy(&h, a + off, 4);
	if (h.type != wifi_dpp_attrib_id_connector || off + 4 + h.length > end) FAIL("connector attribute");
	std::string con((const char *)a + off + 4, h.length);
	off += 4 + h.length;
	size_t d1 = con.find('.'), d2 = (d1 == std::string::npos) ? d1 : con.find('.', d1 + 1);
	if (d2 == std::string::npos || con.find('.', d2 + 1) != std::string::npos) FAIL("connector is not header.body.signature");
	int ok1, ok2, ok3;
	std::string hj = b64u_dec(con.substr(0, d1), ok1), bj = b64u_dec(con.substr(d1 + 1, d2 - d1 - 1), ok2), sg = b64u_dec(con.substr(d2 + 1), ok3);
	if (!ok1 || !ok2 || !ok3) FAIL("connector part is not base64url");
	cJSON *jh = cJSON_Parse(hj.c_str()), *jb = cJSON_Parse(bj.c_str());
	int r = 1;
	if (!jh || !jb) { snprintf(why, sizeof(why), "connector header / body is not json"); r = 0; }
	else {
		cJSON *typ = cJSON_GetObjectItem(jh, "typ"), *kid = cJSON_GetObjectItem(jh, "kid"), *alg = cJSON_GetObjectItem(jh, "alg");
		cJSON *nak = cJSON_GetObjectItem(jb, "netAccessKey");
		if (!cJSON_IsString(typ) || strcmp(typ->valuestring, "dppCon") || !cJSON_IsString(kid) || g_kid != kid->valuestring || !cJSON_IsString(alg) || strcmp(alg->valuestring, "ES256")) { snprintf(why, sizeof(why), "connector header fields"); r = 0; }
		else if (!nak) { snprintf(why, sizeof(why), "connector without netAccessKey"); r = 0; }
		else if (t->curve == 0) {
			unsigned char bx[32] = { 0 }, by[32] = { 0 };
			BN_bn2binpad(g_recfg->x, bx, 32); BN_bn2binpad(g_recfg->y, by, 32);
			cJSON *x = cJSON_GetObjectItem(nak, "x"), *y = cJSON_GetObjectItem(nak, "y");
			if (!cJSON_IsString(x) || b64u_enc(bx, 32) != x->valuestring || !cJSON_IsString(y) || b64u_enc(by, 32) != y->valuestring) { snprintf(why, sizeof(why), "connector netAccessKey x / y differ"); r = 0; }
			else if (sg.size() != 64) { snprintf(why, sizeof(why), "connector signature length %zu", sg.size()); r = 0; }
		}
	}
	cJSON_Delete(jh); cJSON_Delete(jb);
	if (!r) return 0;
	if (off + 4 > end) FAIL("frame ends before the initiator nonce");
	memcpy(&h, a + off, 4);
	if (h.type != wifi_dpp_attrib_id_initiator_nonce || h.length != (unsigned)in->noncelen || off + 4 + h.length > end) FAIL("initiator nonce attribute");
	if (memcmp(a + off + 4, in->initiator_nonce, in->noncelen)) FAIL("initiator nonce differs from the instance's nonce");
	off += 4 + h.length;
	if (off != end) FAIL("frame length %u, attributes end at %u", end, off);
	return 1;
}

static int check(const hwr_wrz_case_t *t)
{
	int ch = (t->channel >= 1 && t->channel <= 14) || (t->channel >= 36 && t->channel <= 64) || (t->channel >= 100 && t->channel <= 140) || (t->channel >= 149 && t->channel <= 165);
	int ok = (t->nul == 0 && t->ipub == 0 && t->csign == 0 && ch && g_retries >= 0 && g_retries < 120);

	if (g_ret != (ok ? RETURN_OK : RETURN_ERR)) FAIL("returned %d, expected %d", g_ret, ok ? RETURN_OK : RETURN_ERR);
	if (ok) { if (!check_frame(t)) return 0; }
	else if (hwr_wrz_cap.calls != 0) FAIL("a frame was sent for a failed call");
	if (t->nul == 0 && t->ipub == 0 && g_ctx->session_data.u.reconfig_data.iPubKey[0] != 'M' && g_ctx->session_data.u.reconfig_data.iPubKey[0] != '\0')
		; /* (a valid SPKI base64 always starts with 'M': see the next check) */
	if (t->nul == 0 && t->ipub == 0 && g_ctx->session_data.u.reconfig_data.iPubKey[0] != 'M') FAIL("iPubKey[0] was overwritten (tran_id[%d] write)", g_retries);
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) FAIL("guard byte %d modified", g);
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppReconfigInitiate(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppReconfigInitiate_suite[i].test_name != NULL; i++) {
			hwr_wrz_case_t *test = &sg_wifi_dppReconfigInitiate_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppReconfigInitiate(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
			cleanup(test);
		}
	printf("\nwifi_dppReconfigInitiate: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
