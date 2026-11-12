/*
 * TEST RUNNER: sg_wifi_dppSendConfigResponse_test
 *
 * test_sg_wifi_dppSendConfigResponse() POISONS what the function must not touch, calls the handler and unpoisons: the instance's k1 / k2 / rauth / iauth / responder_nonce / initiator_nonce arrays and its
 * M / N / m / n / l / initiator_proto_key / responder_connector pointers, the reconfig context (the whole heap block: only its pointer is checked), the csign instance's bnctx / prime / pt / bn pointers, the
 * context's channels_list, received_frame and session union, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  setup() builds a real P-256 session (responder protocol point, configurator
 * signing key, kid, ke, enrollee nonce, configuration object).  The mock wifi_sendActionFrame captures the frame; run_all_tests decrypts it with the same AES-SIV key (AAD = the status TLV), parses the
 * JSON configuration object and compares everything with a reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "hwr_wsc.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t g_inst;
static wifi_dpp_csign_instance_t g_sign;
static wifi_dpp_reconfig_instance_t *g_recfg;
static EC_GROUP *g_group;
static BN_CTX *g_bn;
static EC_KEY *g_rk;                                  /* responder protocol key (point only) */
static int g_ret;
static wifi_device_dpp_context_t *g_ctx_arg;
static std::string g_ssid, g_pass, g_kid;
static unsigned char g_sta[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(g_inst.k1, sizeof(g_inst.k1)); fn(g_inst.k2, sizeof(g_inst.k2)); fn(g_inst.rauth, sizeof(g_inst.rauth)); fn(g_inst.iauth, sizeof(g_inst.iauth));
	fn(g_inst.responder_nonce, sizeof(g_inst.responder_nonce)); fn(g_inst.initiator_nonce, sizeof(g_inst.initiator_nonce));
	fn(&g_inst.M, 2 * sizeof(void *)); fn(&g_inst.m, 3 * sizeof(void *)); fn(&g_inst.initiator_proto_key, sizeof(void *)); fn(&g_inst.responder_connector, sizeof(void *));
	if (g_recfg) fn(g_recfg, sizeof(*g_recfg));
	fn(&g_sign.bnctx, sizeof(void *)); fn(&g_sign.prime, sizeof(void *)); fn(&g_sign.pt, sizeof(void *)); fn(&g_sign.bn, sizeof(void *));
	fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(&g_ctx.received_frame, sizeof(g_ctx.received_frame));
	fn(&g_ctx.session_data.u, sizeof(g_ctx.session_data.u));
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

static std::string b64u_dec(std::string s)
{
	for (size_t i = 0; i < s.size(); i++) { if (s[i] == '-') s[i] = '+'; else if (s[i] == '_') s[i] = '/'; }
	size_t pad = (4 - s.size() % 4) % 4; s.append(pad, '=');
	std::vector<unsigned char> o(s.size() + 4);
	int k = EVP_DecodeBlock(o.data(), (const unsigned char *)s.data(), (int)s.size());
	if (k < 0) return "";
	return std::string((char *)o.data(), k - pad);
}

static void bn32(BIGNUM *b, unsigned char *out) { BN_bn2binpad(b, out, 32); }

static void setup(const hwr_wsc_case_t *t)
{
	g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	g_bn = BN_CTX_new();
	g_rk = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_rk);

	memset(&g_ctx, 0, sizeof(g_ctx)); memset(&g_inst, 0, sizeof(g_inst)); memset(&g_sign, 0, sizeof(g_sign));
	g_inst.group = g_group; g_inst.digestlen = t->digest; g_inst.noncelen = t->noncelen; g_inst.nid = NID_X9_62_prime256v1; g_inst.bnctx = g_bn;
	g_inst.hashfcn = EVP_sha256();
	g_inst.prime = BN_new(); EC_GROUP_get_curve_GFp(g_group, g_inst.prime, NULL, NULL, g_bn);
	g_inst.x = BN_new(); g_inst.y = BN_new();
	g_inst.responder_proto_pt = EC_POINT_dup(EC_KEY_get0_public_key(g_rk), g_group);
	for (int i = 0; i < 64; i++) g_inst.ke[i] = (unsigned char)(0x40 + i);
	for (int i = 0; i < 32; i++) g_inst.enrollee_nonce[i] = (unsigned char)(0xE0 + i);

	/* configurator signing instance */
	g_kid = t->kid ? std::string("0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ").substr(0, 63) : std::string("kid-0123456789");
	g_sign.key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_sign.key);
	g_sign.group = g_group; g_sign.x = BN_new(); g_sign.y = BN_new();
	EC_POINT_get_affine_coordinates_GFp(g_group, EC_KEY_get0_public_key(g_sign.key), g_sign.x, g_sign.y, g_bn);
	strncpy((char *)g_sign.kid, g_kid.c_str(), sizeof(g_sign.kid) - 1);
	strcpy(g_sign.alg, "ES256");
	g_recfg = (wifi_dpp_reconfig_instance_t *)calloc(1, sizeof(*g_recfg));

	static const char *ssids[] = { "", "MyHomeNetwork", "abcdefghijklmnopqrstuvwxyzABCDE", "abcdefghijklmnopqrstuvwxyzABCDEF" };
	g_ssid = ssids[t->ssid];
	g_pass = t->pass == 0 ? "" : t->pass == 1 ? "Passw0rd-12345" : std::string("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/-_=.").substr(0, 63);

	g_ctx.ap_index = t->ap; g_ctx.token = (unsigned char)t->token; g_ctx.enrollee_version = (unsigned char)t->ver;
	g_ctx.activation_status = ActStatus_Idle;
	g_ctx.config.wifiTech = WIFI_DPP_TECH_INFRA;
	memcpy(g_ctx.config.discovery, g_ssid.data(), g_ssid.size() > 32 ? 32 : g_ssid.size());
	g_ctx.config.credentials.keyManagement = (wifi_dpp_key_management_t)t->keymgmt;
	strncpy(g_ctx.config.credentials.creds.passPhrase, g_pass.c_str(), 63);
	g_ctx.config.reconfigCtx = t->csign ? (void *)g_recfg : NULL;
	g_ctx.config.cSignInstance = t->csign ? (void *)&g_sign : NULL;
	g_ctx.session_data.instance = (t->nul == 2) ? NULL : &g_inst;
	memcpy(g_ctx.session_data.sta_mac, g_sta, 6);
	g_ctx.session_data.channel = t->freq;
	memset(&hwr_wsc_cap, 0, sizeof(hwr_wsc_cap));
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;
}

static void cleanup(void)
{
	BN_free(g_inst.prime); BN_free(g_inst.x); BN_free(g_inst.y); EC_POINT_free(g_inst.responder_proto_pt);
	EC_KEY_free(g_sign.key); BN_free(g_sign.x); BN_free(g_sign.y);
	free(g_recfg); g_recfg = NULL;
	EC_KEY_free(g_rk); BN_CTX_free(g_bn); EC_GROUP_free(g_group);
}

/* poison, call, unpoison */
static void test_sg_wifi_dppSendConfigResponse(const hwr_wsc_case_t *t)
{
	(void)t;
	if (g_ctx_arg) poison(1);
	g_ret = hwr_sg_wifi_dppSendConfigResponse(g_ctx_arg);
	if (g_ctx_arg) poison(0);
}

static const char *js(cJSON *o, const char *k) { cJSON *i = cJSON_GetObjectItem(o, k); return (i && cJSON_IsString(i)) ? i->valuestring : NULL; }

#define FAIL(...) do { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } while (0)

static int check_frame(const hwr_wsc_case_t *t)
{
	const hwr_wsc_cap_t *c = &hwr_wsc_cap;
	const unsigned int H = sizeof(wifi_dppConfigResponseFrame_t);
	if (c->calls != 1) FAIL("wifi_sendActionFrame called %d times", c->calls);
	if (c->ap != t->ap) FAIL("ap_index %d, expected %d", c->ap, t->ap);
	if (memcmp(c->sta, g_sta, 6) != 0) FAIL("sta mac differs");
	if (c->freq != (unsigned)t->freq) FAIL("frequency %u, expected %d", c->freq, t->freq);
	if (c->len < H + 9 || c->len > sizeof(c->frame)) FAIL("frame length %u", c->len);
	const wifi_dppConfigResponseFrame_t *f = (const wifi_dppConfigResponseFrame_t *)c->frame;
	if (f->public_action_hdr.cat != 4 || f->public_action_hdr.action != 0x0b) FAIL("public action header");
	if (f->gas_resp_body.token != (unsigned char)t->token) FAIL("token %u", f->gas_resp_body.token);
	if (f->gas_resp_body.status != 0 || f->gas_resp_body.comeback_delay != 0) FAIL("gas status / comeback delay");
	if (f->gas_resp_body.proto_elem.id != 0x6c || f->gas_resp_body.proto_elem.len != 8 || f->gas_resp_body.proto_elem.proto_tuple.query_rsp_info != 0x7f ||
	    f->gas_resp_body.proto_elem.proto_tuple.adv_proto_id != 221 || f->gas_resp_body.proto_elem.proto_tuple.len != 5) FAIL("advertisement protocol element");
	if (f->dpp_oui.oui[0] != 0x50 || f->dpp_oui.oui[1] != 0x6f || f->dpp_oui.oui[2] != 0x9a || f->dpp_oui.oui_type != 0x1a || f->dpp_proto != 1) FAIL("DPP OUI / protocol");
	if (f->rsp_len != c->len - H) FAIL("rsp_len %u, frame carries %u", f->rsp_len, c->len - H);
	const unsigned char *b = f->rsp_body;
	wifi_tlv_t st; memcpy(&st, b, 4);
	if (st.type != wifi_dpp_attrib_id_status || st.length != 1 || b[4] != 0) FAIL("status TLV");
	wifi_tlv_t w; memcpy(&w, b + 5, 4);
	if (w.type != wifi_dpp_attrib_id_wrapped_data || w.length < 16 || 9u + w.length != f->rsp_len) FAIL("wrapped data TLV type 0x%x length %u (rsp_len %u)", w.type, w.length, f->rsp_len);
	const unsigned char *wv = b + 9;
	int P = w.length - 16;
	std::vector<unsigned char> plain(P + 1);
	siv_ctx sc; siv_init(&sc, g_inst.ke, t->digest == 48 ? SIV_384 : t->digest == 64 ? SIV_512 : SIV_256);
	int pl = siv_decrypt(&sc, wv + 16, plain.data(), P, (unsigned char *)wv, 1, b, 5);
	if (pl < 1) FAIL("wrapped data does not decrypt (AAD = status TLV)");     /* siv_decrypt returns 1 on success */
	wifi_tlv_t n; if (P < 4) FAIL("plaintext too short"); memcpy(&n, plain.data(), 4);
	if (n.type != wifi_dpp_attrib_id_enrollee_nonce || n.length != t->noncelen || P < 8 + t->noncelen) FAIL("enrollee nonce TLV");
	for (int i = 0; i < t->noncelen; i++) if (plain[4 + i] != (unsigned char)(0xE0 + i)) FAIL("enrollee nonce byte %d", i);
	wifi_tlv_t o; memcpy(&o, plain.data() + 4 + t->noncelen, 4);
	if (o.type != wifi_dpp_attrib_id_config_object || 8 + t->noncelen + o.length != P) FAIL("config object TLV type 0x%x length %u", o.type, o.length);
	std::string jtxt((char *)plain.data() + 8 + t->noncelen, o.length);
	cJSON *root = cJSON_Parse(jtxt.c_str());
	if (!root) FAIL("configuration object is not valid JSON");
	int ok = 0;
	{
		const char *tech = js(root, "wi-fi_tech");
		cJSON *disc = cJSON_GetObjectItem(root, "discovery"), *cred = cJSON_GetObjectItem(root, "cred");
		int km = (t->ver == 1) ? 0 : t->keymgmt;
		if (!tech || strcmp(tech, "infra")) { snprintf(why, sizeof(why), "wi-fi_tech missing"); goto done; }
		if (!disc || !cred) { snprintf(why, sizeof(why), "discovery / cred object missing"); goto done; }
		{ const char *ss = js(disc, "ssid");
		  if (t->ssid == 0) { if (ss) { snprintf(why, sizeof(why), "ssid present for an empty ssid"); goto done; } }
		  else if (!ss || g_ssid != ss) { snprintf(why, sizeof(why), "ssid has %d chars, expected %d (\"%s\")", ss ? (int)strlen(ss) : -1, (int)g_ssid.size(), ss ? ss : "(none)"); goto done; } }
		static const char *akm[] = { "psk", "dpp", "sae", "psk+sae", "dpp+psk+sae" };
		const char *a = js(cred, "akm");
		if (!a || strcmp(a, akm[km])) { snprintf(why, sizeof(why), "akm \"%s\", expected \"%s\"", a ? a : "(none)", akm[km]); goto done; }
		if (km == 0 || km == 3 || km == 4) { const char *p = js(cred, "pass"); if (!p || g_pass != p) { snprintf(why, sizeof(why), "pass \"%s\", expected \"%s\"", p ? p : "(none)", g_pass.c_str()); goto done; } }
		if (km == 4 && t->csign) {
			const char *sc2 = js(cred, "signedConnector"); cJSON *cs = cJSON_GetObjectItem(cred, "csign");
			if (!sc2 || !cs) { snprintf(why, sizeof(why), "signedConnector / csign missing"); goto done; }
			std::string con = sc2; size_t d1 = con.find('.'), d2 = con.find('.', d1 + 1);
			if (d1 == std::string::npos || d2 == std::string::npos) { snprintf(why, sizeof(why), "signedConnector has no 3 parts"); goto done; }
			cJSON *hdr = cJSON_Parse(b64u_dec(con.substr(0, d1)).c_str());
			cJSON *body = cJSON_Parse(b64u_dec(con.substr(d1 + 1, d2 - d1 - 1)).c_str());
			unsigned char px[32], py[32], cx[32], cy[32];
			BIGNUM *bx = BN_new(), *by = BN_new();
			EC_POINT_get_affine_coordinates_GFp(g_group, g_inst.responder_proto_pt, bx, by, g_bn); bn32(bx, px); bn32(by, py);
			BN_free(bx); BN_free(by); bn32(g_sign.x, cx); bn32(g_sign.y, cy);
			int g = 0;
			if (!hdr || !body) snprintf(why, sizeof(why), "connector header / body is not JSON");
			else if (!js(hdr, "kid") || g_kid != js(hdr, "kid")) snprintf(why, sizeof(why), "connector kid differs");
			else { cJSON *k = cJSON_GetObjectItem(body, "netAccessKey");
			  if (!k || !js(k, "x") || b64u(px, 32) != js(k, "x") || !js(k, "y") || b64u(py, 32) != js(k, "y")) snprintf(why, sizeof(why), "connector netAccessKey differs");
			  else if (!js(cs, "x") || b64u(cx, 32) != js(cs, "x") || !js(cs, "y") || b64u(cy, 32) != js(cs, "y") || !js(cs, "kid") || g_kid != js(cs, "kid")) snprintf(why, sizeof(why), "csign key object differs");
			  else g = 1; }
			cJSON_Delete(hdr); cJSON_Delete(body);
			if (!g) goto done;
		}
		ok = 1;
	}
done:
	cJSON_Delete(root);
	return ok;
}

static int check(const hwr_wsc_case_t *t)
{
	int want = (t->nul == 0 && (t->digest == 32 || t->digest == 48 || t->digest == 64)) ? RETURN_OK : RETURN_ERR;

	if (g_ret != want) FAIL("returned %d, expected %d", g_ret, want);
	if (want == RETURN_OK) {
		if (!check_frame(t)) return 0;
		if (g_ctx.activation_status != ActStatus_In_Progress) FAIL("activation_status %d", (int)g_ctx.activation_status);
	} else {
		if (hwr_wsc_cap.calls != 0) FAIL("a frame was sent for a failed call");
		if (t->nul == 0 && g_ctx.activation_status != ActStatus_Failed) FAIL("activation_status %d, expected ActStatus_Failed", (int)g_ctx.activation_status);
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) FAIL("guard byte %d modified", g);
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppSendConfigResponse(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppSendConfigResponse_suite[i].test_name != NULL; i++) {
			hwr_wsc_case_t *test = &sg_wifi_dppSendConfigResponse_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppSendConfigResponse(test);

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
	printf("\nwifi_dppSendConfigResponse: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
