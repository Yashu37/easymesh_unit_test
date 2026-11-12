/*
 * TEST RUNNER: sg_wifi_dppSendAuthCnf_test
 *
 * test_sg_wifi_dppSendAuthCnf() POISONS what the function must not touch, calls the handler and unpoisons: the instance's k1 / k2 / rauth / enrollee_nonce / responder_nonce arrays, its group / hashfcn and
 * BIGNUM / EC pointer members (x .. responder_connector), the context's config object (everything except the credentials.keyManagement the function prints), channels_list and received_frame, the guard slab
 * and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  setup() builds the bootstrap keys, the base64 SubjectPublicKeyInfo strings, ke and iauth.  The mock wifi_sendActionFrame captures the frame; run_all_tests
 * decrypts it with the same AES-SIV key (AAD = frame body + the attributes in front of the wrapped data), checks every attribute and compares the result with a reference model of the CORRECT behaviour
 * (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "hwr_wsu.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t g_inst;
static EC_KEY *g_br, *g_bi;                       /* responder / initiator boot keys */
static int g_ret;
static wifi_device_dpp_context_t *g_ctx_arg;
static unsigned char g_sta[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(g_inst.k1, sizeof(g_inst.k1)); fn(g_inst.k2, sizeof(g_inst.k2)); fn(g_inst.rauth, sizeof(g_inst.rauth));
	fn(g_inst.enrollee_nonce, sizeof(g_inst.enrollee_nonce)); fn(g_inst.responder_nonce, sizeof(g_inst.responder_nonce));
	fn(&g_inst.group, 2 * sizeof(void *)); fn(&g_inst.x, 12 * sizeof(void *));
	fn(g_ctx.config.discovery, sizeof(g_ctx.config.discovery)); fn(&g_ctx.config.credentials.creds, sizeof(g_ctx.config.credentials.creds));
	fn(&g_ctx.config.reconfigCtx, 2 * sizeof(void *));
	fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(&g_ctx.received_frame, sizeof(g_ctx.received_frame));
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

static std::string key_string(int code, EC_KEY *k)
{
	if (code == 1) { unsigned char g[12] = { 0x30, 0x03, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0 }; unsigned char o[32]; int m = EVP_EncodeBlock(o, g, 9); return std::string((char *)o, m); }
	if (code == 2) return "";
	if (code == 3) return "!!!!!!!!";
	return spki_b64(k);
}

/* SHA-256 of the DER of the compressed public key */
static void boot_hash(EC_KEY *k, unsigned char *out)
{
	EC_KEY *d = EC_KEY_dup(k);
	EC_KEY_set_conv_form(d, POINT_CONVERSION_COMPRESSED); EC_KEY_set_asn1_flag(d, OPENSSL_EC_NAMED_CURVE);
	unsigned char *p = NULL; int n = i2d_EC_PUBKEY(d, &p);
	unsigned int ml = 32; EVP_Digest(p, n, out, &ml, EVP_sha256(), NULL);
	OPENSSL_free(p); EC_KEY_free(d);
}

static void setup(const hwr_wsu_case_t *t)
{
	g_br = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_br);
	g_bi = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_bi);

	memset(&g_ctx, 0, sizeof(g_ctx)); memset(&g_inst, 0, sizeof(g_inst));
	g_inst.digestlen = t->digest; g_inst.noncelen = 16; g_inst.mutual = t->mutual ? true : false;
	for (int i = 0; i < 64; i++) { g_inst.ke[i] = (unsigned char)(0x40 + i); g_inst.iauth[i] = (unsigned char)(0x70 + i); }
	g_ctx.ap_index = t->ap;
	g_ctx.activation_status = ActStatus_Idle;
	g_ctx.config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
	g_ctx.session_data.session = wifi_dpp_session_type_config;
	g_ctx.session_data.state = STATE_DPP_AUTH_RSP_PENDING;
	g_ctx.session_data.instance = (t->nul == 2) ? NULL : &g_inst;
	memcpy(g_ctx.session_data.sta_mac, g_sta, 6);
	g_ctx.session_data.channel = t->freq;
	{
		std::string r = key_string(t->rpub, g_br), i = key_string(t->ipub, g_bi);
		strncpy(g_ctx.session_data.u.config_data.rPubKey, r.c_str(), 511);
		strncpy(g_ctx.session_data.u.config_data.iPubKey, i.c_str(), 511);
	}
	memset(&hwr_wsu_cap, 0, sizeof(hwr_wsu_cap));
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;
}

static void cleanup(void)
{
	EC_KEY_free(g_br); EC_KEY_free(g_bi);
}

/* poison, call, unpoison */
static void test_sg_wifi_dppSendAuthCnf(const hwr_wsu_case_t *t)
{
	(void)t;
	if (g_ctx_arg) poison(1);
	g_ret = hwr_sg_wifi_dppSendAuthCnf(g_ctx_arg);
	if (g_ctx_arg) poison(0);
}

#define FAIL(...) do { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } while (0)

static int check_frame(const hwr_wsu_case_t *t)
{
	const hwr_wsu_cap_t *c = &hwr_wsu_cap;
	const unsigned int H = sizeof(wifi_dppPublicActionFrame_t);
	if (c->calls != 1) FAIL("wifi_sendActionFrame called %d times", c->calls);
	if (c->ap != t->ap) FAIL("ap_index %d, expected %d", c->ap, t->ap);
	if (memcmp(c->sta, g_sta, 6) != 0) FAIL("sta mac differs");
	if (c->freq != (unsigned)t->freq) FAIL("frequency %u, expected %d", c->freq, t->freq);
	if (c->len < H + 5 || c->len > sizeof(c->frame)) FAIL("frame length %u", c->len);
	const wifi_dppPublicActionFrame_t *f = (const wifi_dppPublicActionFrame_t *)c->frame;
	if (f->public_action_hdr.cat != 4 || f->public_action_hdr.action != 9) FAIL("public action header");
	if (f->public_action_body.dpp_oui.oui[0] != 0x50 || f->public_action_body.dpp_oui.oui[1] != 0x6f || f->public_action_body.dpp_oui.oui[2] != 0x9a || f->public_action_body.dpp_oui.oui_type != 0x1a) FAIL("DPP OUI");
	if (f->public_action_body.crypto != 1 || f->public_action_body.frame_type != wifi_dpp_public_action_frame_type_auth_cnf) FAIL("crypto / frame type");
	const unsigned char *a = f->public_action_body.attrib;
	unsigned int off = 0;
	wifi_tlv_t h;
	memcpy(&h, a, 4); if (h.type != wifi_dpp_attrib_id_status || h.length != 1 || a[4] != 0) FAIL("status TLV"); off += 5;
	unsigned char want[32];
	if (t->mutual) {
		memcpy(&h, a + off, 4); if (h.type != wifi_dpp_attrib_id_initiator_boot_hash || h.length != 32) FAIL("initiator boot hash TLV");
		if (t->hashchk) { boot_hash(g_bi, want); if (memcmp(a + off + 4, want, 32)) FAIL("initiator boot hash is not the SHA-256 of the compressed-key DER"); }
		off += 36;
	}
	memcpy(&h, a + off, 4); if (h.type != wifi_dpp_attrib_id_responder_boot_hash || h.length != 32) FAIL("responder boot hash TLV");
	if (t->hashchk) { boot_hash(g_br, want); if (memcmp(a + off + 4, want, 32)) FAIL("responder boot hash is not the SHA-256 of the compressed-key DER"); }
	off += 36;
	unsigned int nw = off;
	memcpy(&h, a + off, 4);
	if (h.type != wifi_dpp_attrib_id_wrapped_data || h.length != 16 + 4 + (unsigned)t->digest) FAIL("wrapped data TLV type 0x%x length %u", h.type, h.length);
	if (c->len != H + off + 4 + h.length) FAIL("frame length %u, expected %u", c->len, H + off + 4 + h.length);
	const unsigned char *wv = a + off + 4;
	int P = h.length - 16;
	std::vector<unsigned char> plain(P + 1);
	siv_ctx sc; siv_init(&sc, g_inst.ke, t->digest == 48 ? SIV_384 : t->digest == 64 ? SIV_512 : SIV_256);
	if (siv_decrypt(&sc, wv + 16, plain.data(), P, (unsigned char *)wv, 2, (unsigned char *)&f->public_action_body, (int)sizeof(wifi_dppPublicActionFrameBody_t), (unsigned char *)a, (int)nw) < 1)
		FAIL("wrapped data does not decrypt (AAD = frame body + preceding attributes)");
	memcpy(&h, plain.data(), 4);
	if (h.type != wifi_dpp_attrib_id_initiator_auth_tag || h.length != t->digest || memcmp(plain.data() + 4, g_inst.iauth, t->digest)) FAIL("initiator auth tag attribute");
	return 1;
}

static int check(const hwr_wsu_case_t *t)
{
	int dok = (t->digest == 32 || t->digest == 48 || t->digest == 64);
	int ok = (t->nul == 0 && dok && t->rpub == 0 && t->ipub != 3 && (t->ipub == 0 || (!t->mutual && (t->ipub == 1 || t->ipub == 2))));

	if (g_ret != (ok ? RETURN_OK : RETURN_ERR)) FAIL("returned %d, expected %d", g_ret, ok ? RETURN_OK : RETURN_ERR);
	if (ok) {
		if (!check_frame(t)) return 0;
		if (g_ctx.session_data.state != STATE_DPP_AUTHENTICATED) FAIL("state %d, expected STATE_DPP_AUTHENTICATED", (int)g_ctx.session_data.state);
		if (g_ctx.activation_status != ActStatus_In_Progress) FAIL("activation_status %d", (int)g_ctx.activation_status);
	} else {
		if (hwr_wsu_cap.calls != 0) FAIL("a frame was sent for a failed call");
		if (t->nul != 1) {
			if (g_ctx.activation_status != ActStatus_Failed) FAIL("activation_status %d, expected ActStatus_Failed", (int)g_ctx.activation_status);
			if (g_ctx.session_data.state != STATE_DPP_AUTH_RSP_PENDING) FAIL("state changed on failure");
		}
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) FAIL("guard byte %d modified", g);
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppSendAuthCnf(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppSendAuthCnf_suite[i].test_name != NULL; i++) {
			hwr_wsu_case_t *test = &sg_wifi_dppSendAuthCnf_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppSendAuthCnf(test);

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
	printf("\nwifi_dppSendAuthCnf: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
