/*
 * TEST RUNNER: sg_wifi_dppInitiate_test
 *
 * test_sg_wifi_dppInitiate() POISONS what the function must not touch, calls the handler and unpoisons: the context's config object, channels_list, received_frame, dpp_init_retries, token, enrollee_version,
 * the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The context is a heap block of exactly sizeof(wifi_device_dpp_context_t).  setup() builds real keys, the base64 SubjectPublicKeyInfo strings of
 * the responder / initiator bootstrap keys and a config session; the mocks capture the frame; run_all_tests recomputes M, k1, the boot hashes and the protocol key attribute itself, decrypts the wrapped data and
 * compares everything with a reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <openssl/kdf.h>
#include "hwr_wit.h"
#include <sanitizer/asan_interface.h>

/* Known open leak #255, NOT fixed: create_dpp_session_instance never frees the bootstrap EC_KEYs it decodes (the instance borrows its group from the key and wifi_dpp_instance_t has no field to own it).
 * Ignored so the run stays clean; covers the copies in the ReconfigInitiate and Initiate harnesses (one definition per binary). */
extern "C" const char *__lsan_default_suppressions(void) { return "leak:hwr_wrz_create_dpp_session_instance\nleak:hwr_wit_create_dpp_session_instance\n"; }

static char why[300];
static wifi_device_dpp_context_t *g_ctx, *g_ctx_arg;
static EC_KEY *g_rk, *g_ik;
static int g_ret, g_ret2;
static unsigned char g_sta[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&g_ctx->config, sizeof(g_ctx->config));
	fn(g_ctx->channels_list, sizeof(g_ctx->channels_list)); fn(&g_ctx->received_frame, sizeof(g_ctx->received_frame));
	fn(&g_ctx->dpp_init_retries, sizeof(g_ctx->dpp_init_retries)); fn(&g_ctx->token, sizeof(g_ctx->token)); fn(&g_ctx->enrollee_version, sizeof(g_ctx->enrollee_version));
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

static std::string key_text(int code, EC_KEY *k)
{
	if (code == 1) return "!!!!!!!!";
	if (code == 2) return "MAMBAgMA";
	if (code == 3) return "";
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

static void setup(const hwr_wit_case_t *t)
{
	static const int nids[] = { NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, NID_secp256k1 };
	g_rk = EC_KEY_new_by_curve_name(nids[t->rcurve]); EC_KEY_generate_key(g_rk);
	g_ik = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(g_ik);

	g_ctx = (wifi_device_dpp_context_t *)calloc(1, sizeof(*g_ctx));
	g_ctx->ap_index = t->ap;
	g_ctx->configurator_version = (unsigned char)t->ver;
	g_ctx->activation_status = ActStatus_Idle;
	g_ctx->session_data.session = wifi_dpp_session_type_config;
	g_ctx->session_data.state = STATE_DPP_UNPROVISIONED;
	g_ctx->session_data.instance = NULL;
	memcpy(g_ctx->session_data.sta_mac, g_sta, 6);
	g_ctx->session_data.channel = t->channel;
	{
		std::string r = key_text(t->rpub, g_rk), i = key_text(t->ipub, g_ik);
		strncpy(g_ctx->session_data.u.config_data.rPubKey, r.c_str(), 511);
		strncpy(g_ctx->session_data.u.config_data.iPubKey, i.c_str(), 511);
	}
	hwr_wit_home_channel = t->home;
	memset(&hwr_wit_cap, 0, sizeof(hwr_wit_cap));
	g_ctx_arg = (t->nul == 1) ? NULL : g_ctx;
}

static void cleanup(const hwr_wit_case_t *t)
{
	wifi_dpp_instance_t *in = g_ctx ? (wifi_dpp_instance_t *)g_ctx->session_data.instance : NULL;
	if (in) {
		int built = (t->rpub == 0 && t->ipub == 0 && t->rcurve < 3);
		if (built) {
			EC_POINT_free(in->N); EC_POINT_free(in->M); EC_POINT_clear_free(in->responder_proto_pt);
			EC_KEY_free(in->initiator_proto_key); BN_CTX_free(in->bnctx); BN_free(in->prime); BN_free(in->n); BN_free(in->m); BN_free(in->y); BN_free(in->x);
		}
		free(in);   /* a failed create leaves a partly initialised block: only the block itself is released */
	}
	free(g_ctx); g_ctx = NULL;
	EC_KEY_free(g_rk); EC_KEY_free(g_ik);
}

/* poison, call, unpoison (once per call); coord != 0: new random protocol key until the coordinate is shorter than the prime */
static void test_sg_wifi_dppInitiate(const hwr_wit_case_t *t)
{
	for (int attempt = 0; attempt < 40000; attempt++) {
		if (attempt > 0) { cleanup(t); setup(t); }
		for (int n = 0; n < t->calls; n++) {
			if (g_ctx_arg) poison(1);
			int r = hwr_sg_wifi_dppInitiate(g_ctx_arg);
			if (g_ctx_arg) poison(0);
			if (n == 0) g_ret = r; else g_ret2 = r;
		}
		if (!t->coord) return;
		wifi_dpp_instance_t *in = (wifi_dpp_instance_t *)g_ctx->session_data.instance;
		if (in && in->prime && in->x && in->y) {
			int pl = BN_num_bytes(in->prime);
			if ((t->coord == 1 && BN_num_bytes(in->x) < pl) || (t->coord == 2 && BN_num_bytes(in->y) < pl)) return;
		}
	}
}

#define FAIL(...) do { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } while (0)

static int ref_k1(wifi_dpp_instance_t *in, unsigned char *k1)
{
	/* M = B_R * p_I ; k1 = HKDF(hash, M.x, no salt, "first intermediate key") */
	EC_POINT *M = EC_POINT_new(in->group); BN_CTX *bc = BN_CTX_new(); BIGNUM *mx = BN_new();
	int pl = BN_num_bytes(in->prime), ok = 0;
	std::vector<unsigned char> m(pl);
	if (EC_POINT_mul(in->group, M, NULL, EC_KEY_get0_public_key(g_rk), EC_KEY_get0_private_key(in->initiator_proto_key), bc) &&
	    EC_POINT_get_affine_coordinates_GFp(in->group, M, mx, NULL, bc)) {
		BN_bn2binpad(mx, m.data(), pl);
		EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
		size_t len = in->digestlen;
		const char *info = "first intermediate key";
		if (pc && EVP_PKEY_derive_init(pc) > 0 && EVP_PKEY_CTX_set_hkdf_md(pc, in->hashfcn) > 0 && EVP_PKEY_CTX_set1_hkdf_key(pc, m.data(), pl) > 0 &&
		    EVP_PKEY_CTX_add1_hkdf_info(pc, (const unsigned char *)info, strlen(info)) > 0 && EVP_PKEY_derive(pc, k1, &len) > 0) ok = 1;
		EVP_PKEY_CTX_free(pc);
	}
	EC_POINT_free(M); BN_CTX_free(bc); BN_free(mx);
	return ok;
}

static int check_frame(const hwr_wit_case_t *t)
{
	const hwr_wit_cap_t *c = &hwr_wit_cap;
	const unsigned int H = sizeof(wifi_dppPublicActionFrame_t);
	wifi_dpp_instance_t *in = (wifi_dpp_instance_t *)g_ctx->session_data.instance;
	if (c->calls != t->calls) FAIL("wifi_sendActionFrame called %d times, expected %d", c->calls, t->calls);
	if (c->ap != t->ap) FAIL("ap_index %d, expected %d", c->ap, t->ap);
	if (memcmp(c->sta, g_sta, 6) != 0) FAIL("sta mac differs");
	unsigned want_f = hwr_wit_channel_to_frequency(t->channel);
	if (c->freq != want_f) FAIL("frequency %u, expected %u", c->freq, want_f);
	if (c->len < H || c->len > sizeof(c->frame)) FAIL("frame length %u", c->len);
	const wifi_dppPublicActionFrame_t *f = (const wifi_dppPublicActionFrame_t *)c->frame;
	if (f->public_action_hdr.cat != 4 || f->public_action_hdr.action != 9) FAIL("public action header");
	if (f->public_action_body.dpp_oui.oui[0] != 0x50 || f->public_action_body.dpp_oui.oui[1] != 0x6f || f->public_action_body.dpp_oui.oui[2] != 0x9a || f->public_action_body.dpp_oui.oui_type != 0x1a) FAIL("DPP OUI");
	if (f->public_action_body.crypto != 1 || f->public_action_body.frame_type != wifi_dpp_public_action_frame_type_auth_req) FAIL("crypto / frame type");
	if (in == NULL) FAIL("no session instance");
	static const int dl[] = { 32, 48, 64 };
	if (in->digestlen != dl[t->rcurve]) FAIL("digestlen %d", in->digestlen);
	const unsigned char *a = f->public_action_body.attrib; unsigned int off = 0, end = c->len - H;
	wifi_tlv_t h; unsigned char want[SHA512_DIGEST_LENGTH];
	#define NEXT(ty, what) do { if (off + 4 > end) FAIL("frame ends before the " what); memcpy(&h, a + off, 4); if (h.type != (ty) || off + 4 + h.length > end) FAIL(what " attribute"); } while (0)
	NEXT(wifi_dpp_attrib_id_initiator_boot_hash, "initiator boot hash"); boot_hash(g_ik, want);
	if (h.length != 32 || memcmp(a + off + 4, want, 32)) FAIL("initiator boot hash value");
	off += 4 + h.length;
	NEXT(wifi_dpp_attrib_id_responder_boot_hash, "responder boot hash"); boot_hash(g_rk, want);
	if (h.length != 32 || memcmp(a + off + 4, want, 32)) FAIL("responder boot hash value");
	off += 4 + h.length;
	if (t->ver > 1) {
		NEXT(wifi_dpp_attrib_id_proto_version, "protocol version");
		if (h.length != 1 || a[off + 4] != t->ver) FAIL("protocol version value");
		off += 4 + h.length;
	}
	NEXT(wifi_dpp_attrib_id_initiator_protocol_key, "initiator protocol key");
	{
		int pl = BN_num_bytes(in->prime);
		BIGNUM *x = BN_new(), *y = BN_new(); BN_CTX *bc = BN_CTX_new();
		EC_POINT_get_affine_coordinates_GFp(in->group, EC_KEY_get0_public_key(in->initiator_proto_key), x, y, bc);
		std::vector<unsigned char> xy(2 * pl);
		BN_bn2binpad(x, xy.data(), pl); BN_bn2binpad(y, xy.data() + pl, pl);
		BN_free(x); BN_free(y); BN_CTX_free(bc);
		if (h.length != (unsigned)(2 * pl) || memcmp(a + off + 4, xy.data(), 2 * pl)) FAIL("initiator protocol key is not x || y padded to the prime length");
	}
	off += 4 + h.length;
	NEXT(wifi_dpp_attrib_id_channel, "channel");
	{
		unsigned short ca = hwr_wit_freq_to_channel(hwr_wit_channel_to_frequency(t->home));
		if (h.length != 2 || memcmp(a + off + 4, &ca, 2)) FAIL("channel attribute");
	}
	off += 4 + h.length;
	unsigned int nw = off;
	NEXT(wifi_dpp_attrib_id_wrapped_data, "wrapped data");
	unsigned char k1[SHA512_DIGEST_LENGTH];
	if (!ref_k1(in, k1)) FAIL("reference k1 failed");
	if (memcmp(k1, in->k1, in->digestlen)) FAIL("k1 differs from HKDF(M.x, \"first intermediate key\")");
	int P = h.length - 16;
	if (P < 4 + in->noncelen) FAIL("wrapped data too short");
	std::vector<unsigned char> plain(P + 1);
	const unsigned char *wv = a + off + 4;
	siv_ctx sc; siv_init(&sc, k1, in->digestlen == 48 ? SIV_384 : in->digestlen == 64 ? SIV_512 : SIV_256);
	if (siv_decrypt(&sc, (unsigned char *)wv + 16, plain.data(), P, (unsigned char *)wv, 2, (unsigned char *)&f->public_action_body, (int)sizeof(wifi_dppPublicActionFrameBody_t), (unsigned char *)a, (int)nw) < 1)
		FAIL("wrapped data does not decrypt with k1 (AAD = frame body + preceding attributes)");
	memcpy(&h, plain.data(), 4);
	if (h.type != wifi_dpp_attrib_id_initiator_nonce || h.length != (unsigned)in->noncelen || memcmp(plain.data() + 4, in->initiator_nonce, in->noncelen)) FAIL("initiator nonce in the wrapped data");
	off += 4 + (unsigned)(16 + P);
	if (off != end) FAIL("frame length %u, attributes end at %u", end, off);
	return 1;
}

static int check(const hwr_wit_case_t *t)
{
	int ch = (t->channel >= 1 && t->channel <= 14) || (t->channel >= 36 && t->channel <= 64) || (t->channel >= 100 && t->channel <= 140) || (t->channel >= 149 && t->channel <= 165);
	int ok = (t->nul == 0 && t->rpub == 0 && t->ipub == 0 && t->rcurve < 3 && ch);

	if (g_ret != (ok ? RETURN_OK : RETURN_ERR)) FAIL("returned %d, expected %d", g_ret, ok ? RETURN_OK : RETURN_ERR);
	if (t->calls == 2 && g_ret2 != RETURN_OK) FAIL("second call returned %d", g_ret2);
	if (ok) {
		if (!check_frame(t)) return 0;
		if (g_ctx->session_data.state != STATE_DPP_AUTH_RSP_PENDING) FAIL("state %d, expected STATE_DPP_AUTH_RSP_PENDING", (int)g_ctx->session_data.state);
		if (g_ctx->activation_status != ActStatus_In_Progress) FAIL("activation_status %d", (int)g_ctx->activation_status);
	} else {
		if (hwr_wit_cap.calls != 0) FAIL("a frame was sent for a failed call");
		if (t->nul != 1) {
			if (g_ctx->activation_status != ActStatus_Failed) FAIL("activation_status %d, expected ActStatus_Failed", (int)g_ctx->activation_status);
			if (g_ctx->session_data.state == STATE_DPP_AUTH_RSP_PENDING) FAIL("state changed on failure");
		}
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) FAIL("guard byte %d modified", g);
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppInitiate(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppInitiate_suite[i].test_name != NULL; i++) {
			hwr_wit_case_t *test = &sg_wifi_dppInitiate_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppInitiate(test);

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
	printf("\nwifi_dppInitiate: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
