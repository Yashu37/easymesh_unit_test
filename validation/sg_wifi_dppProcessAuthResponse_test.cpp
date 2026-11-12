/*
 * TEST RUNNER: sg_wifi_dppProcessAuthResponse_test
 *
 * test_sg_wifi_dppProcessAuthResponse() POISONS what the function must not touch, calls the handler and unpoisons: the instance's k1 / enrollee_nonce arrays and its M / responder_connector pointers,
 * the context's config object, channels_list and session_data.sta_mac, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  (k2, ke, rauth, iauth, responder_nonce, x, y, n, N and the session
 * channel are legitimately written, initiator_nonce, m, l, prime and both public keys are read.)  The frame lives in a heap block of EXACTLY the declared length, so ASan also reports every read outside
 * the frame.  setup() builds a real P-256 session (initiator protocol key pi, responder protocol key PR, responder / initiator boot keys), derives k2 / ke with the same HKDF the function uses (hwr_wap_hkdf)
 * and builds the frame with AES-SIV (header + preceding attributes as associated data for the primary wrapped data).  run_all_tests compares the result with a reference model of the CORRECT behaviour
 * (see the construct file) and checks the stored values, the frame bytes and the guard slab.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "hwr_wap.h"
#include <sanitizer/asan_interface.h>

#define FRAME_HDR 6
#define NONCELEN 16
#define SENTINEL RESPONDER_STATUS_BAD_CODE

static char why[240];
static wifi_device_dpp_context_t g_ctx;
static wifi_dpp_instance_t g_inst;
static EC_GROUP *g_group;
static BN_CTX *g_bn;
static EC_KEY *g_pi, *g_pr, *g_br, *g_bi;           /* initiator protocol key, responder protocol key, responder boot key, initiator boot key */
static unsigned char *g_frame;
static unsigned int g_declared;
static std::vector<unsigned char> g_frame_copy;
static int g_ret;
static wifi_device_dpp_context_t *g_ctx_arg;
static unsigned char g_rn[NONCELEN * 2], g_k2[64], g_rauth[64], g_iauth[64];
static int g_rnlen;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(g_inst.k1, sizeof(g_inst.k1)); fn(g_inst.enrollee_nonce, sizeof(g_inst.enrollee_nonce));
	fn(&g_inst.M, sizeof(g_inst.M)); fn(&g_inst.responder_connector, sizeof(g_inst.responder_connector));
	fn(&g_ctx.config, sizeof(g_ctx.config)); fn(g_ctx.channels_list, sizeof(g_ctx.channels_list));
	fn(g_ctx.session_data.sta_mac, sizeof(g_ctx.session_data.sta_mac));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void put_tlv(std::vector<unsigned char> &v, unsigned short type, unsigned short declared, const void *data, size_t actual)
{
	size_t o = v.size();
	v.resize(o + 4 + actual);
	memcpy(&v[o], &type, 2); memcpy(&v[o + 2], &declared, 2);
	if (actual) memcpy(&v[o + 4], data, actual);
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

static void xcoord(EC_KEY *k, unsigned char *x, unsigned char *y)
{
	BIGNUM *bx = BN_new(), *by = BN_new();
	EC_POINT_get_affine_coordinates_GFp(g_group, EC_KEY_get0_public_key(k), bx, by, g_bn);
	BN_bn2binpad(bx, x, 32); if (y) BN_bn2binpad(by, y, 32);
	BN_free(bx); BN_free(by);
}

/* SHA-256 of the DER of the compressed public key = the responder boot hash the function computes */
static void boot_hash(EC_KEY *k, unsigned char *out)
{
	EC_KEY *d = EC_KEY_dup(k);
	EC_KEY_set_conv_form(d, POINT_CONVERSION_COMPRESSED); EC_KEY_set_asn1_flag(d, OPENSSL_EC_NAMED_CURVE);
	unsigned char *p = NULL; int n = i2d_EC_PUBKEY(d, &p);
	unsigned int ml = 32; EVP_Digest(p, n, out, &ml, EVP_sha256(), NULL);
	OPENSSL_free(p); EC_KEY_free(d);
}

static const EVP_MD *md_for(int digest) { return digest == 48 ? EVP_sha384() : digest == 64 ? EVP_sha512() : EVP_sha256(); }
static int siv_for(int digest) { return digest == 48 ? SIV_384 : digest == 64 ? SIV_512 : SIV_256; }

/* R-auth' / I-auth' as create_auth_tags computes them */
static void auth_tag(const hwr_wap_case_t *t, int rauth, unsigned char *out)
{
	const EVP_MD *md = md_for(t->digest);
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	unsigned char pix[32], prx[32], brx[32], i16[NONCELEN], fin = rauth ? 0 : 1;
	unsigned int ml = 0;
	xcoord(g_pi, pix, NULL); xcoord(g_pr, prx, NULL); xcoord(g_br, brx, NULL);
	memset(i16, 0x22, sizeof(i16));
	EVP_DigestInit(c, md);
	if (rauth) { EVP_DigestUpdate(c, i16, NONCELEN); EVP_DigestUpdate(c, g_rn, NONCELEN); EVP_DigestUpdate(c, pix, 32); EVP_DigestUpdate(c, prx, 32); }
	else       { EVP_DigestUpdate(c, g_rn, NONCELEN); EVP_DigestUpdate(c, i16, NONCELEN); EVP_DigestUpdate(c, prx, 32); EVP_DigestUpdate(c, pix, 32); }
	EVP_DigestUpdate(c, brx, 32);
	if (t->mutual) EVP_DigestUpdate(c, brx, 32);          /* as implemented: BR.x is hashed again instead of BI.x */
	EVP_DigestUpdate(c, &fin, 1);
	EVP_DigestFinal(c, out, &ml);
	EVP_MD_CTX_free(c);
}

static void setup(const hwr_wap_case_t *t)
{
	g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	g_bn = BN_CTX_new();
	EC_KEY **ks[4] = { &g_pi, &g_pr, &g_br, &g_bi };
	for (int i = 0; i < 4; i++) { *ks[i] = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); EC_KEY_generate_key(*ks[i]); }

	memset(&g_ctx, 0, sizeof(g_ctx)); memset(&g_inst, 0, sizeof(g_inst));
	g_inst.group = g_group; g_inst.hashfcn = md_for(t->digest); g_inst.digestlen = t->digest; g_inst.noncelen = NONCELEN; g_inst.nid = NID_X9_62_prime256v1;
	g_inst.bnctx = g_bn; g_inst.prime = BN_new();
	EC_GROUP_get_curve_GFp(g_group, g_inst.prime, NULL, NULL, g_bn);
	g_inst.x = BN_new(); g_inst.y = BN_new(); g_inst.m = BN_new(); g_inst.n = BN_new(); g_inst.l = BN_new();
	BN_rand(g_inst.m, 250, 0, 0); BN_rand(g_inst.l, 250, 0, 0);
	g_inst.N = EC_POINT_new(g_group); g_inst.responder_proto_pt = EC_POINT_new(g_group);
	g_inst.initiator_proto_key = g_pi;
	memset(g_inst.initiator_nonce, 0x22, NONCELEN);
	memset(g_inst.enrollee_nonce, 0x11, sizeof(g_inst.enrollee_nonce));
	if (t->nul == 3) { BN_free(g_inst.x); g_inst.x = NULL; }
	if (t->nul == 4) { BN_free(g_inst.y); g_inst.y = NULL; }

	g_ctx.session_data.session = wifi_dpp_session_type_config;
	g_ctx.session_data.instance = (t->nul == 2) ? NULL : &g_inst;
	g_ctx.ap_index = 2;
	g_ctx.enrollee_version = 0xEE;
	g_ctx.enrollee_status = SENTINEL;
	g_ctx.session_data.channel = 0xDEAD;
	{
		std::string r = key_string(t->rpub, g_br), i = key_string(t->ipub, g_bi);
		strncpy(g_ctx.session_data.u.config_data.rPubKey, r.c_str(), 511);
		strncpy(g_ctx.session_data.u.config_data.iPubKey, i.c_str(), 511);
	}

	/* the keys the function derives */
	unsigned int pl = 32;
	EC_POINT *Np = EC_POINT_new(g_group); BIGNUM *nx = BN_new();
	EC_POINT_mul(g_group, Np, NULL, EC_KEY_get0_public_key(g_pr), EC_KEY_get0_private_key(g_pi), g_bn);
	EC_POINT_get_affine_coordinates_GFp(g_group, Np, nx, NULL, g_bn);
	unsigned char mb[32], nb[32], lb[32], ikm[96], salt[2 * NONCELEN], i16[NONCELEN];
	BN_bn2binpad(g_inst.m, mb, 32); BN_bn2binpad(nx, nb, 32); BN_bn2binpad(g_inst.l, lb, 32);
	memset(g_k2, 0, sizeof(g_k2));
	hwr_wap_hkdf(md_for(t->digest), 0, nb, pl, NULL, 0, (unsigned char *)"second intermediate key", (int)strlen("second intermediate key"), g_k2, t->digest);
	static const int rnl[] = { 0, 16, 32, 33, 8, 0 }, inl[] = { 0, 16, 16, 8, 0 };
	unsigned char rnsrc[40], insrc[40];
	for (int i = 0; i < 40; i++) { rnsrc[i] = (unsigned char)(0xB0 + i); insrc[i] = (unsigned char)(0xA0 + i); }
	memset(g_rn, 0, sizeof(g_rn)); g_rnlen = rnl[t->rn];
	memcpy(g_rn, rnsrc, g_rnlen > (int)sizeof(g_rn) ? sizeof(g_rn) : g_rnlen);
	memset(i16, 0x22, sizeof(i16));
	memcpy(ikm, mb, 32); memcpy(ikm + 32, nb, 32); memcpy(ikm + 64, lb, 32);
	memcpy(salt, i16, NONCELEN); memcpy(salt + NONCELEN, g_rn, NONCELEN);
	unsigned char ke[64]; memset(ke, 0, sizeof(ke));
	hwr_wap_hkdf(md_for(t->digest), 0, ikm, t->mutual ? 96 : 64, salt, 2 * NONCELEN, (unsigned char *)"DPP Key", 7, ke, t->digest);
	auth_tag(t, 1, g_rauth); auth_tag(t, 0, g_iauth);

	/* the frame */
	std::vector<unsigned char> f(FRAME_HDR, 0);
	f[0] = 0x50; f[1] = 0x6F; f[2] = 0x9A; f[3] = 0x1A; f[4] = 1; f[5] = 1;
	unsigned char verv = 2, vv2[2] = { 2, 0 }, st0 = 0, st1 = 1, st2[2] = { 0, 0 };
	if (t->ver == 1) put_tlv(f, wifi_dpp_attrib_id_proto_version, 1, &verv, 1);
	else if (t->ver == 2) put_tlv(f, wifi_dpp_attrib_id_proto_version, 2, vv2, 2);
	if (t->status == 1) put_tlv(f, wifi_dpp_attrib_id_status, 1, &st0, 1);
	else if (t->status == 2) put_tlv(f, wifi_dpp_attrib_id_status, 1, &st1, 1);
	else if (t->status == 3) put_tlv(f, wifi_dpp_attrib_id_status, 2, st2, 2);
	if (t->bhash) {
		unsigned char h[32]; boot_hash(g_br, h);
		if (t->bhash == 2) h[31] ^= 0xFF;
		put_tlv(f, wifi_dpp_attrib_id_responder_boot_hash, t->bhash == 3 ? 16 : t->bhash == 4 ? 0 : 32, h, t->bhash == 3 ? 16 : t->bhash == 4 ? 0 : 32);
	}
	if (t->mutual) { unsigned char h[32]; boot_hash(g_bi, h); put_tlv(f, wifi_dpp_attrib_id_initiator_boot_hash, 32, h, 32); }
	if (t->rkey) {
		unsigned char kb[64]; xcoord(g_pr, kb, kb + 32);
		if (t->rkey == 3) { memset(kb, 0x11, 32); memset(kb + 32, 0x22, 32); }
		size_t kl = (t->rkey == 2) ? 32 : 64;
		put_tlv(f, wifi_dpp_attrib_id_responder_protocol_key, (unsigned short)kl, kb, kl);
	}
	if (t->wrap) {
		size_t non_wrapped = f.size() - FRAME_HDR;
		std::vector<unsigned char> plain;
		if (t->wrap == 1 || t->wrap == 2) {
			unsigned char cap = 2;
			if (t->rn) put_tlv(plain, wifi_dpp_attrib_id_responder_nonce, rnl[t->rn], rnsrc, rnl[t->rn]);
			if (t->rcap) put_tlv(plain, wifi_dpp_attrib_id_responder_cap, 1, &cap, 1);
			if (t->in) { unsigned char in[40]; memcpy(in, insrc, 40); memset(in, 0x22, NONCELEN); if (t->in == 2) in[15] ^= 0xFF; put_tlv(plain, wifi_dpp_attrib_id_initiator_nonce, inl[t->in], in, inl[t->in]); }
			if (t->sec) {
				std::vector<unsigned char> sp;
				unsigned char tg[64]; memcpy(tg, g_rauth, 64);
				if (t->tag == 1) put_tlv(sp, wifi_dpp_attrib_id_responder_auth_tag, t->digest, tg, t->digest);
				else if (t->tag == 2) { tg[0] ^= 0xFF; put_tlv(sp, wifi_dpp_attrib_id_responder_auth_tag, t->digest, tg, t->digest); }
				else if (t->tag == 3) put_tlv(sp, wifi_dpp_attrib_id_responder_auth_tag, 8, tg, 8);
				else put_tlv(sp, wifi_dpp_attrib_id_reserved_1, 4, tg, 4);
				if (t->sec == 3) { unsigned char junk[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }; put_tlv(plain, wifi_dpp_attrib_id_wrapped_data, 8, junk, 8); }
				else if (t->sec == 4) { unsigned char junk[20]; memset(junk, 0x33, sizeof(junk)); put_tlv(plain, wifi_dpp_attrib_id_wrapped_data, 600, junk, sizeof(junk)); }
				else {
					size_t wl = (t->sec == 5) ? 0 : sp.size(), off = plain.size();
					plain.resize(off + 4 + 16 + wl);
					wifi_tlv_t *s = (wifi_tlv_t *)&plain[off];
					s->type = wifi_dpp_attrib_id_wrapped_data; s->length = (unsigned short)(wl + 16);
					siv_ctx sc; siv_init(&sc, ke, siv_for(t->digest));
					siv_encrypt(&sc, sp.data(), &s->value[16], (int)wl, s->value, 0);
					if (t->sec == 2) s->value[16 + 3] ^= 0x01;
				}
			}
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
			siv_ctx sc; siv_init(&sc, g_k2, siv_for(t->digest));
			wifi_dppPublicActionFrameBody_t *body = (wifi_dppPublicActionFrameBody_t *)f.data();
			siv_encrypt(&sc, plain.data(), &w->value[16], (int)wl, w->value, 2, body, FRAME_HDR, body->attrib, (int)non_wrapped);
			if (t->wrap == 2) w->value[16 + 3] ^= 0x01;
		}
	}
	g_declared = (t->flen >= 0) ? (unsigned int)t->flen : (unsigned int)f.size();
	size_t alloc = g_declared ? g_declared : 1;
	g_frame = (unsigned char *)malloc(alloc);
	memset(g_frame, 0, alloc);
	memcpy(g_frame, f.data(), alloc < f.size() ? alloc : f.size());
	g_frame_copy.assign(g_frame, g_frame + alloc);
	g_ctx.received_frame.frame = (t->nul == 5) ? NULL : g_frame;
	g_ctx.received_frame.length = g_declared;
	g_ctx_arg = (t->nul == 1) ? NULL : &g_ctx;
	EC_POINT_free(Np); BN_free(nx);
}

static void cleanup(void)
{
	free(g_frame); g_frame = NULL;
	BN_free(g_inst.x); BN_free(g_inst.y); BN_free(g_inst.m); BN_free(g_inst.n); BN_free(g_inst.l); BN_free(g_inst.prime);
	EC_POINT_free(g_inst.N); EC_POINT_free(g_inst.responder_proto_pt);
	EC_KEY_free(g_pi); EC_KEY_free(g_pr); EC_KEY_free(g_br); EC_KEY_free(g_bi);
	BN_CTX_free(g_bn); EC_GROUP_free(g_group);
}

/* poison, call, unpoison */
static void test_sg_wifi_dppProcessAuthResponse(const hwr_wap_case_t *t)
{
	(void)t;
	if (g_ctx_arg) poison(1);
	g_ret = hwr_sg_wifi_dppProcessAuthResponse(g_ctx_arg);
	if (g_ctx_arg) poison(0);
}

/* reference model of the CORRECT behaviour */
static int model(const hwr_wap_case_t *t)
{
	if (t->nul || t->flen >= 0) return RETURN_ERR;
	if (t->digest != 32 && t->digest != 48 && t->digest != 64) return RETURN_ERR;
	if (t->ver == 2 || t->ver == 3) return RETURN_ERR;
	if (t->status != 1 || t->bhash != 1 || t->rpub || t->ipub || t->rkey != 1 || t->wrap != 1) return RETURN_ERR;
	if (t->rn != 1 || !t->rcap || t->in != 1 || t->sec != 1 || t->tag != 1) return RETURN_ERR;
	return RETURN_OK;
}

static int check(const hwr_wap_case_t *t)
{
	int want = model(t);
	size_t alloc = g_declared ? g_declared : 1;

	if (g_ret != want) { snprintf(why, sizeof(why), "returned %d, expected %d", g_ret, want); return 0; }
	if (t->nul != 1) {
		int ws = (want == RETURN_OK) ? RESPONDER_STATUS_OK : RESPONDER_STATUS_AUTH_FAILURE;
		int lenient = (t->nul >= 2 && t->nul <= 4) || t->ver == 2 || t->ver == 3;      /* the original returns without setting a status there */
		if (g_ctx.enrollee_status != ws && !(lenient && g_ctx.enrollee_status == SENTINEL)) { snprintf(why, sizeof(why), "enrollee_status %d, expected %d", (int)g_ctx.enrollee_status, ws); return 0; }
	}
	if (want == RETURN_OK) {
		if (g_ctx.enrollee_version != (t->ver ? 2 : 1)) { snprintf(why, sizeof(why), "enrollee_version %d", g_ctx.enrollee_version); return 0; }
		if (memcmp(g_inst.responder_nonce, g_rn, NONCELEN) != 0) { snprintf(why, sizeof(why), "responder_nonce not stored"); return 0; }
		if ((g_inst.mutual ? 1 : 0) != t->mutual) { snprintf(why, sizeof(why), "mutual flag %d", (int)g_inst.mutual); return 0; }
		if (memcmp(g_inst.k2, g_k2, t->digest) != 0) { snprintf(why, sizeof(why), "k2 differs from the reference"); return 0; }
		if (!t->mutual && (memcmp(g_inst.rauth, g_rauth, t->digest) != 0 || memcmp(g_inst.iauth, g_iauth, t->digest) != 0)) { snprintf(why, sizeof(why), "R-auth / I-auth differ from the reference"); return 0; }
		if (g_ctx.session_data.channel != 2437) { snprintf(why, sizeof(why), "channel %u, expected 2437", g_ctx.session_data.channel); return 0; }
	}
	if (memcmp(g_frame, g_frame_copy.data(), alloc) != 0) { snprintf(why, sizeof(why), "frame modified"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppProcessAuthResponse(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppProcessAuthResponse_suite[i].test_name != NULL; i++) {
			hwr_wap_case_t *test = &sg_wifi_dppProcessAuthResponse_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppProcessAuthResponse(test);

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
	printf("\nwifi_dppProcessAuthResponse: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
