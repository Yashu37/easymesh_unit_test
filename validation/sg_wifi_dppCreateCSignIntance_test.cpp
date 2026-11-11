/*
 * TEST RUNNER: sg_wifi_dppCreateCSignIntance_test
 *
 * test_sg_wifi_dppCreateCSignIntance() POISONS what the function must not touch, calls the handler and unpoisons (once per call): the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The key string and the 32-byte sign_key_hash are exactly sized heap blocks; the function's keyasn1[1024] / digest[32] are stack objects with red zones.  The expected bn,
 * kid and key hash are computed independently with OpenSSL.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file); contexts are released by the
 * runner (BN / EC objects and bn, not the public point, which belongs to the key).  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <string.h>
#include "hwr_wcg.h"
#include <openssl/x509.h>
#include <sanitizer/asan_interface.h>

/* generated test keys: base64 DER ECPrivateKey (with public key), made with openssl ecparam -genkey -noout -outform DER */
static const char *hwr_wcg_key0 = "MHcCAQEEIFvSpqB0/9JcuTqGhdV45OdW+ZC5R1R3Qr+p04dqryG1oAoGCCqGSM49AwEHoUQDQgAELXVu9VjOgthrP7fQuzz6Uu5YVzmeyrBIkVF+LATnBbPD1i1UfQ/d7mMGrKzzF3EV0RG/IiIuKLfRr8EePVGUuw==";
static const char *hwr_wcg_key1 = "MIGkAgEBBDCXSYWcBNUhzhH8hysAtwjEE9K7iPJq1hKKwQj4kBxr8+hTLViSG5V3m6+LmjRhUh+gBwYFK4EEACKhZANiAAQOT/lS+UjvDjepaahCEs+FyPhTEgChC7d2KPmg7KACGhIRX8Q/DFznoYXO+67LmDRYMtz9yeIZTaq04HaK5UJelc3oQ4N94SrcQO75MwriwT6KoTkjlhCxleQ9fY7s5tI=";
static const char *hwr_wcg_key2 = "MIHcAgEBBEIBvOC1bTvXC3Upzsj89KzixbG+zxa3Vk52hqu43ILPsQOBhkVarE1ubB4HIc+l8pqb7SOwVrlZG5X/rCuxvc6XgcegBwYFK4EEACOhgYkDgYYABADF8n26IwJRoC2Vk5a002fDNH4AWpM3JWh1zO6tCUqt1SomMU0G+U6ztSkya7h8iv6Br1nyMkf5lId5aNZN8aKBuwGn85EKmoaDF/Z7zTcsK0TcIfKG9t0RGtrmFvZ3CS9HL2uP6Vo9yg6Bb3BpiMGV1A0lO/UA8hUzJKvouhInmIKLwA==";
static const char *hwr_wcg_key3 = "MHQCAQEEIKfA0AvOJxpuwMS5CNZdGUW1YohXrgPr22ig0Ye9WsOuoAcGBSuBBAAKoUQDQgAEqzNUXUvQsw8l2fgUGYkTwogZfVf7i5zo3gy9Fka8gUjG70FbNRkKm+5ADUtH/7cyG6PSne4HHNP+CKlxZu6I/g==";

static char why[300];
static int rets[2];
static wifi_dpp_csign_instance_t *inst;
static char *key_s; static unsigned char *hash_buf;

static char *key_string(int id)
{
	static char big[1401], trunc[61];
	switch (id) {
	case 0: return (char *)hwr_wcg_key0; case 1: return (char *)hwr_wcg_key1; case 2: return (char *)hwr_wcg_key2; case 3: return (char *)hwr_wcg_key3;
	case 4: return (char *)"@@@@@@@@"; case 5: return (char *)"";
	case 6: memcpy(trunc, hwr_wcg_key0, 60); trunc[60] = 0; return trunc;
	case 7: return (char *)"AAAAAAAA";
	default: memset(big, 'A', 1400); big[1400] = 0; return big;
	}
}
static int key_ok(int id) { return id >= 0 && id <= 2; }

typedef struct { std::string alg; std::string bn; std::string kid; unsigned char hash[32]; } expect_t;

/* independently computed results for key id (returns 0 when the key is not usable) */
static int expect_for(int id, expect_t *e)
{
	unsigned char der[1024]; const unsigned char *p = der; unsigned char *pub = NULL;
	const char *s = key_string(id);
	int n = EVP_DecodeBlock(der, (const unsigned char *)s, strlen(s));
	EC_KEY *k = n > 0 ? d2i_ECPrivateKey(NULL, &p, n) : NULL;
	if (!k) return 0;
	int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(k)), bnlen;
	if (nid == NID_X9_62_prime256v1) { e->alg = "ES256"; bnlen = 32; }
	else if (nid == NID_secp384r1) { e->alg = "ES384"; bnlen = 48; }
	else if (nid == NID_secp521r1) { e->alg = "ES521"; bnlen = 66; }
	else { EC_KEY_free(k); return 0; }
	BN_CTX *c = BN_CTX_new(); BIGNUM *x = BN_new(), *y = BN_new();
	EC_POINT_get_affine_coordinates(EC_KEY_get0_group(k), EC_KEY_get0_public_key(k), x, y, c);
	std::string bn(2 * bnlen + 1, '\0'); bn[0] = 4;
	BN_bn2bin(x, (unsigned char *)&bn[1] + bnlen - BN_num_bytes(x));
	BN_bn2bin(y, (unsigned char *)&bn[1 + bnlen] + bnlen - BN_num_bytes(y));
	e->bn = bn;
	unsigned char d[32]; SHA256((const unsigned char *)bn.data(), bn.size(), d);
	char b64[100]; int o = EVP_EncodeBlock((unsigned char *)b64, d, 32);
	for (int i = 0; i < o; i++) { if (b64[i] == '+') b64[i] = '-'; else if (b64[i] == '/') b64[i] = '_'; }
	while (o > 0 && b64[o - 1] == '=') o--;
	e->kid = std::string(b64, o);
	int l = i2d_EC_PUBKEY(k, &pub); SHA256(pub, l, e->hash);
	OPENSSL_free(pub); BN_free(x); BN_free(y); BN_CTX_free(c); EC_KEY_free(k);
	return 1;
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wcg_world.unrelated, sizeof(hwr_wcg_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void release(wifi_dpp_csign_instance_t *i)
{
	if (!i) return;
	if (i->bnctx) BN_CTX_free(i->bnctx);
	if (i->key) EC_KEY_free(i->key);
	if (i->x) BN_free(i->x);
	if (i->y) BN_free(i->y);
	if (i->prime) BN_free(i->prime);
	if (i->bn) hwr_wcg_free(i->bn);
	hwr_wcg_free(i);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_dppCreateCSignIntance(const hwr_wcg_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		char *k = t->key_null ? NULL : (char *)malloc(strlen(key_string(t->key[n])) + 1);
		if (k) strcpy(k, key_string(t->key[n]));
		unsigned char *hb = t->hash_null ? NULL : (unsigned char *)malloc(32);
		if (hb) memset(hb, 0xEE, 32);
		poison(1);
		rets[n] = hwr_sg_wifi_dppCreateCSignIntance(t->ap, k, t->inst_null ? NULL : &inst, hb);
		poison(0);
		if (n == t->calls - 1) { key_s = k; hash_buf = hb; }
		else { free(k); free(hb); }
	}
}

static int check(const hwr_wcg_case_t *t)
{
	const hwr_wcg_world_t *w = &hwr_wcg_world;
	int id = t->key[t->calls - 1];
	int want_ok = !t->inst_null && !t->key_null && !t->hash_null && key_ok(id);

	for (int n = 0; n < t->calls; n++) {
		int ok_n = !t->inst_null && !t->key_null && !t->hash_null && key_ok(t->key[n]);
		if (rets[n] != (ok_n ? RETURN_OK : RETURN_ERR)) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", n, rets[n], ok_n ? RETURN_OK : RETURN_ERR); return 0; }
	}
	if (want_ok) {
		expect_t e; expect_for(id, &e);
		if (!inst) { snprintf(why, sizeof(why), "*inst is NULL after success"); return 0; }
		if (w->live != 2) { snprintf(why, sizeof(why), "%d blocks allocated, expected 2 (context + bn)", w->live); return 0; }
		if (!inst->bnctx || !inst->key || !inst->x || !inst->y || !inst->prime || !inst->pt || !inst->bn) { snprintf(why, sizeof(why), "context members missing"); return 0; }
		if (inst->pt != EC_KEY_get0_public_key(inst->key)) { snprintf(why, sizeof(why), "public point does not belong to the key"); return 0; }
		if (e.alg != inst->alg) { snprintf(why, sizeof(why), "algorithm \"%s\", expected \"%s\"", inst->alg, e.alg.c_str()); return 0; }
		if (memcmp(inst->bn, e.bn.data(), e.bn.size()) != 0) { snprintf(why, sizeof(why), "public key bytes differ"); return 0; }
		if (e.kid != (char *)inst->kid) { snprintf(why, sizeof(why), "kid \"%s\", expected \"%s\"", (char *)inst->kid, e.kid.c_str()); return 0; }
		if (memcmp(hash_buf, e.hash, 32) != 0) { snprintf(why, sizeof(why), "sign key hash differs"); return 0; }
	} else {
		if (inst != NULL && !t->inst_null) { snprintf(why, sizeof(why), "*inst is %p after a failure, expected NULL", (void *)inst); return 0; }
		if (w->live != 0) { snprintf(why, sizeof(why), "%d block(s) still allocated after a failure", w->live); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppCreateCSignIntance(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppCreateCSignIntance_suite[i].test_name != NULL; i++) {
			hwr_wcg_case_t *test = &sg_wifi_dppCreateCSignIntance_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_wcg_world, 0, sizeof(hwr_wcg_world));
			inst = NULL;
			if (test->pre_existing) { inst = (wifi_dpp_csign_instance_t *)hwr_wcg_malloc(sizeof(*inst)); memset(inst, 0, sizeof(*inst)); inst->bnctx = BN_CTX_new(); }
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppCreateCSignIntance(test);

			int ok = check(test);
			if (hwr_wcg_world.live > 0) release(inst);
			free(key_s); free(hash_buf); key_s = NULL; hash_buf = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_dppCreateCSignIntance: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
