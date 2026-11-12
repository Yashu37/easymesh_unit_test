/*
 * TEST RUNNER: sg_wifi_dppProcessReconfigAnnouncement_test
 *
 * test_sg_wifi_dppProcessReconfigAnnouncement() POISONS what the function must not touch, calls the handler and unpoisons: the caller's key_hash block beyond the 32-byte digest (bytes 32..511 of the
 * 512-byte sign_key_hash field: only the digest is ever compared or dumped), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The frame lives in a heap block of EXACTLY the declared
 * length, so ASan also reports every read outside the frame.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file) and checks that the frame
 * bytes, the key hash and the guard slab are unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "hwr_wrn.h"
#include <sanitizer/asan_interface.h>

#define FRAME_HDR 6

static char why[240];
static unsigned char *g_frame, *g_key;
static unsigned int g_declared;
static std::vector<unsigned char> g_frame_copy;
static unsigned char g_key_copy[32];
static int g_ret;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (g_key) fn(g_key + 32, HWR_WRN_KEYHASH_SZ - 32);
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

static void other_attr(std::vector<unsigned char> &v, int k)
{
	static const unsigned char b[4] = { 0x31, 0x32, 0x33, 0x34 };
	static const unsigned short ty[3] = { wifi_dpp_attrib_id_transaction_id, wifi_dpp_attrib_id_proto_version, wifi_dpp_attrib_id_reconfig_flags };
	static const unsigned short ln[3] = { 1, 1, 4 };
	put_tlv(v, ty[k % 3], ln[k % 3], b, ln[k % 3]);
}

static void setup(const hwr_wrn_case_t *t)
{
	g_key = (unsigned char *)malloc(HWR_WRN_KEYHASH_SZ);
	memset(g_key, 0, HWR_WRN_KEYHASH_SZ);
	for (int i = 0; i < 32; i++) g_key[i] = t->zero_key ? 0 : (unsigned char)(0xC0 + i);
	memcpy(g_key_copy, g_key, 32);

	std::vector<unsigned char> f(FRAME_HDR, 0);
	f[0] = 0x50; f[1] = 0x6F; f[2] = 0x9A; f[3] = 0x1A; f[4] = 1; f[5] = 14;
	for (int k = 0; k < t->before; k++) other_attr(f, k);
	if (t->tlv) {
		std::vector<unsigned char> val(t->hlen > 0 ? t->hlen : 0, 0x5A);
		for (int i = 0; i < t->hlen && i < 32; i++) val[i] = g_key[i];
		if (t->tlv == 2 && t->hlen >= 32) val[31] ^= 0xFF;
		if (t->tlv == 3 && t->hlen >= 32) val[0] ^= 0xFF;
		if (t->tlv == 4) memset(val.data(), 0, val.size());
		unsigned short type = (t->tlv == 5) ? wifi_dpp_attrib_id_wrapped_data : wifi_dpp_attrib_id_C_sign_key_hash;
		size_t present = (t->tlv == 6) ? val.size() - 4 : val.size();
		put_tlv(f, type, (unsigned short)t->hlen, val.data(), present);
	}
	for (int k = 0; k < t->after; k++) other_attr(f, k + 1);

	g_declared = (t->flen >= 0) ? (unsigned int)t->flen : (unsigned int)f.size();
	size_t alloc = g_declared ? g_declared : 1;
	g_frame = (unsigned char *)malloc(alloc);
	memset(g_frame, 0, alloc);
	memcpy(g_frame, f.data(), alloc < f.size() ? alloc : f.size());
	g_frame_copy.assign(g_frame, g_frame + alloc);
}

static void cleanup(void)
{
	free(g_frame); g_frame = NULL;
	free(g_key); g_key = NULL;
}

/* poison, call, unpoison */
static void test_sg_wifi_dppProcessReconfigAnnouncement(const hwr_wrn_case_t *t)
{
	unsigned char *fr = (t->nul == 1) ? NULL : g_frame;
	unsigned char *kh = (t->nul == 2) ? NULL : g_key;

	poison(1);
	g_ret = hwr_sg_wifi_dppProcessReconfigAnnouncement(fr, g_declared, kh);
	poison(0);
}

/* reference model of the CORRECT behaviour */
static int model(const hwr_wrn_case_t *t)
{
	if (t->nul || t->flen >= 0) return RETURN_ERR;
	if (t->tlv != 1 || t->hlen != 32) return RETURN_ERR;
	return RETURN_OK;
}

static int check(const hwr_wrn_case_t *t)
{
	int want = model(t);
	size_t alloc = g_declared ? g_declared : 1;

	if (g_ret != want) { snprintf(why, sizeof(why), "returned %d, expected %d", g_ret, want); return 0; }
	if (memcmp(g_frame, g_frame_copy.data(), alloc) != 0) { snprintf(why, sizeof(why), "frame modified"); return 0; }
	if (memcmp(g_key, g_key_copy, 32) != 0) { snprintf(why, sizeof(why), "key hash modified"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppProcessReconfigAnnouncement(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppProcessReconfigAnnouncement_suite[i].test_name != NULL; i++) {
			hwr_wrn_case_t *test = &sg_wifi_dppProcessReconfigAnnouncement_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppProcessReconfigAnnouncement(test);

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
	printf("\nwifi_dppProcessReconfigAnnouncement: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
