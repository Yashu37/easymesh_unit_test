/*
 * TEST RUNNER: wifi_drv_get_phy_eht_cap_mac_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_drv_get_phy_eht_cap_mac() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the struct eht_capabilities (preset to a 0xA5 pattern, mac_cap preset to 0xBEEF) and the
 * attribute table tb (NL80211_BAND_IFTYPE_ATTR_MAX + 1 pointers).  During the call it POISONS every byte of the struct EXCEPT mac_cap (a write to
 * eht_supported, phy_cap, mcs or ppet aborts under ASan), every tb slot EXCEPT the EHT_CAP_MAC one (reading another attribute aborts), the guard slab and the
 * log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The EHT_CAP_MAC attribute is an exact-size heap block (4-byte header + payload), so reading more than the
 * 2 MAC bytes aborts too.  Checks: mac_cap == little-endian first 2 payload bytes when the attribute exists and nla_len() >= 2, else still 0xBEEF; the rest
 * of the struct unchanged; guard slab unchanged.  Rows with last = 1 crash the original function: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "hwr_gem.h"
#include <sanitizer/asan_interface.h>

#define NTB (NL80211_BAND_IFTYPE_ATTR_MAX + 1)
#define PRESET_MAC 0xBEEF

static struct eht_capabilities eht;
static struct eht_capabilities eht_before;
static struct nlattr *tb_arr[NTB];
static struct nlattr *attr_blk, *he_blk, *phy_blk;
static char why[200];

static struct nlattr *make_attr(int type, int payload_len, unsigned char b0, unsigned char b1, int raw_len)
{
	size_t total = raw_len >= 0 ? NLA_HDRLEN : NLA_HDRLEN + payload_len;
	struct nlattr *a = (struct nlattr *)malloc(total);

	a->nla_len = raw_len >= 0 ? (unsigned short)raw_len : (unsigned short)(NLA_HDRLEN + payload_len);
	a->nla_type = (unsigned short)type;
	if (raw_len < 0) {
		unsigned char *p = (unsigned char *)a + NLA_HDRLEN;
		memset(p, 0xCC, payload_len);
		if (payload_len > 0) p[0] = b0;
		if (payload_len > 1) p[1] = b1;
	}
	return a;
}

static void poison(int on, const hwr_gem_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	size_t off = offsetof(struct eht_capabilities, mac_cap);

	if (t->eht_mode) {
		fn(&eht, off);
		fn((char *)&eht + off + sizeof(eht.mac_cap), sizeof(eht) - off - sizeof(eht.mac_cap));
	}
	if (t->tb_mode) {
		for (int i = 0; i < NTB; i++) if (i != NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC) fn(&tb_arr[i], sizeof(tb_arr[i]));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
void test_wifi_drv_get_phy_eht_cap_mac(const hwr_gem_case_t *t)
{
	struct eht_capabilities *e = t->eht_mode ? &eht : NULL;
	struct nlattr **tb = t->tb_mode ? tb_arr : NULL;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) hwr_wifi_drv_get_phy_eht_cap_mac(e, tb);
	poison(0, t);
}

static void setup(const hwr_gem_case_t *t)
{
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&eht, 0xA5, sizeof(eht));
	eht.mac_cap = PRESET_MAC;
	memcpy(&eht_before, &eht, sizeof(eht));
	memset(tb_arr, 0, sizeof(tb_arr));
	attr_blk = he_blk = phy_blk = NULL;
	if (t->attr) {
		attr_blk = make_attr(NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, t->payload_len, t->b0, t->b1, t->raw_nla_len);
		tb_arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] = attr_blk;
	}
	if (t->others) {
		he_blk = make_attr(NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, 6, 0x11, 0x22, -1);
		phy_blk = make_attr(NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, 9, 0x33, 0x44, -1);
		tb_arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC] = he_blk;
		tb_arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY] = phy_blk;
	}
}

static int check(const hwr_gem_case_t *t)
{
	unsigned short want = PRESET_MAC;

	if (t->attr && t->raw_nla_len < 0 && t->payload_len >= 2) want = (unsigned short)((t->b1 << 8) | t->b0);
	if (t->eht_mode) {
		if (eht.mac_cap != want) { snprintf(why, sizeof(why), "mac_cap 0x%04x, expected 0x%04x", eht.mac_cap, want); return 0; }
		if (memcmp(&eht.eht_supported, &eht_before.eht_supported, sizeof(eht.eht_supported)) != 0 ||
		    memcmp(eht.phy_cap, eht_before.phy_cap, sizeof(eht.phy_cap)) != 0 ||
		    memcmp(eht.mcs, eht_before.mcs, sizeof(eht.mcs)) != 0 ||
		    memcmp(eht.ppet, eht_before.ppet, sizeof(eht.ppet)) != 0) { snprintf(why, sizeof(why), "a field other than mac_cap was modified"); return 0; }
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static int run_one(const hwr_gem_case_t *t)
{
	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	test_wifi_drv_get_phy_eht_cap_mac(t);
	int ok = check(t);

	free(attr_blk); free(he_blk); free(phy_blk);
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m %s =====\n", t->test_name, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_wifi_drv_get_phy_eht_cap_mac(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, crash rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; wifi_drv_get_phy_eht_cap_mac_suite[i].test_name != NULL; i++) {
			if (wifi_drv_get_phy_eht_cap_mac_suite[i].last != last) continue;
			if (run_one(&wifi_drv_get_phy_eht_cap_mac_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_drv_get_phy_eht_cap_mac: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
