/*
 * TEST RUNNER: wifi_sendActionFrameExt_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_sendActionFrameExt() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests then compares the return value and what reached the driver stub.  The runner owns the caller's frame (a 65600-byte slab of which
 * exactly len bytes are valid) and MacAddr (a 16-byte slab of which 6 bytes are valid).  During the call it POISONS the frame tail [len, 65600), the
 * MacAddr tail [6, 16), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ): a read past len / past the 6-byte MAC, or a log write past
 * the slot aborts under ASan.  The 24 + len byte heap buffer of the function is guarded by ASan itself (a read of its byte 24 when len == 0 aborts).
 * Checks: return value, number of wifi_drv_send_mlme calls, the length / frequency / wait / noack / no_encrypt / csa handed to it, the 802.11 header
 * (frame control 0x00D0, addr1 = MacAddr, addr2 = interface MAC, addr3 = broadcast, duration and sequence 0), the payload copied to offset 24 and
 * the category byte seen by the driver.  Rows with crash = 1 crash the original function: they run LAST, so on the original code every other row has
 * reported before the ASan abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_sae.h"
#include <sanitizer/asan_interface.h>

#define FRAME_SLAB 65600
static unsigned char frame_slab[FRAME_SLAB];
static unsigned char mac_slab[16];
static sae_interface_t iface_obj;
static char why[200];

static void poison(int on, const hwr_sae_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->frame_mode) fn(&frame_slab[t->len], FRAME_SLAB - t->len);
	if (t->mac_mode) fn(&mac_slab[6], sizeof(mac_slab) - 6);
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what wifi_sendActionFrameExt returned */
int test_wifi_sendActionFrameExt(const hwr_sae_case_t *t)
{
	UCHAR *frame = t->frame_mode ? frame_slab : NULL;
	unsigned char *mac = t->mac_mode ? mac_slab : NULL;

	poison(1, t);
	int ret = hwr_wifi_sendActionFrameExt(t->ap_index, mac, t->freq, t->wait, frame, t->len);
	poison(0, t);
	return ret;
}

static void setup(const hwr_sae_case_t *t)
{
	static const unsigned char imac[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };

	memset(&hwr_sae_world, 0, sizeof(hwr_sae_world));
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	for (unsigned i = 0; i < FRAME_SLAB; i++) frame_slab[i] = (unsigned char)(i * 7 + 3);
	memset(mac_slab, 0x5A, sizeof(mac_slab));
	for (int i = 0; i < 6; i++) mac_slab[i] = 0x10 * (i + 1);
	memset(&iface_obj, 0, sizeof(iface_obj));
	memcpy(iface_obj.mac, imac, 6); iface_obj.index = 7;
	iface_obj.vap_index = (t->has_iface == 2) ? (unsigned)t->ap_index + 1u : (unsigned)t->ap_index;
	hwr_sae_world.iface = t->has_iface ? &iface_obj : NULL;
	hwr_sae_world.mlme_rc = t->mlme_rc; hwr_sae_world.fail_alloc = t->fail_alloc;
}

static int check(const hwr_sae_case_t *t, int ret)
{
	sae_world_t *w = &hwr_sae_world;
	const sae_hdr_t *h = (const sae_hdr_t *)w->mlme_frame;
	static const unsigned char bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (w->mlme_calls != t->exp_calls) { snprintf(why, sizeof(why), "%d wifi_drv_send_mlme calls, expected %d", w->mlme_calls, t->exp_calls); return 0; }
	if (!t->exp_calls) return 1;
	if (w->mlme_len != 24 + (size_t)t->len) { snprintf(why, sizeof(why), "frame length %zu handed on, expected %u", w->mlme_len, 24 + t->len); return 0; }
	if (w->mlme_freq != t->freq) { snprintf(why, sizeof(why), "freq %u handed on, expected %u", w->mlme_freq, t->freq); return 0; }
	if (w->mlme_wait != t->wait) { snprintf(why, sizeof(why), "wait %u handed on, expected %u", w->mlme_wait, t->wait); return 0; }
	if (w->mlme_noack != 1 || w->mlme_no_encrypt != 0 || w->mlme_csa) { snprintf(why, sizeof(why), "noack %d no_encrypt %d csa %d, expected 1 0 0", w->mlme_noack, w->mlme_no_encrypt, w->mlme_csa); return 0; }
	if (h->frame_control != 0x00D0) { snprintf(why, sizeof(why), "frame control 0x%04x, expected 0x00d0", h->frame_control); return 0; }
	if (h->duration_id != 0 || h->seq_ctrl != 0) { snprintf(why, sizeof(why), "duration / sequence not zero"); return 0; }
	if (memcmp(h->addr1, mac_slab, 6) != 0) { snprintf(why, sizeof(why), "addr1 is not MacAddr"); return 0; }
	if (memcmp(h->addr2, iface_obj.mac, 6) != 0) { snprintf(why, sizeof(why), "addr2 is not the interface MAC"); return 0; }
	if (memcmp(h->addr3, bc, 6) != 0) { snprintf(why, sizeof(why), "addr3 is not broadcast"); return 0; }
	if (t->len && memcmp(w->mlme_frame + 24, frame_slab, t->len) != 0) { snprintf(why, sizeof(why), "payload not copied to offset 24"); return 0; }
	if (t->len && w->mlme_cat != frame_slab[0]) { snprintf(why, sizeof(why), "driver saw category %u, expected %u", w->mlme_cat, frame_slab[0]); return 0; }
	return 1;
}

static int run_one(const hwr_sae_case_t *t)
{
	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	int ret = test_wifi_sendActionFrameExt(t);
	int ok = check(t, ret);

	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, ret, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_wifi_sendActionFrameExt(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, crash rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; wifi_sendActionFrameExt_suite[i].test_name != NULL; i++) {
			if (wifi_sendActionFrameExt_suite[i].crash != last) continue;
			if (run_one(&wifi_sendActionFrameExt_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_sendActionFrameExt: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
