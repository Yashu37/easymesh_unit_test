/*
 * TEST RUNNER: sg_wifi_hal_cancelRMBeaconRequest_test
 *
 * test_sg_wifi_hal_cancelRMBeaconRequest() POISONS what the function must not touch, calls the handler and unpoisons: the g_DialogToken rows of every VAP except the one the function may update (the sending
 * VAP, known from the preset tables), the other 64-bit words of that row, the g_DialogTokenSender bytes of every token except the one cancelled (all of both tables when apIndex is rejected), the guard slab and
 * the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The tables are preset and compared with CORRECT 64-bit bit operations (1UL << n), independent of the handler's helpers, against a reference model of the CORRECT
 * behaviour (see the construct file): return value, requested bits, sender records, the lock released, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wcb.h"
#include <sanitizer/asan_interface.h>

#define NV HWR_WCB_MAXV
static char why[240];
static int ret_val;
static unsigned long (*bm)[4];
static unsigned char (*snd)[256];

static int bad(const hwr_wcb_case_t *t) { return t->apIndex >= (unsigned)NV; }
static int get_bit(int v, unsigned tok) { return (bm[v][tok / 64] >> (tok % 64)) & 1UL; }
static void put_bit(int v, unsigned tok, int on) { if (on) bm[v][tok / 64] |= 1UL << (tok % 64); else bm[v][tok / 64] &= ~(1UL << (tok % 64)); }
static int pre_sender(const hwr_wcb_case_t *t, int vap)
{
	for (int k = 0; k < 3; k++) if (t->s_orig[k] == vap) return t->s_sent[k] + 1;
	return 0;
}
static int sent_vap(const hwr_wcb_case_t *t) { int s = pre_sender(t, (int)t->apIndex); return s ? s - 1 : (int)t->apIndex; }

static void poison(int on, const hwr_wcb_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (bad(t)) {
		fn(bm, sizeof(unsigned long) * 4 * NV); fn(snd, 256 * NV);
	} else {
		int sv = sent_vap(t);
		for (int v = 0; v < NV; v++) {
			if (v != sv) fn(bm[v], sizeof(bm[v]));
			else for (int w = 0; w < 4; w++) if (w != (int)(t->token / 64)) fn(&bm[v][w], sizeof(bm[v][w]));
			if (t->token > 0) fn(snd[v], t->token);
			if (t->token < 255) fn(&snd[v][t->token + 1], 255 - t->token);
		}
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_cancelRMBeaconRequest(const hwr_wcb_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_cancelRMBeaconRequest(t->apIndex, (UCHAR)t->token);
	poison(0, t);
}

static int check(const hwr_wcb_case_t *t)
{
	int want_ret = bad(t) ? WIFI_HAL_INVALID_ARGUMENTS : WIFI_HAL_SUCCESS;

	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	/* the reference model, from the preset state */
	int exp_bit[NV], exp_other[NV], exp_snd[NV];
	for (int v = 0; v < NV; v++) {
		exp_bit[v] = (t->bits_mask >> v) & 1;
		exp_other[v] = (t->other_token >= 0 && v == (int)(bad(t) ? 0 : t->apIndex)) ? 1 : 0;
		exp_snd[v] = pre_sender(t, v);
	}
	if (t->other_token >= 0 && bad(t)) exp_other[0] = 1;
	if (!bad(t)) {
		int sent = (int)t->apIndex;
		if (exp_snd[t->apIndex]) { sent = exp_snd[t->apIndex] - 1; exp_snd[t->apIndex] = 0; }
		int keep = 0;
		for (int v = 0; v < NV; v++) if (exp_snd[v] == sent + 1) keep = 1;
		if (!keep) exp_bit[sent] = 0;
	}
	for (int v = 0; v < NV; v++) {
		if (get_bit(v, t->token) != exp_bit[v]) { snprintf(why, sizeof(why), "requested bit of token %u on VAP %d is %d, expected %d", t->token, v, get_bit(v, t->token), exp_bit[v]); return 0; }
		if (snd[v][t->token] != exp_snd[v]) { snprintf(why, sizeof(why), "sender record [%d][%u] is %d, expected %d", v, t->token, snd[v][t->token], exp_snd[v]); return 0; }
		if (t->other_token >= 0 && get_bit(v, (unsigned)t->other_token) != exp_other[v]) { snprintf(why, sizeof(why), "bit of the other token %d on VAP %d is %d, expected %d", t->other_token, v, get_bit(v, (unsigned)t->other_token), exp_other[v]); return 0; }
	}
	if (!hwr_wcb_lock_free()) { snprintf(why, sizeof(why), "hapd_lock still locked"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wcb_case_t *t)
{
	void *b; size_t row; unsigned char *s;

	hwr_wcb_reset_tables();
	hwr_wcb_tables(&b, &row, &s);
	bm = (unsigned long (*)[4])b; snd = (unsigned char (*)[256])s;
	for (int v = 0; v < NV; v++) if ((t->bits_mask >> v) & 1) put_bit(v, t->token, 1);
	for (int k = 0; k < 3; k++) if (t->s_orig[k] >= 0) snd[t->s_orig[k]][t->token] = (unsigned char)(t->s_sent[k] + 1);
	if (t->other_token >= 0) put_bit(bad(t) ? 0 : (int)t->apIndex, (unsigned)t->other_token, 1);
}

extern "C" void run_all_tests_sg_wifi_hal_cancelRMBeaconRequest(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_cancelRMBeaconRequest_suite[i].test_name != NULL; i++) {
			hwr_wcb_case_t *test = &sg_wifi_hal_cancelRMBeaconRequest_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_cancelRMBeaconRequest(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_cancelRMBeaconRequest: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
