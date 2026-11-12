/*
 * TEST RUNNER: sg_wifi_dppTestFrameHandler_test
 *
 * test_sg_wifi_dppTestFrameHandler() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The function's own buffers (cmd, interface_name[32], bmac[6], frame[1024], msg[1024]) are stack objects with ASan red zones, so an overflow of any of them - and get_tlv
 * reading past msg - is reported by ASan itself.  The datagrams are built from the case table (signature + TLVs, optional filler TLVs up to 1024 bytes, optional truncation) and fed by the scripted stubs;
 * the stubs end the function's endless loop by throwing (2) once every datagram is consumed, a select that keeps failing throws (1) after 1000 calls (hang).  run_all_tests compares the callback calls with a
 * reference model of the CORRECT behaviour (see the construct file).  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wtd.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static void *ret_val; static int arg_marker, g_ended;
extern unsigned char hwr_wtd_sig[8];

static unsigned char pat(int seed, unsigned k) { return (unsigned char)(seed * 17 + k * 3 + 1); }

static unsigned build(const hwr_wtd_dg_t *d, unsigned char *out)
{
	unsigned p = 0;

	memcpy(out, hwr_wtd_sig, 8);
	if (!d->sig_ok) out[0] ^= 0xFF;
	p = 8;
	for (int i = 0; i < d->n; i++) {
		const hwr_wtd_tlv_t *t = &d->t[i];
		out[p++] = t->type & 0xff; out[p++] = t->type >> 8; out[p++] = t->len & 0xff; out[p++] = t->len >> 8;
		for (unsigned k = 0; k < t->len; k++) {
			unsigned char b;
			if (t->type == 0) b = k < 4 ? (unsigned char)((t->val == 0 ? wifi_test_command_id_chirp : t->val == 1 ? wifi_test_command_id_reconf_auth_resp : t->val == 2 ? wifi_test_command_id_anqp : wifi_test_command_id_mgmt) >> (8 * k)) : 0;
			else if (t->type == 1) { char nm[8]; if (t->val < 0) snprintf(nm, sizeof(nm), "eth0"); else snprintf(nm, sizeof(nm), "ath%d", t->val); b = k <= strlen(nm) && k < sizeof(nm) ? (unsigned char)nm[k] : 0; }
			else b = pat(t->val, k);
			out[p++] = b;
		}
	}
	while (d->total && p + 4 <= d->total) { out[p++] = 99; out[p++] = 0; out[p++] = 0; out[p++] = 0; }
	return d->cut ? d->cut : p;
}

/* does the model say this datagram must reach the callback; fills the expected values */
static int expect_cb(const hwr_wtd_dg_t *d, int *ap, unsigned char *mac, unsigned char *raw, unsigned *rawlen)
{
	const hwr_wtd_tlv_t *c = NULL, *v = NULL, *m = NULL, *r = NULL;

	if (!d->sig_ok || d->cut) return 0;
	for (int i = 0; i < d->n; i++) {
		const hwr_wtd_tlv_t *t = &d->t[i];
		if (t->type == 0 && !c) c = t; else if (t->type == 1 && !v) v = t; else if (t->type == 2 && !m) m = t; else if (t->type == 4 && !r) r = t;
	}
	if (!c || !v || !m || !r) return 0;
	{ unsigned tot = 8; for (int i = 0; i < d->n; i++) tot += 4 + d->t[i].len; if (tot > 1024) return 0; }   /* recvfrom delivers at most 1024 bytes: a TLV that is not completely inside is not valid */
	if (c->len != 4 || c->val >= 2) return 0;
	if (v->len < 1 || v->len > 31 || v->val < 0) return 0;
	if (m->len != 6 || r->len > 1024) return 0;
	*ap = v->val; for (int k = 0; k < 6; k++) mac[k] = pat(m->val, k);
	for (unsigned k = 0; k < r->len; k++) raw[k] = pat(r->val, k);
	*rawlen = r->len;
	return 1;
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wtd_world.unrelated, sizeof(hwr_wtd_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_dppTestFrameHandler(const hwr_wtd_case_t *t)
{
	poison(1);
	g_ended = 0; ret_val = (void *)1;
	try { ret_val = hwr_sg_wifi_dppTestFrameHandler(&arg_marker); } catch (int e) { g_ended = e; }
	poison(0);
}

static int check(const hwr_wtd_case_t *t)
{
	const hwr_wtd_world_t *w = &hwr_wtd_world;
	int want_cb = 0;

	if (t->noaccess || t->socket_fail || t->selfail) {
		if (g_ended == 1) { snprintf(why, sizeof(why), "busy loop: a failing select never ends the loop (1000 failed select calls)"); return 0; }
		if (g_ended == 2 || ret_val != NULL) { snprintf(why, sizeof(why), "did not return NULL (ended=%d, returned %p)", g_ended, ret_val); return 0; }
		if (t->selfail && w->closes != 1) { snprintf(why, sizeof(why), "socket closed %d times after the select failure, expected 1", w->closes); return 0; }
		if (!t->selfail && w->closes != 0) { snprintf(why, sizeof(why), "closed a socket that was never opened"); return 0; }
		if (w->cb_calls != 0) { snprintf(why, sizeof(why), "callback called %d times", w->cb_calls); return 0; }
		return 1;
	}
	if (g_ended != 2) { snprintf(why, sizeof(why), "the loop ended by itself (ended=%d, returned %p)", g_ended, ret_val); return 0; }
	for (int d = 0; d < t->ndg; d++) {
		int ap; unsigned char mac[6], raw[1100]; unsigned rl = 0;
		if (!expect_cb(&t->dg[d], &ap, mac, raw, &rl)) continue;
		if (want_cb >= HWR_WTD_MAXCB || want_cb >= w->cb_calls) { want_cb++; continue; }
		if (w->cb_ap[want_cb] != ap) { snprintf(why, sizeof(why), "callback %d got ap %d, expected %d", want_cb, w->cb_ap[want_cb], ap); return 0; }
		if (memcmp(w->cb_mac[want_cb], mac, 6) != 0) { snprintf(why, sizeof(why), "callback %d got a different mac", want_cb); return 0; }
		if (memcmp(w->cb_frame[want_cb], raw, rl < 128 ? rl : 128) != 0) { snprintf(why, sizeof(why), "callback %d got different frame bytes", want_cb); return 0; }
		if (w->cb_type[want_cb] != WIFI_MGMT_FRAME_TYPE_ACTION || w->cb_dir[want_cb] != wifi_direction_uplink) { snprintf(why, sizeof(why), "callback %d got wrong type / direction", want_cb); return 0; }
		if (t->chk_len && w->cb_len[want_cb] != rl) { snprintf(why, sizeof(why), "callback %d got frame length %u, expected %u", want_cb, w->cb_len[want_cb], rl); return 0; }
		want_cb++;
	}
	if (w->cb_calls != want_cb) { snprintf(why, sizeof(why), "callback called %d times, expected %d", w->cb_calls, want_cb); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wtd_case_t *t)
{
	hwr_wtd_world_t *w = &hwr_wtd_world;

	memset(w, 0, sizeof(*w));
	w->ndg = t->ndg; w->socket_fail = t->socket_fail; w->noaccess = t->noaccess; w->selfail = t->selfail; w->sel0 = t->sel0; w->recvfail = t->recvfail;
	for (int d = 0; d < t->ndg; d++) w->dglen[d] = build(&t->dg[d], w->dgbuf[d]);
}

extern "C" void run_all_tests_sg_wifi_dppTestFrameHandler(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppTestFrameHandler_suite[i].test_name != NULL; i++) {
			hwr_wtd_case_t *test = &sg_wifi_dppTestFrameHandler_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppTestFrameHandler(test);

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
	printf("\nwifi_dppTestFrameHandler: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
