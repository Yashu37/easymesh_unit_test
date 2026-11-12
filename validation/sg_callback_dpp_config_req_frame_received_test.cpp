/*
 * TEST RUNNER: sg_callback_dpp_config_req_frame_received_test
 *
 * test_sg_callback_dpp_config_req_frame_received() POISONS what the function must not touch, calls the handler and unpoisons (once per call): the callbacks table members before and after the five DPP
 * slots, the other four DPP callback slots (only dpp_config_req_callback may be read), the whole attribute buffer (the function only forwards the pointer; the mock callback only records it), the
 * guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the call record of the mock with a reference model of the CORRECT behaviour (see the construct file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wcf.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static struct { int calls; UINT ap[2]; unsigned char sta[2][6]; UCHAR token[2]; UCHAR *attrib[2]; UINT len[2]; } rec;
static int other_calls;
static unsigned char *g_attr;

extern "C" void hwr_wcf_mock_cfgreq(UINT apIndex, mac_address_t sta, UCHAR token, UCHAR *attribs, UINT length)
{
	if (rec.calls < 2) {
		rec.ap[rec.calls] = apIndex; memcpy(rec.sta[rec.calls], sta, 6); rec.token[rec.calls] = token; rec.attrib[rec.calls] = attribs; rec.len[rec.calls] = length;
	}
	rec.calls++;
}
extern "C" void hwr_wcf_mock_other(void) { other_calls++; }

static void poison(const hwr_wcf_case_t *t, int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	wifi_device_callbacks_t *c = &hwr_wcf_world.cbs;

	fn(c->before, sizeof(c->before)); fn(c->after, sizeof(c->after));
	fn(&c->dpp_auth_rsp_callback, sizeof(c->dpp_auth_rsp_callback));
	fn(&c->dpp_config_result_callback, 3 * sizeof(void *));
	if (g_attr && t->attrlen > 0) fn(g_attr, (size_t)t->attrlen);
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void setup(const hwr_wcf_case_t *t)
{
	memset(&rec, 0, sizeof(rec)); other_calls = 0;
	memset(&hwr_wcf_world, 0, sizeof(hwr_wcf_world));
	hwr_wcf_world.cbs.before[0] = (void *)0x11; hwr_wcf_world.cbs.before[1] = (void *)0x12;
	hwr_wcf_world.cbs.after[0] = (void *)0x21; hwr_wcf_world.cbs.after[1] = (void *)0x22;
	if (t->registered) hwr_wcf_world.cbs.dpp_config_req_callback = hwr_wcf_mock_cfgreq;
	if (t->others) {
		hwr_wcf_world.cbs.dpp_auth_rsp_callback = (wifi_dppAuthResponse_callback_t)hwr_wcf_mock_other;
		hwr_wcf_world.cbs.dpp_config_result_callback = (wifi_dppConfigResult_callback_t)hwr_wcf_mock_other;
		hwr_wcf_world.cbs.dpp_reconfig_announce_callback = (wifi_dppReconfigAnnounce_callback_t)hwr_wcf_mock_other;
		hwr_wcf_world.cbs.dpp_reconfig_auth_rsp_callback = (wifi_dppReconfigAuthResponse_callback_t)hwr_wcf_mock_other;
	}
	g_attr = NULL;
	if (t->attrlen >= 0) { size_t a = t->attrlen ? (size_t)t->attrlen : 1; g_attr = (unsigned char *)malloc(a); for (size_t i = 0; i < a; i++) g_attr[i] = (unsigned char)(0x30 + i); }
}

static void sta_for(const hwr_wcf_case_t *t, mac_address_t m)
{
	for (int i = 0; i < 6; i++) m[i] = (t->sta == 0) ? 0 : (t->sta == 2) ? 0xFF : (unsigned char)(0xA0 + i);
}

/* poison, call, unpoison (once per call) */
static void test_sg_callback_dpp_config_req_frame_received(const hwr_wcf_case_t *t)
{
	mac_address_t sta; sta_for(t, sta);
	for (int n = 0; n < t->calls; n++) {
		poison(t, 1);
		hwr_sg_callback_dpp_config_req_frame_received(t->ap_index + n, sta, (unsigned char)t->token, g_attr, (unsigned int)(t->attrlen < 0 ? 0 : t->attrlen) + t->len_extra);
		poison(t, 0);
	}
}

static int check(const hwr_wcf_case_t *t)
{
	const wifi_device_callbacks_t *c = &hwr_wcf_world.cbs;
	mac_address_t sta; sta_for(t, sta);
	int want = t->registered ? t->calls : 0;

	if (rec.calls != want) { snprintf(why, sizeof(why), "callback called %d times, expected %d", rec.calls, want); return 0; }
	for (int n = 0; n < want; n++) {
		if (rec.ap[n] != (UINT)(t->ap_index + n)) { snprintf(why, sizeof(why), "call %d: ap_index %u", n, rec.ap[n]); return 0; }
		if (memcmp(rec.sta[n], sta, 6) != 0) { snprintf(why, sizeof(why), "call %d: sta mac differs", n); return 0; }
		if (rec.token[n] != (UCHAR)t->token) { snprintf(why, sizeof(why), "call %d: token %u", n, rec.token[n]); return 0; }
		if (rec.attrib[n] != g_attr) { snprintf(why, sizeof(why), "call %d: attrib pointer differs", n); return 0; }
		if (rec.len[n] != (UINT)(t->attrlen < 0 ? 0 : t->attrlen) + t->len_extra) { snprintf(why, sizeof(why), "call %d: length %u", n, rec.len[n]); return 0; }
	}
	if (other_calls) { snprintf(why, sizeof(why), "another DPP callback was called"); return 0; }
	if (c->before[0] != (void *)0x11 || c->before[1] != (void *)0x12 || c->after[0] != (void *)0x21 || c->after[1] != (void *)0x22) { snprintf(why, sizeof(why), "neighbouring table members modified"); return 0; }
	if ((c->dpp_config_req_callback != NULL) != (t->registered != 0)) { snprintf(why, sizeof(why), "dpp_config_req_callback slot modified"); return 0; }
	if (hwr_wcf_world.accessor_calls != t->calls) { snprintf(why, sizeof(why), "accessor ran %d times, expected %d", hwr_wcf_world.accessor_calls, t->calls); return 0; }
	if (g_attr) { size_t a = t->attrlen ? (size_t)t->attrlen : 1; for (size_t i = 0; i < a; i++) if (g_attr[i] != (unsigned char)(0x30 + i)) { snprintf(why, sizeof(why), "attribute buffer modified"); return 0; } }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_callback_dpp_config_req_frame_received(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_callback_dpp_config_req_frame_received_suite[i].test_name != NULL; i++) {
			hwr_wcf_case_t *test = &sg_callback_dpp_config_req_frame_received_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_callback_dpp_config_req_frame_received(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
			free(g_attr); g_attr = NULL;
		}
	printf("\ncallback_dpp_config_req_frame_received: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
