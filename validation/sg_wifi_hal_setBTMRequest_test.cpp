/*
 * TEST RUNNER: sg_wifi_hal_setBTMRequest_test
 *
 * test_sg_wifi_hal_setBTMRequest() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots other than the addressed one, request->url[] after the URL (and the whole
 * array when urlLen is 0), request->candidates[] from numCandidates on (all of them, and numCandidates itself, when the candidate flag is off), the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  request is an exact heap block of sizeof(wifi_BTMRequest_t), so a read past it is a heap-buffer-overflow.  run_all_tests compares the result with a reference model of the CORRECT
 * behaviour (see the construct file): return value, the request sent (station, token, mode, timer, validity, BSS termination bytes, URL, neighbour list), the token written back, mutex released, allocator balance,
 * guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include "hwr_wbt.h"
#include <sanitizer/asan_interface.h>

#define PC 0x01
#define TD 0x08
#define ES 0x10
#define NEI_ENT 18
static char why[240];
static int ret_val;
static wifi_BTMRequest_t *req;
static unsigned char peer[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
static const unsigned long long TSF = 0x1122334455667788ULL;

static int args_bad(const hwr_wbt_case_t *t) { return t->peer_null || t->req_null; }
static int url_flag_in(const hwr_wbt_case_t *t) { return (t->mode & ES) && t->urlLen && !(t->url_kind == 1); }

/* the reference model of the correct behaviour */
struct model {
	int ret, sent, mode, ncand_bytes, nei_null, url_null; size_t url_len; unsigned token_after; int mallocs;
};
static model run_model(const hwr_wbt_case_t *t)
{
	model m = {};
	m.token_after = t->token;
	if (args_bad(t)) { m.ret = WIFI_HAL_INVALID_ARGUMENTS; return m; }
	if (t->apIndex >= HWR_WBT_MAXI || t->vap_sta || t->no_sta) { m.ret = WIFI_HAL_ERROR; return m; }
	unsigned mode = t->mode & 0xFF;
	if (!t->dur) mode &= ~(unsigned)TD;
	int call = 0;
	m.nei_null = 1;
	if (mode & PC) {
		call++;
		if (t->malloc_fail_at == call) { m.ret = WIFI_HAL_ERROR; m.mallocs = call; return m; }
		if (t->ncand >= 64) { m.ret = WIFI_HAL_ERROR; m.mallocs = call; return m; }
		if (t->ncand == 0) mode &= ~(unsigned)PC; else { m.nei_null = 0; m.ncand_bytes = t->ncand * NEI_ENT; }
	}
	if (!url_flag_in(t)) mode &= ~(unsigned)ES;
	m.url_null = 1;
	if (mode & ES) {
		call++;
		if (t->malloc_fail_at == call) { m.ret = WIFI_HAL_ERROR; m.mallocs = call; return m; }
		size_t avail = t->url_kind == 2 ? 512 : (t->urlLen < 511 ? t->urlLen : 511);
		m.url_len = t->urlLen < avail ? t->urlLen : avail;
		m.url_null = 0;
	}
	m.mallocs = call;
	m.sent = 1; m.mode = mode;
	m.ret = t->send_ret < 0 ? WIFI_HAL_ERROR : WIFI_HAL_SUCCESS;
	if (t->send_ret > 0 && t->token == 0) m.token_after = t->send_ret;
	return m;
}

static void poison(int on, const hwr_wbt_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wbt_world_t *w = &hwr_wbt_world;

	for (int i = 0; i < HWR_WBT_MAXI; i++) if (args_bad(t) || i != (int)t->apIndex) fn(&w->ifs[i], sizeof(w->ifs[i]));
	if (req && t->url_kind != 2) {
		unsigned ul = req->urlLen;
		size_t from = ul == 0 ? 0 : (size_t)ul + 1;
		if (from < sizeof(req->url)) fn(&req->url[from], sizeof(req->url) - from);
		unsigned flag_pc = req->requestMode & PC;
		if (!flag_pc) { fn(&req->numCandidates, sizeof(req->numCandidates)); fn(req->candidates, sizeof(req->candidates)); }
		else if (req->numCandidates < 64) fn(&req->candidates[req->numCandidates], (64 - req->numCandidates) * sizeof(req->candidates[0]));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_setBTMRequest(const hwr_wbt_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_setBTMRequest(t->apIndex, t->peer_null ? NULL : peer, t->req_null ? NULL : req);
	poison(0, t);
}

static int check(const hwr_wbt_case_t *t)
{
	const hwr_wbt_world_t *w = &hwr_wbt_world;
	model m = run_model(t);

	if (ret_val != m.ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, m.ret); return 0; }
	if (w->send_calls != m.sent) { snprintf(why, sizeof(why), "send ran %d times, expected %d", w->send_calls, m.sent); return 0; }
	if (w->malloc_calls != m.mallocs) { snprintf(why, sizeof(why), "malloc ran %d times, expected %d", w->malloc_calls, m.mallocs); return 0; }
	if (w->live_alloc != 0) { snprintf(why, sizeof(why), "allocator balance %d (leak)", w->live_alloc); return 0; }
	if (pthread_mutex_trylock((pthread_mutex_t *)&w->hal.hapd_lock) != 0) { snprintf(why, sizeof(why), "hapd_lock still locked"); return 0; }
	pthread_mutex_unlock((pthread_mutex_t *)&w->hal.hapd_lock);
	if (m.sent) {
		if (!w->mutex_held_at_send) { snprintf(why, sizeof(why), "hapd_lock not held during the send"); return 0; }
		if (w->send_sta != &w->sta) { snprintf(why, sizeof(why), "wrong station"); return 0; }
		if (w->send_token != (t->token & 0xFF) || w->send_timer != 0x1234 || w->send_valid != 0x56) { snprintf(why, sizeof(why), "token / timer / validity wrong"); return 0; }
		if ((int)w->send_mode != m.mode) { snprintf(why, sizeof(why), "mode 0x%x, expected 0x%x", w->send_mode, m.mode); return 0; }
		u8 term[12] = {0};
		if (m.mode & TD) { term[0] = 4; term[1] = 10; for (int k = 0; k < 8; k++) term[2 + k] = (u8)(TSF >> (8 * k)); term[10] = (u8)t->dur; term[11] = (u8)(t->dur >> 8); }
		if (memcmp(term, w->send_term, 12) != 0) { snprintf(why, sizeof(why), "BSS termination bytes wrong"); return 0; }
		if (w->send_url_null != m.url_null) { snprintf(why, sizeof(why), "url NULL-ness wrong"); return 0; }
		if (!m.url_null) {
			char want[1100];
			memset(want, t->url_kind == 2 ? 'A' : 'u', m.url_len); want[m.url_len] = '\0';
			if (strcmp(w->send_url, want) != 0) { snprintf(why, sizeof(why), "url wrong (len %zu, expected %zu)", strlen(w->send_url), m.url_len); return 0; }
		}
		if (w->send_nei_null != m.nei_null || w->send_nei_len != m.ncand_bytes) { snprintf(why, sizeof(why), "neighbour list length %d, expected %d", w->send_nei_len, m.ncand_bytes); return 0; }
		for (unsigned i = 0; i < t->ncand && !m.nei_null; i++) {
			const u8 *e = &w->send_nei[i * NEI_ENT];
			unsigned info = 0x01020304u + i;
			u8 want[NEI_ENT] = { 52, 16, (u8)(i + 1), 2, 3, 4, 5, 6, (u8)info, (u8)(info >> 8), (u8)(info >> 16), (u8)(info >> 24), 81, (u8)(i + 1), 7, 3, 1, (u8)(255 - i) };
			if (memcmp(e, want, NEI_ENT) != 0) { snprintf(why, sizeof(why), "neighbour entry %u wrong", i); return 0; }
		}
	}
	if (!t->req_null && req->token != (UCHAR)m.token_after) { snprintf(why, sizeof(why), "request->token is %u, expected %u", req->token, m.token_after); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wbt_case_t *t)
{
	hwr_wbt_world_t *w = &hwr_wbt_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	memcpy(w->known_mac, peer, 6);
	w->no_sta = t->no_sta; w->malloc_fail_at = t->malloc_fail_at; w->send_ret = t->send_ret;
	for (int i = 0; i < HWR_WBT_MAXI; i++) w->ifs[i].vap_info.vap_mode = (i == (int)t->apIndex && t->vap_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
	req = NULL;
	if (!t->req_null) {
		req = (wifi_BTMRequest_t *)malloc(sizeof(wifi_BTMRequest_t));
		if (t->url_kind == 2) memset(req, 'A', sizeof(*req)); else memset(req, 0, sizeof(*req));
		req->token = (UCHAR)t->token; req->requestMode = (UCHAR)t->mode; req->timer = 0x1234; req->validityInterval = 0x56;
		req->termDuration.duration = t->dur; req->termDuration.tsf = TSF;
		req->urlLen = (USHORT)t->urlLen;
		if (t->url_kind != 1 && t->url_kind != 2) for (unsigned i = 0; i < t->urlLen && i < 511; i++) req->url[i] = 'u';
		if (t->url_kind == 1) req->url[0] = '\0';
		if (t->url_kind != 2) {
			req->numCandidates = (UCHAR)t->ncand;
			for (unsigned i = 0; i < t->ncand && i < 64; i++) {
				wifi_NeighborReport_t *c = &req->candidates[i];
				static const unsigned char b[6] = { 0, 2, 3, 4, 5, 6 };
				memcpy(c->bssid, b, 6); c->bssid[0] = (unsigned char)(i + 1);
				c->info = 0x01020304u + i; c->opClass = 81; c->channel = (UCHAR)(i + 1); c->phyTable = 7;
			}
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_setBTMRequest(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_setBTMRequest_suite[i].test_name != NULL; i++) {
			hwr_wbt_case_t *test = &sg_wifi_hal_setBTMRequest_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_setBTMRequest(test);

			int ok = check(test);
			free(req); req = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_setBTMRequest: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
