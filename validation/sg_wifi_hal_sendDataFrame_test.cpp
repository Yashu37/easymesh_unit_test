/*
 * TEST RUNNER: sg_wifi_hal_sendDataFrame_test
 *
 * test_sg_wifi_hal_sendDataFrame() POISONS what the function must not touch, calls the handler and unpoisons: the elements of g_fd_arr / g_IfIdx_arr other than the one of vap_id (all of them, and g_vapSmac,
 * when the call must be rejected before the arrays are used: data_len above 1586 or below -14, vap_id out of range), the world's interface slots beyond the ones present, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  dmac (6 bytes) and data_buff
 * (data_len bytes) are exact heap blocks, so a read past them is a heap-buffer-overflow, and t_data is a stack array.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see
 * the construct file): return value, socket / bind / close / sendto call counts, the frame handed to sendto (addresses, ether type, payload, length) and its sockaddr_ll, the fd kept in g_fd_arr, guard slab
 * unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>
#include "hwr_wdf.h"
#include <sanitizer/asan_interface.h>

#define MAXV (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)
#define FRESH_FD 7
#define CACHED_FD 9
#define IF_INDEX 42
#define CACHED_IDX 77
static char why[240];
static int ret_val;
static unsigned char *dmac, *dbuf;
static const unsigned char if_mac[6] = { 0x02, 0x42, 0x42, 0x42, 0x42, 0x42 };
static const unsigned char cached_mac[6] = { 0x02, 0x77, 0x77, 0x77, 0x77, 0x77 };
static const unsigned char dst_mac[6] = { 0x02, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4 };

static int reject(const hwr_wdf_case_t *t)
{
	return t->data_len < 0 || t->data_len > 1586 || t->vap_id < 0 || t->vap_id >= MAXV || t->dmac_null || (t->data_null && t->data_len > 0);
}
static int fresh_ok(const hwr_wdf_case_t *t) { return !t->sock_fail && !t->no_iface && !t->bind_fail; }
static int sendto_reached(const hwr_wdf_case_t *t) { return !reject(t) && (t->cached || fresh_ok(t)); }
static int expect_ret(const hwr_wdf_case_t *t)
{
	if (!sendto_reached(t)) return RETURN_ERR;
	return t->sendto_mode == 0 ? RETURN_OK : RETURN_ERR;
}

static void poison(int on, const hwr_wdf_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wdf_world_t *w = &hwr_wdf_world;
	int *fd, *idx, max; unsigned char (*smac)[6];

	hwr_wdf_statics(&fd, &idx, &smac, &max);
	/* the original also rejects data_len > 1586 and data_len < -14 before the arrays are used; for the other rejected inputs (data_len -14..-1, NULL pointers) it uses them, so only the other elements are poisoned */
	if (t->data_len > 1586 || t->data_len < -14 || t->vap_id < 0 || t->vap_id >= MAXV) {
		fn(fd, max * sizeof(int)); fn(idx, max * sizeof(int)); fn(smac, max * 6);
	} else {
		for (int g = 0; g < max / 2; g++) if (g != t->vap_id / 2) { fn(&fd[2 * g], 8); fn(&idx[2 * g], 8); }
	}
	for (int k = w->n_if; k < HWR_WDF_MAXI; k++) fn(&w->ifs[k], sizeof(w->ifs[k]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_sendDataFrame(const hwr_wdf_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_sendDataFrame(t->vap_id, t->dmac_null ? NULL : dmac, t->data_null ? NULL : dbuf, t->data_len, 1, t->protocol, 0);
	poison(0, t);
}

static int check(const hwr_wdf_case_t *t)
{
	const hwr_wdf_world_t *w = &hwr_wdf_world;
	int want = expect_ret(t), rj = reject(t), fr = !rj && !t->cached;
	int *fd, *idx, max; unsigned char (*smac)[6];

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->socket_calls != (fr ? 1 : 0)) { snprintf(why, sizeof(why), "socket ran %d times, expected %d", w->socket_calls, fr ? 1 : 0); return 0; }
	if (w->bind_calls != ((fr && !t->sock_fail && !t->no_iface) ? 1 : 0)) { snprintf(why, sizeof(why), "bind ran %d times", w->bind_calls); return 0; }
	if (w->close_calls != ((fr && !t->sock_fail && (t->no_iface || t->bind_fail)) ? 1 : 0)) { snprintf(why, sizeof(why), "close ran %d times", w->close_calls); return 0; }
	if (w->sendto_calls != (sendto_reached(t) ? 1 : 0)) { snprintf(why, sizeof(why), "sendto ran %d times", w->sendto_calls); return 0; }
	if (sendto_reached(t)) {
		const unsigned char *src = t->cached ? cached_mac : if_mac;
		uint16_t et = htons((uint16_t)t->protocol);
		if (w->sent_len != 14 + t->data_len) { snprintf(why, sizeof(why), "frame length %d, expected %d", w->sent_len, 14 + t->data_len); return 0; }
		if (memcmp(w->sent, dst_mac, 6) != 0) { snprintf(why, sizeof(why), "destination MAC wrong"); return 0; }
		if (memcmp(w->sent + 6, src, 6) != 0) { snprintf(why, sizeof(why), "source MAC wrong"); return 0; }
		if (memcmp(w->sent + 12, &et, 2) != 0) { snprintf(why, sizeof(why), "ether type wrong"); return 0; }
		if (t->data_len > 0 && memcmp(w->sent + 14, dbuf, t->data_len) != 0) { snprintf(why, sizeof(why), "payload wrong"); return 0; }
		if (w->sent_ifindex != (t->cached ? CACHED_IDX : IF_INDEX) || w->sent_halen != 6 || memcmp(w->sent_addr, dst_mac, 6) != 0) { snprintf(why, sizeof(why), "sockaddr_ll wrong"); return 0; }
		if (w->sent_family != AF_PACKET || w->sent_fd != (t->cached ? CACHED_FD : FRESH_FD)) { snprintf(why, sizeof(why), "family / fd wrong"); return 0; }
	}
	if (!rj) {
		hwr_wdf_statics(&fd, &idx, &smac, &max);
		int want_fd = t->cached ? CACHED_FD : (fresh_ok(t) ? FRESH_FD : -1);
		if (fd[t->vap_id] != want_fd) { snprintf(why, sizeof(why), "g_fd_arr[vap_id] is %d, expected %d", fd[t->vap_id], want_fd); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wdf_case_t *t)
{
	hwr_wdf_world_t *w = &hwr_wdf_world;

	memset(w, 0, sizeof(*w));
	hwr_wdf_reset_statics();
	w->n_if = 2; w->sock_fail = t->sock_fail; w->bind_fail = t->bind_fail; w->sendto_mode = t->sendto_mode; w->next_fd = FRESH_FD;
	for (int k = 0; k < 2; k++) {
		w->vap_of[k] = (k == 1 && !t->no_iface && t->vap_id >= 0) ? (unsigned)t->vap_id : 100u + k;
		w->ifs[k].index = k == 1 ? IF_INDEX : 1;
		memcpy(w->ifs[k].mac, k == 1 ? if_mac : cached_mac, 6);
	}
	if (t->cached && t->vap_id >= 0 && t->vap_id < MAXV) hwr_wdf_preset(t->vap_id, CACHED_FD, CACHED_IDX, cached_mac);
	dmac = (unsigned char *)malloc(6); memcpy(dmac, dst_mac, 6);
	{ int n = t->data_len > 0 && t->data_len <= 4096 ? t->data_len : 1; dbuf = (unsigned char *)malloc(n); for (int i = 0; i < n; i++) dbuf[i] = (unsigned char)(i * 7 + 3); }
}

extern "C" void run_all_tests_sg_wifi_hal_sendDataFrame(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_sendDataFrame_suite[i].test_name != NULL; i++) {
			hwr_wdf_case_t *test = &sg_wifi_hal_sendDataFrame_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_sendDataFrame(test);

			int ok = check(test);
			free(dmac); free(dbuf); dmac = dbuf = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_sendDataFrame: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
