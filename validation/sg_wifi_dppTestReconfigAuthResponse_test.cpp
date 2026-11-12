/*
 * TEST RUNNER: sg_wifi_dppTestReconfigAuthResponse_test
 *
 * test_sg_wifi_dppTestReconfigAuthResponse() POISONS what the function must not touch, calls the handler and unpoisons (once per call): the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The station mac is an exactly sized 6-byte heap block (over-read / NULL reported by ASan); the function's own msg[1024] / interface_name[32] / test_data[] are stack
 * objects with red zones.  run_all_tests compares the recorded socket / sendto / close calls and the datagram with a reference model of the CORRECT behaviour (see the construct file).
 * Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "hwr_wtt.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static INT rets[2];
static unsigned char *mac;

#include "hwr_wtt_data.h"
#define test_data hwr_wtt_test_data
extern "C" const unsigned char *hwr_wtt_sig(void);

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wtt_world.unrelated, sizeof(hwr_wtt_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_dppTestReconfigAuthResponse(const hwr_wtt_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		poison(1);
		rets[n] = hwr_sg_wifi_dppTestReconfigAuthResponse(t->ap + n, t->sta_null ? NULL : mac);
		poison(0);
		if (n + 1 < t->calls && !t->socket_fail) { /* the world keeps the last datagram only */ }
	}
}

static int check(const hwr_wtt_case_t *t)
{
	const hwr_wtt_world_t *w = &hwr_wtt_world;
	int send_expected = !t->socket_fail && !t->sta_null;
	int n_ok = t->calls;

	if (w->socket_calls != (t->sta_null ? w->socket_calls : t->calls)) { snprintf(why, sizeof(why), "socket ran %d times, expected %d", w->socket_calls, t->calls); return 0; }
	for (int n = 0; n < t->calls; n++) {
		INT want = (t->socket_fail || t->sta_null || t->send_fail) ? RETURN_ERR : RETURN_OK;
		if (rets[n] != want) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", n, rets[n], want); return 0; }
	}
	if (!send_expected) {
		if (w->sendto_calls != 0) { snprintf(why, sizeof(why), "%d datagram(s) sent, expected none", w->sendto_calls); return 0; }
		if (t->socket_fail && w->closes != 0) { snprintf(why, sizeof(why), "closed %d sockets that were never opened", w->closes); return 0; }
		return 1;
	}
	if (w->sendto_calls != n_ok) { snprintf(why, sizeof(why), "%d datagrams sent, expected %d", w->sendto_calls, n_ok); return 0; }
	if (w->closes != n_ok) { snprintf(why, sizeof(why), "socket closed %d times, expected %d", w->closes, n_ok); return 0; }
	if (w->sock_domain != AF_INET || w->sock_type != SOCK_DGRAM) { snprintf(why, sizeof(why), "wrong socket type"); return 0; }
	if (w->sent_addr_family != AF_INET || w->sent_port != 8888 || w->sent_ip != 0x7F000001) { snprintf(why, sizeof(why), "wrong destination %u:%u", w->sent_ip, w->sent_port); return 0; }
	if (w->sent_len != 8 + 8 + 20 + 10 + 4 + (long)sizeof(test_data)) { snprintf(why, sizeof(why), "datagram is %ld bytes, expected %ld", w->sent_len, 8 + 8 + 20 + 10 + 4 + (long)sizeof(test_data)); return 0; }
	{
		const unsigned char *p = w->sent;
		unsigned ap = t->ap + (t->calls - 1);
		char name[24]; snprintf(name, sizeof(name), "ath%u", ap);
		if (memcmp(p, hwr_wtt_sig(), 8) != 0) { snprintf(why, sizeof(why), "signature differs"); return 0; }
		p += 8;
		if (p[0] != 0 || p[1] != 0 || p[2] != 4 || p[3] != 0 || ((p[4] | (p[5] << 8)) != wifi_test_command_id_reconf_auth_resp)) { snprintf(why, sizeof(why), "command TLV wrong"); return 0; }
		p += 8;
		if (p[0] != 1 || p[1] != 0 || p[2] != 16 || p[3] != 0) { snprintf(why, sizeof(why), "vap-name TLV header wrong"); return 0; }
		if (strncmp((const char *)p + 4, name, 16) != 0) { snprintf(why, sizeof(why), "vap name is \"%.16s\", expected \"%s\"", (const char *)p + 4, name); return 0; }
		p += 20;
		if (p[0] != 2 || p[1] != 0 || p[2] != 6 || p[3] != 0 || memcmp(p + 4, mac, 6) != 0) { snprintf(why, sizeof(why), "station mac TLV wrong"); return 0; }
		p += 10;
		if (p[0] != 4 || p[1] != 0 || (p[2] | (p[3] << 8)) != (int)sizeof(test_data) || memcmp(p + 4, test_data, sizeof(test_data)) != 0) { snprintf(why, sizeof(why), "raw TLV wrong"); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppTestReconfigAuthResponse(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppTestReconfigAuthResponse_suite[i].test_name != NULL; i++) {
			hwr_wtt_case_t *test = &sg_wifi_dppTestReconfigAuthResponse_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_wtt_world, 0, sizeof(hwr_wtt_world));
			hwr_wtt_world.socket_fail = test->socket_fail; hwr_wtt_world.send_fail = test->send_fail;
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			mac = (unsigned char *)malloc(6);
			for (int k = 0; k < 6; k++) mac[k] = test->sta_pattern == 0 ? 0 : test->sta_pattern == 1 ? 0xFF : (unsigned char)(0x10 + k * 0x11);

			test_sg_wifi_dppTestReconfigAuthResponse(test);

			int ok = check(test);
			free(mac); mac = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_dppTestReconfigAuthResponse: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
