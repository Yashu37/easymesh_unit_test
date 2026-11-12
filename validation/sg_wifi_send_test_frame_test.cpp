/*
 * TEST RUNNER: sg_wifi_send_test_frame_test
 *
 * test_sg_wifi_send_test_frame() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).
 * The frame is an exactly sized heap block (max(frame_len, 1) bytes) and arg an exactly sized heap block (over-reads / NULL reported by ASan); the function's own msg[2048] is a stack object with red zones.
 * run_all_tests compares the recorded socket / sendto / close calls and the datagram with a reference model of the CORRECT behaviour (see the construct file).  The datagram content is checked first and its
 * total length last.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "hwr_wft.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static INT ret;
static unsigned char *frame;
static frame_test_arg_t *arg;
extern "C" const unsigned char *hwr_wft_sig(void);

static const wifi_test_command_id_t cmds[4] = { wifi_test_command_id_probe_req, wifi_test_command_id_8021x, wifi_test_command_id_action, wifi_test_command_id_deauth };

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wft_world.unrelated, sizeof(hwr_wft_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_send_test_frame(const hwr_wft_case_t *t)
{
	poison(1);
	ret = hwr_sg_wifi_send_test_frame(t->frame_null ? NULL : frame, t->flen, t->arg_null ? NULL : arg, cmds[t->cmd], (wifi_direction_t)t->dir);
	poison(0);
}

static int check(const hwr_wft_case_t *t)
{
	const hwr_wft_world_t *w = &hwr_wft_world;
	int invalid = t->arg_null || (t->frame_null && t->flen > 0) || t->flen > 1993;
	long want_len = 8 + 8 + 20 + 10 + 5 + 4 + (long)t->flen;

	if (invalid || t->socket_fail || t->send_fail) {
		if (ret != RETURN_ERR) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, RETURN_ERR); return 0; }
		if (invalid) {
			if (w->sendto_calls != 0) { snprintf(why, sizeof(why), "%d datagram(s) sent for invalid input", w->sendto_calls); return 0; }
			if (w->closes != w->socket_calls) { snprintf(why, sizeof(why), "%d sockets opened, %d closed", w->socket_calls, w->closes); return 0; }
			return 1;
		}
		if (t->socket_fail) {
			if (w->sendto_calls != 0) { snprintf(why, sizeof(why), "%d datagram(s) sent after socket failure", w->sendto_calls); return 0; }
			if (w->closes != 0) { snprintf(why, sizeof(why), "closed %d sockets that were never opened", w->closes); return 0; }
			return 1;
		}
		if (w->sendto_calls != 1 || w->closes != 1) { snprintf(why, sizeof(why), "sendto failure: %d sends, %d closes, expected 1 / 1", w->sendto_calls, w->closes); return 0; }
		return 1;
	}
	if (ret != RETURN_OK) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, RETURN_OK); return 0; }
	if (w->socket_calls != 1 || w->sendto_calls != 1 || w->closes != 1) { snprintf(why, sizeof(why), "%d socket / %d sendto / %d close calls, expected 1 / 1 / 1", w->socket_calls, w->sendto_calls, w->closes); return 0; }
	if (w->sock_domain != AF_INET || w->sock_type != SOCK_DGRAM) { snprintf(why, sizeof(why), "wrong socket type"); return 0; }
	if (w->sent_addr_family != AF_INET || w->sent_port != 8888 || w->sent_ip != 0x7F000001) { snprintf(why, sizeof(why), "wrong destination %u:%u", w->sent_ip, w->sent_port); return 0; }
	{
		const unsigned char *p = w->sent;
		unsigned short cmd = cmds[t->cmd];

		if (memcmp(p, hwr_wft_sig(), 8) != 0) { snprintf(why, sizeof(why), "signature differs"); return 0; }
		p += 8;
		if (p[0] != 0 || p[1] != 0 || p[2] != 4 || p[3] != 0 || (p[4] | (p[5] << 8)) != cmd || p[6] != 0 || p[7] != 0) { snprintf(why, sizeof(why), "command TLV wrong"); return 0; }
		p += 8;
		if (p[0] != 1 || p[1] != 0 || p[2] != 16 || p[3] != 0 || memcmp(p + 4, arg->interface_name, 16) != 0) { snprintf(why, sizeof(why), "vap-name TLV wrong"); return 0; }
		p += 20;
		if (p[0] != 2 || p[1] != 0 || p[2] != 6 || p[3] != 0 || memcmp(p + 4, arg->mac, 6) != 0) { snprintf(why, sizeof(why), "station mac TLV wrong"); return 0; }
		p += 10;
		if (p[0] != 3 || p[1] != 0 || p[2] != 1 || p[3] != 0 || p[4] != t->dir) { snprintf(why, sizeof(why), "direction TLV wrong"); return 0; }
		p += 5;
		if (p[0] != 4 || p[1] != 0 || (p[2] | (p[3] << 8)) != (int)t->flen || memcmp(p + 4, frame, t->flen) != 0) { snprintf(why, sizeof(why), "raw frame TLV wrong"); return 0; }
	}
	if (w->sent_len != want_len) { snprintf(why, sizeof(why), "datagram is %ld bytes, expected %ld (5 TLVs back to back)", w->sent_len, want_len); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_send_test_frame(void)
{
	int pass = 0, fail = 0;
	static const char *names[4] = { "ath0", "", "ath123456789012", "ath1234567890123456789012345678" };

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_send_test_frame_suite[i].test_name != NULL; i++) {
			hwr_wft_case_t *test = &sg_wifi_send_test_frame_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_wft_world, 0, sizeof(hwr_wft_world));
			hwr_wft_world.socket_fail = test->socket_fail; hwr_wft_world.send_fail = test->send_fail;
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			frame = (unsigned char *)malloc(test->flen ? test->flen : 1);
			for (size_t k = 0; k < test->flen; k++) frame[k] = (unsigned char)(k * 7 + 3);
			arg = (frame_test_arg_t *)calloc(1, sizeof(frame_test_arg_t));
			strcpy(arg->interface_name, names[test->name]);
			for (int k = 0; k < 6; k++) arg->mac[k] = test->mac == 0 ? 0 : test->mac == 1 ? 0xFF : (unsigned char)(0x10 + k * 0x11);
			arg->uplink_downlink = test->dir; arg->num_commands = 1; arg->cmd[0] = cmds[test->cmd];

			test_sg_wifi_send_test_frame(test);

			int ok = check(test);
			free(frame); frame = NULL; free(arg); arg = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_send_test_frame: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
