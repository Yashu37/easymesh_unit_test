/*
 * TEST RUNNER: sync_hostapd_freq_param_test
 *
 * The runner builds the world from the suite row in runner-owned slabs,
 * POISONS their tails, calls the function, UNPOISONS and verifies:
 *   hshf_iface_slab : [sizeof(hcf_hostapd_iface_t), end)  - the hostapd interface
 *   hshf_intf_slab  : [sizeof(wifi_interface_info_t), end)
 *   hshf_radio_slab : [sizeof(wifi_radio_info_t), end)
 *   hipc_log_buf    : [HIPC_LOG_USE, HIPC_LOG_SZ)
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* the types are scaffolded inside the handler file; the runner only needs their layout */
typedef struct { int freq; } hcf_hostapd_iface_t;
typedef struct { unsigned int radio_index; } wifi_vap_info_t;
typedef struct { int countryCode; unsigned char operatingClass; unsigned char channel; } wifi_radio_operationParam_t;
typedef struct { wifi_radio_operationParam_t oper_param; } wifi_radio_info_t;
typedef struct { wifi_vap_info_t vap_info; union { struct { struct { hcf_hostapd_iface_t *iface; } hapd; } ap; } u; } wifi_interface_info_t;

#define PADSZ 64
static unsigned char hshf_iface_slab[sizeof(hcf_hostapd_iface_t) + PADSZ];
static unsigned char hshf_intf_slab [sizeof(wifi_interface_info_t) + PADSZ];
static unsigned char hshf_radio_slab[sizeof(wifi_radio_info_t) + PADSZ];

wifi_interface_info_t *hshf_interface;
unsigned int           hshf_interface_vap_index;
wifi_radio_info_t     *hshf_radio;
unsigned int           hshf_radio_index;
char                   hshf_last_country[16];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hshf_iface_slab[sizeof(hcf_hostapd_iface_t)], PADSZ);
	fn(&hshf_intf_slab[sizeof(wifi_interface_info_t)], PADSZ);
	fn(&hshf_radio_slab[sizeof(wifi_radio_info_t)], PADSZ);
	fn(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);
}

static int run_case(const hshf_test_case_t *t)
{
	hcf_hostapd_iface_t *hi = (hcf_hostapd_iface_t *)hshf_iface_slab;
	wifi_interface_info_t *ii = (wifi_interface_info_t *)hshf_intf_slab;
	wifi_radio_info_t *ri = (wifi_radio_info_t *)hshf_radio_slab;
	int ret = 0;

	memset(hshf_iface_slab, 0, sizeof(hshf_iface_slab));
	memset(hshf_intf_slab, 0, sizeof(hshf_intf_slab));
	memset(hshf_radio_slab, 0, sizeof(hshf_radio_slab));
	memset(hipc_log_buf, 0, HIPC_LOG_USE);
	hshf_last_country[0] = 0;
	hipc_exec_why[0] = 0;

	hi->freq = t->cur_freq;
	ii->vap_info.radio_index = t->vap_radio_index;
	ii->u.ap.hapd.iface = t->hapd_iface ? hi : NULL;
	ri->oper_param.countryCode = t->country_code;
	ri->oper_param.operatingClass = (unsigned char)t->op_class;
	ri->oper_param.channel = (unsigned char)t->channel;
	hshf_interface = t->interface_present ? ii : NULL;
	hshf_interface_vap_index = 3;
	hshf_radio = t->radio_present ? ri : NULL;
	hshf_radio_index = 0;

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { sync_hostapd_freq_param_entry(t->ap_index); _exit(0); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) { snprintf(hipc_exec_why, 256, "child died (SEGV on NULL radio / hapd.iface)"); return 0; }
		return 1;
	}

	poison_all(1);
	ret = sync_hostapd_freq_param_entry(t->ap_index);
	poison_all(0);

	if (ret != t->exp_ret) { snprintf(hipc_exec_why, 256, "returned %d, expected %d", ret, t->exp_ret); return 0; }
	if (hi->freq != t->exp_freq) { snprintf(hipc_exec_why, 256, "hostapd iface freq = %d, expected %d%s", hi->freq, t->exp_freq, hi->freq < 0 ? " (invalid freq written to hostapd)" : ""); return 0; }
	if (t->exp_country && strcmp(hshf_last_country, t->exp_country)) { snprintf(hipc_exec_why, 256, "country '%s', expected '%s'", hshf_last_country, t->exp_country); return 0; }
	return 1;
}

void run_all_tests_sync_hostapd_freq_param(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sync_hostapd_freq_param_suite[i].test_name != NULL; i++) {
		hshf_test_case_t *test = &sync_hostapd_freq_param_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == test->expected_result) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n",
			       test->test_name, test->expected_result, ret, hipc_exec_why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nsync_hostapd_freq_param: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
