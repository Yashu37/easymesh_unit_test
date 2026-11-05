/*
 * TEST RUNNER: platform_pre_create_vap_test
 *
 * The runner owns the vap map in a slab (hwr_ppv_slab) and POISONS everything behind sizeof(wifi_vap_info_map_t) (vap_array has
 * MAX_NUM_VAP_PER_RADIO = 8 entries) and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) during the call.  The map is filled with a 0x5A canary, the described
 * vaps are set up and a copy is kept.  After the call the WHOLE map is compared with a safe oracle applied to the copy: a RADIUS default is applied
 * only when valid (ip 1..44 chars, port 1..65535, key 1..63 chars), otherwise the field keeps its value, nothing else changes (so an overflow into
 * port / key / identity / connectedendpoint is caught); NULL map or num_vaps > 8 -> -1 and the map untouched.  Also checked: the nvram is asked
 * (ip, port, key) once per applied server and for nothing else, and get_interface_by_vap_index once per AP vap.  Rows flagged `forked` crash the
 * unfixed function (stack overflow of the 32-byte port buffer, over-read of vap_array): they run in a child so the ASan report is visible but the run
 * continues; the child also checks the result.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_ppv.h"
#include <sanitizer/asan_interface.h>

#define MAP_SZ sizeof(wifi_vap_info_map_t)
static unsigned char hwr_ppv_slab[sizeof(wifi_vap_info_map_t) + 4096] __attribute__((aligned(16)));
static unsigned char want[sizeof(wifi_vap_info_map_t)];
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_ppv_slab[(MAP_SZ + 7) & ~(size_t)7], sizeof(hwr_ppv_slab) - ((MAP_SZ + 7) & ~(size_t)7));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int is_radius_mode(int m)
{
	return m == wifi_security_mode_wpa_enterprise || m == wifi_security_mode_wpa2_enterprise || m == wifi_security_mode_wpa3_enterprise || m == wifi_security_mode_wpa_wpa2_enterprise;
}

/* oracle for one server: valid -> applied, else unchanged */
static void oracle_server(const hwr_ppv_case_t *t, unsigned char *ip, unsigned short *port, char *key)
{
	size_t l;
	char *end = NULL; long p;

	if (t->ip_ret == 0 && (l = strlen(t->ip_val)) >= 1 && l <= 44) memcpy(ip, t->ip_val, l + 1);
	if (t->port_ret == 0 && (p = strtol(t->port_val, &end, 10), end != t->port_val) && p >= 1 && p <= 65535) *port = (unsigned short)p;
	if (t->key_ret == 0 && (l = strlen(t->key_val)) >= 1 && l <= 63) memcpy(key, t->key_val, l + 1);
}

static int check_result(const hwr_ppv_case_t *t, int ret, int exp_blocks, int exp_ap)
{
	wifi_vap_info_map_t *map = (wifi_vap_info_map_t *)hwr_ppv_slab;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->null_map) return 1;
	if (memcmp(hwr_ppv_slab, want, MAP_SZ)) {
		for (unsigned int i = 0; i < MAX_NUM_VAP_PER_RADIO; i++)
			if (memcmp(&map->vap_array[i], &((wifi_vap_info_map_t *)want)->vap_array[i], sizeof(wifi_vap_info_t))) {
				const wifi_radius_settings_t *g = &map->vap_array[i].u.bss_info.security.u.radius, *e = &((wifi_vap_info_map_t *)want)->vap_array[i].u.bss_info.security.u.radius;
				if (memcmp(g->ip, e->ip, sizeof(g->ip))) snprintf(why, sizeof(why), "vap %u: ip '%.20s', expected '%.20s'", i, (char *)g->ip, (char *)e->ip);
				else if (g->port != e->port) snprintf(why, sizeof(why), "vap %u: port %u, expected %u", i, g->port, e->port);
				else if (memcmp(g->key, e->key, sizeof(g->key))) snprintf(why, sizeof(why), "vap %u: key '%.20s'(%zu chars), expected '%.20s'", i, g->key, strlen(g->key), e->key);
				else if (memcmp(g->s_ip, e->s_ip, sizeof(g->s_ip))) snprintf(why, sizeof(why), "vap %u: s_ip '%.20s', expected '%.20s'", i, (char *)g->s_ip, (char *)e->s_ip);
				else if (g->s_port != e->s_port) snprintf(why, sizeof(why), "vap %u: s_port %u, expected %u", i, g->s_port, e->s_port);
				else if (memcmp(g->s_key, e->s_key, sizeof(g->s_key))) snprintf(why, sizeof(why), "vap %u: s_key '%.20s', expected '%.20s'", i, g->s_key, e->s_key);
				else snprintf(why, sizeof(why), "vap %u: a field behind the RADIUS values was modified (overflow)", i);
				return 0;
			}
		snprintf(why, sizeof(why), "map modified"); return 0;
	}
	if (hwr_ppv_st.n_other) { snprintf(why, sizeof(why), "nvram asked for %d unknown keys", hwr_ppv_st.n_other); return 0; }
	if (hwr_ppv_st.n_ip != exp_blocks || hwr_ppv_st.n_port != exp_blocks || hwr_ppv_st.n_key != exp_blocks) { snprintf(why, sizeof(why), "nvram asked ip/port/key %d/%d/%d times, expected %d each", hwr_ppv_st.n_ip, hwr_ppv_st.n_port, hwr_ppv_st.n_key, exp_blocks); return 0; }
	if (hwr_ppv_st.get_if_calls != exp_ap) { snprintf(why, sizeof(why), "interface looked up %d times, expected %d", hwr_ppv_st.get_if_calls, exp_ap); return 0; }
	return 1;
}

static int run_case(const hwr_ppv_case_t *t)
{
	wifi_vap_info_map_t *map = (wifi_vap_info_map_t *)hwr_ppv_slab;
	wifi_vap_info_map_t *w = (wifi_vap_info_map_t *)want;
	unsigned int fill = t->num_vaps < MAX_NUM_VAP_PER_RADIO ? t->num_vaps : MAX_NUM_VAP_PER_RADIO;
	int exp_blocks = 0, exp_ap = 0, ret = 0;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(&hwr_ppv_st, 0, sizeof(hwr_ppv_st));
	hwr_ppv_st.ip_val = t->ip_val; hwr_ppv_st.ip_ret = t->ip_ret; hwr_ppv_st.port_val = t->port_val; hwr_ppv_st.port_ret = t->port_ret;
	hwr_ppv_st.key_val = t->key_val; hwr_ppv_st.key_ret = t->key_ret;
	for (int k = 0; k < 16; k++) hwr_ppv_st.if_mode[k] = wifi_vap_mode_ap;
	memset(hwr_ppv_slab, 0x5A, sizeof(hwr_ppv_slab));
	map->num_vaps = t->num_vaps;
	for (unsigned int i = 0; i < fill; i++) {
		wifi_vap_info_t *v = &map->vap_array[i];
		wifi_radius_settings_t *r = &v->u.bss_info.security.u.radius;
		hwr_ppv_vap_t d = i < 3 ? t->v[i] : (hwr_ppv_vap_t){ wifi_vap_mode_ap, wifi_security_mode_wpa2_personal, (unsigned)i + 8, "0.0.0.0", "0.0.0.0", 0, 0, "oldkey", "oldskey", wifi_vap_mode_ap };
		v->vap_mode = (wifi_vap_mode_t)d.mode; v->vap_index = d.vap_index; v->u.bss_info.security.mode = (wifi_security_modes_t)d.sec;
		memset(r->ip, 0, sizeof(r->ip)); strcpy((char *)r->ip, d.ip);
		memset(r->s_ip, 0, sizeof(r->s_ip)); strcpy((char *)r->s_ip, d.s_ip);
		r->port = d.port; r->s_port = d.s_port;
		memset(r->key, 0, sizeof(r->key)); strcpy(r->key, d.key);
		memset(r->s_key, 0, sizeof(r->s_key)); strcpy(r->s_key, d.s_key);
		if (i < 16) hwr_ppv_st.if_mode[d.vap_index < 16 ? d.vap_index : 0] = d.if_mode;
	}
	/* the first three described vaps may share an interface index; give each its own mode by index */
	memcpy(want, hwr_ppv_slab, sizeof(want));
	if (!t->null_map && t->num_vaps <= MAX_NUM_VAP_PER_RADIO) {
		for (unsigned int i = 0; i < t->num_vaps; i++) {
			wifi_vap_info_t *v = &w->vap_array[i];
			wifi_radius_settings_t *r = &v->u.bss_info.security.u.radius;

			if (v->vap_mode != wifi_vap_mode_ap) continue;
			exp_ap++;
			if (!(is_radius_mode(v->u.bss_info.security.mode) || v->vap_index == HWR_PPV_LNF_IDX || v->vap_index == HWR_PPV_HOTSPOT_IDX)) continue;
			if (!strcmp((char *)r->ip, "0.0.0.0")) { oracle_server(t, r->ip, &r->port, r->key); exp_blocks++; }
			if (!strcmp((char *)r->s_ip, "0.0.0.0")) { oracle_server(t, r->s_ip, &r->s_port, r->s_key); exp_blocks++; }
		}
	}

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { ret = hwr_platform_pre_create_vap(0, t->null_map ? NULL : map); poison(0); _exit(check_result(t, ret, exp_blocks, exp_ap) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (%s)", t->num_vaps > MAX_NUM_VAP_PER_RADIO ? "vap_array over-read" : "radius_s_port value overflows the 32-byte stack buffer"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	ret = hwr_platform_pre_create_vap(0, t->null_map ? NULL : map);
	poison(0);
	return check_result(t, ret, exp_blocks, exp_ap);
}

extern "C" void run_all_tests_platform_pre_create_vap(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_pre_create_vap_suite[i].test_name != NULL; i++) {
		hwr_ppv_case_t *test = &platform_pre_create_vap_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nplatform_pre_create_vap: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
