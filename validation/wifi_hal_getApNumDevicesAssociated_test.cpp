/*
 * TEST RUNNER: wifi_hal_getApNumDevicesAssociated_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radios, interface maps, interfaces with the REAL
 * wifi_vap_info_t and the u.ap / u.sta union) in runner-owned slabs, POISONS their tails, calls the function,
 * UNPOISONS and checks:
 *   hwr_iface_slab : [used interfaces * sizeof(iface), end)   - interfaces past the used ones
 *   hwr_radio_slab / hwr_map_slab : the radios / maps past the used ones
 *   hwr_out_slab   : [sizeof(ULONG), end)                     - *output_ulong is the only thing it may write
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * *output_ulong is preset to 0xA5 bytes so "written" / "untouched" is visible; after every call hapd_lock must be
 * free (trylock) and no interface byte may have changed.  Rows flagged `forked` crash the unfixed function (NULL
 * output, hapd_lock held): they run in a child so the ASan report is visible but the run continues; the child
 * also checks the result and the lock.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gnd.h"
#include <sanitizer/asan_interface.h>

static hwr_gnd_radio_t hwr_radio_slab[HWR_GND_MAX_RADIOS + 2];
static hwr_gnd_map_t   hwr_map_slab[HWR_GND_MAX_RADIOS + 2];
static hwr_gnd_iface_t hwr_iface_slab[HWR_GND_MAX_IFACES];
static hwr_gnd_iface_t hwr_snap[HWR_GND_MAX_IFACES];
static unsigned char   hwr_out_slab[64];
static int used_ifaces, used_radios;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_gnd_radio_t));
	fn(&hwr_map_slab[used_radios], sizeof(hwr_map_slab) - used_radios * sizeof(hwr_gnd_map_t));
	fn(&hwr_iface_slab[used_ifaces], sizeof(hwr_iface_slab) - used_ifaces * sizeof(hwr_gnd_iface_t));
	fn(&hwr_out_slab[sizeof(ULONG)], sizeof(hwr_out_slab) - sizeof(ULONG));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void build(const hwr_gnd_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_map_slab, 0, sizeof(hwr_map_slab));
	memset(hwr_iface_slab, 0, sizeof(hwr_iface_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_ifaces = 0; used_radios = t->nradios;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].interface_map = &hwr_map_slab[r];
		for (int k = 0; k < t->r[r].n; k++) {
			hwr_gnd_iface_t *f = &hwr_iface_slab[used_ifaces++];
			const hwr_gnd_if_t *s = &t->r[r].ifs[k];
			f->vap_info.vap_index = s->vap_index;
			f->vap_info.vap_mode = (wifi_vap_mode_t)(s->mode == 0 ? wifi_vap_mode_ap : s->mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor);
			memset(&f->u, s->fill, sizeof(f->u));                                      /* union bytes, then the member valid for the mode */
			if (s->mode == 0) f->u.ap.hapd.num_sta = s->num_sta;
			hwr_map_slab[r].items[hwr_map_slab[r].n++] = f;
		}
	}
	hwr_gnd_world.num_radios = t->nradios;
	hwr_gnd_world.radio_info = hwr_radio_slab;
	memset(hwr_out_slab, 0xA5, sizeof(hwr_out_slab));
}

/* 1 = lock was free (and is released again) */
static int lock_free(void)
{
	if (pthread_mutex_trylock(&hwr_gnd_world.hapd_lock) != 0) return 0;
	pthread_mutex_unlock(&hwr_gnd_world.hapd_lock);
	return 1;
}

static int check_result(const hwr_gnd_case_t *t, INT ret)
{
	if (ret != t->expected_ret) {
		int sta_like = 0;
		for (int r = 0; r < t->nradios; r++) for (int k = 0; k < t->r[r].n; k++) if (t->r[r].ifs[k].vap_index == (unsigned)t->query && t->r[r].ifs[k].mode != 0) sta_like = 1;
		snprintf(why, sizeof(why), "returned %d, expected %d%s", ret, t->expected_ret, (ret == 0 && sta_like) ? " (non-AP VAP accepted: num_sta read from STA state bytes)" : "");
		return 0;
	}
	if (!lock_free()) { snprintf(why, sizeof(why), "hapd_lock still held after the call"); return 0; }
	if (!t->null_out) {
		if (t->expected_out < 0) {
			for (size_t k = 0; k < sizeof(ULONG); k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "*output_ulong written although the call failed"); return 0; }
		} else if (*(ULONG *)hwr_out_slab != (ULONG)t->expected_out) { snprintf(why, sizeof(why), "*output_ulong = %lu, expected %ld", *(ULONG *)hwr_out_slab, t->expected_out); return 0; }
		for (size_t k = sizeof(ULONG); k < 16; k++) if (hwr_out_slab[k] != 0xA5) { snprintf(why, sizeof(why), "byte %zu behind *output_ulong modified", k); return 0; }
	}
	if (memcmp(hwr_iface_slab, hwr_snap, sizeof(hwr_snap))) { snprintf(why, sizeof(why), "an interface was modified"); return 0; }
	return 1;
}

static int run_case(const hwr_gnd_case_t *t)
{
	ULONG *out = t->null_out ? NULL : (ULONG *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	build(t);
	memcpy(hwr_snap, hwr_iface_slab, sizeof(hwr_snap));

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getApNumDevicesAssociated(t->query, out); poison_all(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on NULL output_ulong)"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV on NULL output_ulong, hapd_lock held)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result / lock state"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		build(t);
		memcpy(hwr_snap, hwr_iface_slab, sizeof(hwr_snap));
		poison_all(1);
		ret = hwr_wifi_hal_getApNumDevicesAssociated(t->query, out);
		poison_all(0);
		if (!check_result(t, ret)) { char tmp[220]; snprintf(tmp, sizeof(tmp), "call %d: %s", i, why); memcpy(why, tmp, sizeof(why)); return 0; }
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_getApNumDevicesAssociated") || !strstr(hwr_log_buf, "num assoc devs: 12"))) { snprintf(why, sizeof(why), "log lacks function name / count: '%.150s'", hwr_log_buf); return 0; }
	if (t->check_log == 2 && !strstr(hwr_log_buf, "doesn't exist")) { snprintf(why, sizeof(why), "log lacks the error line: '%.150s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getApNumDevicesAssociated(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getApNumDevicesAssociated_suite[i].test_name != NULL; i++) {
		hwr_gnd_case_t *test = &wifi_hal_getApNumDevicesAssociated_suite[i];

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
	printf("\nwifi_hal_getApNumDevicesAssociated: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
