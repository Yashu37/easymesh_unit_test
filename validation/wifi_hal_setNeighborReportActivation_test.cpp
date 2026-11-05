/*
 * TEST RUNNER: wifi_hal_setNeighborReportActivation_test
 *
 * The runner builds the "world" of the suite row (g_wifi_hal, radios, interface maps, interfaces with the REAL
 * wifi_vap_info_t) in runner-owned slabs, POISONS their tails, calls the function, UNPOISONS and checks:
 *   hwr_iface_slab : [used interfaces * sizeof(iface), end)   - interfaces past the used ones
 *   hwr_radio_slab / hwr_map_slab : the radios / maps past the used ones
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)
 * Before every call the runner snapshots all used interfaces; afterwards exactly the nbrReportActivated byte of the
 * expected interface may differ (and nothing at all on a failed call), so a write into the union of a STA / monitor
 * VAP, or into another interface, is visible.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hwr_snr.h"
#include <sanitizer/asan_interface.h>

static hwr_snr_radio_t hwr_radio_slab[HWR_SNR_MAX_RADIOS + 2];
static hwr_snr_map_t   hwr_map_slab[HWR_SNR_MAX_RADIOS + 2];
static hwr_snr_iface_t hwr_iface_slab[HWR_SNR_MAX_IFACES];
static hwr_snr_iface_t hwr_snap[HWR_SNR_MAX_IFACES];
static int used_ifaces, used_radios;

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_radio_slab[used_radios], sizeof(hwr_radio_slab) - used_radios * sizeof(hwr_snr_radio_t));
	fn(&hwr_map_slab[used_radios], sizeof(hwr_map_slab) - used_radios * sizeof(hwr_snr_map_t));
	fn(&hwr_iface_slab[used_ifaces], sizeof(hwr_iface_slab) - used_ifaces * sizeof(hwr_snr_iface_t));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static void build(const hwr_snr_case_t *t)
{
	memset(hwr_radio_slab, 0, sizeof(hwr_radio_slab));
	memset(hwr_map_slab, 0, sizeof(hwr_map_slab));
	memset(hwr_iface_slab, 0, sizeof(hwr_iface_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	used_ifaces = 0; used_radios = t->nradios;
	for (int r = 0; r < t->nradios; r++) {
		hwr_radio_slab[r].interface_map = &hwr_map_slab[r];
		for (int k = 0; k < t->r[r].n; k++) {
			hwr_snr_iface_t *f = &hwr_iface_slab[used_ifaces++];
			const hwr_snr_if_t *s = &t->r[r].ifs[k];
			f->vap_info.vap_index = s->vap_index;
			f->vap_info.vap_mode = (wifi_vap_mode_t)(s->mode == 0 ? wifi_vap_mode_ap : s->mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor);
			memset(&f->vap_info.u, s->fill, sizeof(f->vap_info.u));                 /* union bytes, then the member that is valid for the mode */
			if (s->mode == 0) f->vap_info.u.bss_info.nbrReportActivated = (BOOL)s->enabled;
			hwr_map_slab[r].items[hwr_map_slab[r].n++] = f;
		}
	}
	hwr_snr_world.num_radios = t->nradios;
	hwr_snr_world.radio_info = hwr_radio_slab;
}

static int run_case(const hwr_snr_case_t *t)
{
	INT ret = 0;

	why[0] = 0;
	for (int i = 0; i < t->calls; i++) {
		build(t);
		memcpy(hwr_snap, hwr_iface_slab, sizeof(hwr_snap));
		poison_all(1);
		ret = hwr_wifi_hal_setNeighborReportActivation(t->query, (BOOL)t->activate);
		poison_all(0);
		if (ret != t->expected_ret) {
			int sta_like = 0;
			for (int r = 0; r < t->nradios; r++) for (int k = 0; k < t->r[r].n; k++) if (t->r[r].ifs[k].vap_index == t->query && t->r[r].ifs[k].mode != 0) sta_like = 1;
			snprintf(why, sizeof(why), "call %d returned %d, expected %d%s", i, ret, t->expected_ret, (ret == 0 && sta_like) ? " (non-AP VAP accepted: the AP-only flag was written into its union)" : "");
			return 0;
		}
		for (int k = 0; k < used_ifaces; k++) {
			unsigned char *now = (unsigned char *)&hwr_iface_slab[k], *was = (unsigned char *)&hwr_snap[k];
			size_t flag = (size_t)((unsigned char *)&hwr_iface_slab[k].vap_info.u.bss_info.nbrReportActivated - now);
			for (size_t z = 0; z < sizeof(hwr_snr_iface_t); z++) {
				if (now[z] == was[z]) continue;
				if (k == t->expected_set && z == flag) continue;
				snprintf(why, sizeof(why), "interface %d byte %zu modified (0x%02x -> 0x%02x)%s", k, z, was[z], now[z], z == flag ? " = the offset of nbrReportActivated, which belongs to another field in a non-AP VAP" : "");
				return 0;
			}
			if (k == t->expected_set && hwr_iface_slab[k].vap_info.u.bss_info.nbrReportActivated != (BOOL)t->activate) { snprintf(why, sizeof(why), "flag of interface %d is %d, expected %d", k, (int)hwr_iface_slab[k].vap_info.u.bss_info.nbrReportActivated, (int)(BOOL)t->activate); return 0; }
		}
	}
	if (t->check_log == 1 && (!strstr(hwr_log_buf, "wifi_hal_setNeighborReportActivation") || (!strstr(hwr_log_buf, "Enter") && !strstr(hwr_log_buf, "not found")))) { snprintf(why, sizeof(why), "log lacks function name / message: '%s'", hwr_log_buf); return 0; }
	if (t->check_log == 1 && t->expected_ret != 0 && !strstr(hwr_log_buf, "not found")) { snprintf(why, sizeof(why), "log lacks the not found line: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_setNeighborReportActivation(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_setNeighborReportActivation_suite[i].test_name != NULL; i++) {
		hwr_snr_case_t *test = &wifi_hal_setNeighborReportActivation_suite[i];

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
	printf("\nwifi_hal_setNeighborReportActivation: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
