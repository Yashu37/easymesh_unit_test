/*
 * TEST RUNNER: sg_wifi_hal_getHalCapability_test
 *
 * test_sg_wifi_hal_getHalCapability() POISONS what the function must not touch, calls the handler and unpoisons; run_all_tests compares the result with a reference
 * model of the CORRECT behaviour.  The runner owns the output: a heap object of exactly sizeof(wifi_hal_capability_t) (redzones: any write beyond it aborts under ASan), preset to
 * 0x5A.  During the call the guard slab, the log slot tail [HWR_LOG_USE, HWR_LOG_SZ), and the stand-in radio slots / interface maps beyond the configured radio count are POISONED.
 * Checks: return value; version 3.0; numRadios; BssMaxStaAllow == 75 (the fields around the radio arrays must not be overwritten); serialNo / manufacturerModel / manufacturer /
 * software_version equal the shell replies without the trailing newline and cut to the 63 characters the 64-byte fields can hold; cm_mac; al_1905_mac and colocated_mode as the
 * EasyMesh config / interface rules give; per radio the presence flag and the capabilities; every interface firmware_version; one band query and one adjust call per radio.
 * Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_ghc.h"
#include <sanitizer/asan_interface.h>

#define FLD 64
static char why[240];
static wifi_hal_capability_t *hal_obj;

static void poison(int on, const hwr_ghc_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_ghc_world_t *w = &hwr_ghc_world;

	for (unsigned r = t->nrad < HWR_GHC_MAXR ? t->nrad : HWR_GHC_MAXR; r < HWR_GHC_MAXR; r++) fn(&w->hal.radio_info[r], sizeof(w->hal.radio_info[r]));
	for (int r = 0; r < HWR_GHC_MAXR; r++) for (int i = (r < (int)t->nrad ? t->ifaces : 0); i < HWR_GHC_MAXI; i++) fn(&w->ifs[r][i], sizeof(w->ifs[r][i]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned */
static int test_sg_wifi_hal_getHalCapability(const hwr_ghc_case_t *t)
{
	int ret;

	poison(1, t);
	ret = hwr_sg_wifi_hal_getHalCapability(t->hal_mode ? hal_obj : NULL);
	poison(0, t);
	return ret;
}

/* reference model: reply -> value stored in a 64-byte field (trailing newline removed, cut to 63 characters) */
static void want_str(const char *reply, char *out)
{
	char tmp[256];
	size_t len;

	snprintf(tmp, sizeof(tmp), "%s", reply ? reply : "");
	len = strlen(tmp);
	if (len != 0 && tmp[len - 1] == '\n') tmp[len - 1] = '\0';
	snprintf(out, FLD, "%s", tmp);
}
static void want_mac(const char *s, unsigned char *m)
{
	unsigned v[6]; char tmp[256];
	want_str(s, tmp);
	if (sscanf(tmp, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) for (int i = 0; i < 6; i++) m[i] = (unsigned char)v[i];
	else memset(m, 0, 6);
}

static int check(const hwr_ghc_case_t *t, int ret)
{
	wifi_hal_capability_t *h = hal_obj;
	char sn[FLD], md[FLD], sw[FLD];
	unsigned char cm[6], al[6];
	int col;
	unsigned nr = t->nrad < (unsigned)MAX_NUM_RADIOS ? t->nrad : (unsigned)MAX_NUM_RADIOS;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	if (!t->hal_mode) return 1;
	if (h->version.major != 3 || h->version.minor != 0) { snprintf(why, sizeof(why), "version %u.%u", h->version.major, h->version.minor); return 0; }
	if (h->wifi_prop.BssMaxStaAllow != 75) { snprintf(why, sizeof(why), "BssMaxStaAllow = %u, expected 75 (overwritten)", h->wifi_prop.BssMaxStaAllow); return 0; }
	if (t->nrad <= (unsigned)MAX_NUM_RADIOS && h->wifi_prop.numRadios != t->nrad) { snprintf(why, sizeof(why), "numRadios = %u, expected %u", h->wifi_prop.numRadios, t->nrad); return 0; }
	want_str(t->serial, sn); want_str(t->model, md); want_str(t->image, sw);
	if (strncmp(h->wifi_prop.serialNo, sn, FLD) != 0 || strlen(h->wifi_prop.serialNo) >= FLD) { snprintf(why, sizeof(why), "serialNo is not \"%.20s...\" (len %zu)", sn, strnlen(h->wifi_prop.serialNo, 400)); return 0; }
	if (strncmp(h->wifi_prop.manufacturerModel, md, FLD) != 0 || strlen(h->wifi_prop.manufacturerModel) >= FLD) { snprintf(why, sizeof(why), "manufacturerModel is not \"%.20s...\" (len %zu)", md, strnlen(h->wifi_prop.manufacturerModel, 400)); return 0; }
	if (strncmp(h->wifi_prop.manufacturer, md, FLD) != 0 || strlen(h->wifi_prop.manufacturer) >= FLD) { snprintf(why, sizeof(why), "manufacturer is not the model (len %zu)", strnlen(h->wifi_prop.manufacturer, 400)); return 0; }
	if (strncmp(h->wifi_prop.software_version, sw, FLD) != 0 || strlen(h->wifi_prop.software_version) >= FLD) { snprintf(why, sizeof(why), "software_version is not \"%.20s...\" (len %zu)", sw, strnlen(h->wifi_prop.software_version, 400)); return 0; }
	want_mac(t->cm, cm);
	if (memcmp(h->wifi_prop.cm_mac, cm, 6) != 0) { snprintf(why, sizeof(why), "cm_mac wrong"); return 0; }
	/* al mac / colocated mode */
	{
		const hwr_ghc_world_t *w = &hwr_ghc_world;
		if (t->eth_ret == 0) memcpy(al, w->eth_mac, 6); else memset(al, 0, 6);
		if (t->off_flag) col = -1;
		else {
			col = 0;
			if (t->js_ret == 0) want_mac(t->js_val, al); else { memset(al, 0, 6); col = -1; }
			if (t->ji_ret == 0) {
				col = t->ji_val;
				if (t->found) {
					const char *n = t->ifname;
					if (strncmp(n, "eth", 3) && strncmp(n, "lo", 2) && strncmp(n, "lan", 3) && strncmp(n, "brlan", 5) && t->conf_ret != 0) col = -1;
				} else { memset(al, 0, 6); col = -1; }
			} else col = -1;
		}
	}
	if (memcmp(h->wifi_prop.al_1905_mac, al, 6) != 0) { snprintf(why, sizeof(why), "al_1905_mac wrong"); return 0; }
	if (h->wifi_prop.colocated_mode != col) { snprintf(why, sizeof(why), "colocated_mode = %d, expected %d", h->wifi_prop.colocated_mode, col); return 0; }
	for (unsigned r = 0; r < nr; r++) {
		if (h->wifi_prop.radio_presence[r] != hwr_ghc_world.hal.radio_info[r].radio_presence) { snprintf(why, sizeof(why), "radio_presence[%u] wrong", r); return 0; }
		if (memcmp(&h->wifi_prop.radiocap[r], &hwr_ghc_world.hal.radio_info[r].capab, sizeof(wifi_radio_capabilities_t)) != 0) { snprintf(why, sizeof(why), "radiocap[%u] wrong", r); return 0; }
		for (int i = 0; i < t->ifaces; i++)
			if (strcmp(hwr_ghc_world.ifs[r][i].firmware_version, sw) != 0) { snprintf(why, sizeof(why), "radio %u interface %d firmware_version wrong", r, i); return 0; }
	}
	if (t->nrad <= (unsigned)MAX_NUM_RADIOS && (hwr_ghc_world.band_calls != t->nrad || hwr_ghc_world.adjust_calls != t->nrad)) { snprintf(why, sizeof(why), "band / adjust called %u / %u times, expected %u", hwr_ghc_world.band_calls, hwr_ghc_world.adjust_calls, t->nrad); return 0; }
	return 1;
}

static void setup(const hwr_ghc_case_t *t)
{
	hwr_ghc_world_t *w = &hwr_ghc_world;

	memset(w, 0, sizeof(*w));
	w->hal.num_radios = t->nrad;
	for (unsigned r = 0; r < HWR_GHC_MAXR; r++) {
		hwr_ghc_radio_t *x = &w->hal.radio_info[r];
		x->index = r; x->rdk_radio_index = r + t->shift; x->radio_presence = (r % 2) == 0;
		memset(&x->capab, (int)(r + 1), sizeof(x->capab));
		w->maps[r].n = t->ifaces;
		for (int i = 0; i < t->ifaces; i++) { w->maps[r].items[i] = &w->ifs[r][i]; snprintf(w->ifs[r][i].name, sizeof(w->ifs[r][i].name), "wl%u.%d", r, i); }
		x->interface_map = &w->maps[r];
	}
	w->serial = t->serial; w->model = t->model; w->image = t->image; w->cm = t->cm;
	w->off_flag = t->off_flag; w->access_errno = t->access_errno;
	w->js_ret = t->js_ret; w->js_val = t->js_val; w->ji_ret = t->ji_ret; w->ji_val = t->ji_val;
	w->found = t->found; w->ifname = t->ifname; w->conf_ret = t->conf_ret;
	w->eth_ret = t->eth_ret; for (int i = 0; i < 6; i++) w->eth_mac[i] = (unsigned char)(0xe0 + i);
}

extern "C" void run_all_tests_sg_wifi_hal_getHalCapability(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_getHalCapability_suite[i].test_name != NULL; i++) {
		hwr_ghc_case_t *test = &sg_wifi_hal_getHalCapability_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		setup(test);
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		hal_obj = (wifi_hal_capability_t *)malloc(sizeof(wifi_hal_capability_t));
		memset(hal_obj, 0x5A, sizeof(*hal_obj));

		int ret = test_sg_wifi_hal_getHalCapability(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		free(hal_obj);
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_getHalCapability: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
