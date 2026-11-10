/*
 * TEST RUNNER: sg_wifi_hal_rnr_init_test
 *
 * test_sg_wifi_hal_rnr_init() POISONS what the function must not touch, calls the handler and unpoisons: the radio slots other than the addressed one (and all of them when no radio is found), the
 * guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The ssid is an exact heap block of ssid_len + 1 bytes, so a read past its NUL is a heap-buffer-overflow; rnr.ssid is the 32-byte ssid_t, so
 * a write past it is caught by the struct's own redzone-free layout check below (the bytes after rnr.ssid hold the radio's rnr_enabled and next radio, the former is checked and the latter is poisoned).
 * run_all_tests compares the radio state with a reference model of the CORRECT behaviour (see the construct file); guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wri.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static char *ssid;
static uint32_t crc(const char *s, size_t n)
{
	uint32_t c = 0xFFFFFFFFu;
	for (size_t i = 0; i < n; i++) { c ^= (unsigned char)s[i]; for (int b = 0; b < 8; b++) c = (c >> 1) ^ ((c & 1u) ? 0xEDB88320u : 0u); }
	return c ^ 0xFFFFFFFFu;
}
static int radio_ok(const hwr_wri_case_t *t) { return !t->no_radio && t->radio_index < HWR_WRI_MAXR; }
static int has_ssid(const hwr_wri_case_t *t) { return t->ssid_mode == 2 && t->ssid_len > 0; }

static void poison(int on, const hwr_wri_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wri_world_t *w = &hwr_wri_world;

	for (int i = 0; i < HWR_WRI_MAXR; i++)
		if (!radio_ok(t) || i != (int)t->radio_index) fn(&w->radios[i], sizeof(w->radios[i]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_rnr_init(const hwr_wri_case_t *t)
{
	poison(1, t);
	hwr_sg_wifi_hal_rnr_init((wifi_radio_index_t)t->radio_index, t->ssid_mode == 0 ? NULL : ssid);
	poison(0, t);
}

static int check(const hwr_wri_case_t *t)
{
	const hwr_wri_world_t *w = &hwr_wri_world;

	for (int i = 0; i < HWR_WRI_MAXR; i++) {
		const wifi_radio_info_t *r = &w->radios[i];
		if (!radio_ok(t) || i != (int)t->radio_index) {
			if (r->rnr_enabled != (t->dirty != 0) || r->rnr.nfreq != (t->dirty ? 5u : 0u) || r->index != (unsigned)i) { snprintf(why, sizeof(why), "radio %d was modified", i); return 0; }
			continue;
		}
		if (r->rnr_enabled) { snprintf(why, sizeof(why), "rnr_enabled not cleared"); return 0; }
		if (r->rnr.nfreq != 0 || r->rnr.freq[0] != 0 || r->rnr.freq[RNR_FREQ_CAP - 1] != 0 || r->rnr.scan_started) { snprintf(why, sizeof(why), "rnr not cleared"); return 0; }
		if (has_ssid(t)) {
			size_t n = t->ssid_len;
			size_t keep = n > 31 ? 31 : n;
			if (!r->rnr.have_ssid) { snprintf(why, sizeof(why), "have_ssid not set"); return 0; }
			if (r->rnr.ssid_crc != crc(ssid, n)) { snprintf(why, sizeof(why), "ssid_crc wrong"); return 0; }
			if (memcmp(r->rnr.ssid, ssid, keep) != 0 || r->rnr.ssid[keep] != '\0') { snprintf(why, sizeof(why), "stored ssid wrong or not terminated"); return 0; }
		} else {
			if (r->rnr.have_ssid || r->rnr.ssid_crc != 0 || r->rnr.ssid[0] != '\0') { snprintf(why, sizeof(why), "ssid state not empty"); return 0; }
		}
		if (r->index != t->radio_index) { snprintf(why, sizeof(why), "radio index modified"); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wri_case_t *t)
{
	hwr_wri_world_t *w = &hwr_wri_world;

	memset(w, 0, sizeof(*w));
	w->no_radio = t->no_radio;
	for (int i = 0; i < HWR_WRI_MAXR; i++) {
		w->radios[i].index = i;
		if (t->dirty) {
			memset(w->radios[i].rnr.freq, 0x5A, sizeof(w->radios[i].rnr.freq));
			w->radios[i].rnr.nfreq = 5; w->radios[i].rnr.ssid_crc = 0x1234; w->radios[i].rnr.have_ssid = true; w->radios[i].rnr.scan_started = true;
			memset(w->radios[i].rnr.ssid, 'Z', sizeof(w->radios[i].rnr.ssid)); w->radios[i].rnr_enabled = true;
		}
	}
	ssid = NULL;
	if (t->ssid_mode == 1) { ssid = (char *)malloc(1); ssid[0] = '\0'; }
	else if (t->ssid_mode == 2) { ssid = (char *)malloc(t->ssid_len + 1); for (int i = 0; i < t->ssid_len; i++) ssid[i] = (char)('A' + i % 26); ssid[t->ssid_len] = '\0'; }
}

extern "C" void run_all_tests_sg_wifi_hal_rnr_init(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_rnr_init_suite[i].test_name != NULL; i++) {
			hwr_wri_case_t *test = &sg_wifi_hal_rnr_init_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_rnr_init(test);

			int ok = check(test);
			free(ssid); ssid = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_rnr_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
