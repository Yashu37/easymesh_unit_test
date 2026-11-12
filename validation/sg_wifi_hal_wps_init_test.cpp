/*
 * TEST RUNNER: sg_wifi_hal_wps_init_test
 *
 * test_sg_wifi_hal_wps_init() POISONS what the function must not touch, calls the handler and unpoisons: the guard slab, the log slot tail [HWR_LOG_USE, HWR_LOG_SZ), the padding of the conf / radios /
 * interfaces, and every member of the VAP, radios and interfaces that the function does not read (the VAP keeps only vap_name, wps.enable, wps.methods and wps.pin readable, so an unterminated name or PIN
 * read past its field is reported by ASan).  The VAP, conf, radio, interfaces, maps and the config_methods / ap_pin buffers are exactly sized heap blocks.  run_all_tests compares the whole conf with a reference model
 * of the CORRECT behaviour (see the construct file; the UUID model is SHA1 of the namespace id and the MAC computed here).  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <algorithm>
#include "hwr_wwi.h"
#include <sanitizer/asan_interface.h>

typedef struct { char *p; size_t n; } keep_t;
typedef struct { int idx; unsigned band; int kind; } rdesc_t;      /* kind: 0 no interface, 1 private_ssid_, 2 public_ssid_ */
typedef struct { int n; rdesc_t r[3]; } scen_t;
static const scen_t scens[7] = {
	{ 0, {} },
	{ 1, { {0, 0x1, 1} } },
	{ 3, { {0, 0x1, 1}, {1, 0x2, 1}, {2, 0x10, 1} } },
	{ 3, { {0, 0x1, 2}, {1, 0x2, 1}, {2, 0x10, 0} } },
	{ 2, { {0, 0x20, 1}, {1, 0x1, 1} } },
	{ 2, { {7, 0x1, 1}, {1, 0x8, 1} } },
	{ 1, { {0, 0x1, 0} } },
};

static char why[300];
static wifi_vap_info_t *vap;
static hwr_wwi_radio_t *radio;
static struct hwr_wwi_conf *conf;
static char *cm_buf, *pin_buf;
static hwr_wwi_iface_t *ifaces[3];
static hwr_wwi_map_t *maps[3];
static unsigned char macs[3][6];

/* poison [base, base + size) except the keep ranges; on == 0 unpoisons everything */
static void pz(void *base, size_t size, int on, keep_t *keep, int nk)
{
	if (!on) { __asan_unpoison_memory_region(base, size); return; }
	std::sort(keep, keep + nk, [](const keep_t &a, const keep_t &b) { return a.p < b.p; });
	char *cur = (char *)base;
	for (int i = 0; i < nk; i++) {
		if (keep[i].p > cur) __asan_poison_memory_region(cur, keep[i].p - cur);
		cur = keep[i].p + keep[i].n;
	}
	if (cur < (char *)base + size) __asan_poison_memory_region(cur, (char *)base + size - cur);
}

static void poison_vap(wifi_vap_info_t *v, int on)
{
	keep_t k[4] = { { v->vap_name, sizeof(v->vap_name) },
		{ (char *)&v->u.bss_info.wps.enable, sizeof(v->u.bss_info.wps.enable) },
		{ (char *)&v->u.bss_info.wps.methods, sizeof(v->u.bss_info.wps.methods) },
		{ (char *)v->u.bss_info.wps.pin, sizeof(v->u.bss_info.wps.pin) } };
	pz(v, sizeof(*v), on, k, 4);
}

static void poison_radio(hwr_wwi_radio_t *r, int on, int used)
{
	if (!used) { pz(r, sizeof(*r), on, NULL, 0); return; }
	keep_t k[3] = { { (char *)&r->rdk_radio_index, sizeof(r->rdk_radio_index) }, { (char *)&r->oper_param.band, sizeof(r->oper_param.band) },
		{ (char *)&r->interface_map, sizeof(r->interface_map) } };
	pz(r, sizeof(*r), on, k, 3);
}

static void poison_all(int on, const hwr_wwi_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	const scen_t *s = &scens[t->scen];

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	poison_vap(vap, on);
	{
		keep_t k[1] = { { (char *)&radio->oper_param.band, sizeof(radio->oper_param.band) } };
		pz(radio, sizeof(*radio), on, k, 1);
	}
	{
		keep_t k[3] = { { (char *)&conf->ignore_broadcast_ssid, sizeof(conf->ignore_broadcast_ssid) }, { (char *)&conf->wps_state, sizeof(conf->wps_state) },
			{ (char *)&conf->wps_cred_processing, sizeof(conf->wps_cred_processing) } };
		(void)k;
		fn(conf->pre, sizeof(conf->pre));
		fn(conf->post, sizeof(conf->post));
	}
	for (unsigned r = 0; r < 3; r++) poison_radio(&hwr_wwi_hal.radio_info[r], on, (int)r < s->n);
	for (int r = 0; r < s->n; r++) {
		if (!ifaces[r]) continue;
		hwr_wwi_iface_t *f = ifaces[r];
		keep_t k[3] = { { f->vap_info.vap_name, sizeof(f->vap_info.vap_name) }, { (char *)f->mac, sizeof(f->mac) }, { (char *)&f->next, sizeof(f->next) } };
		fn(f->pre, sizeof(f->pre));
		fn(f->post, sizeof(f->post));
		{
			char *a = (char *)&f->vap_info, *b = a + sizeof(f->vap_info);
			if (!on) fn(a, b - a);
			else { keep_t kk[1] = { { f->vap_info.vap_name, sizeof(f->vap_info.vap_name) } }; pz(a, b - a, 1, kk, 1); }
		}
		(void)k;
	}
}

static void (*volatile call_fn)(wifi_radio_info_t *, wifi_vap_info_t *, struct hostapd_bss_config *) = hwr_sg_wifi_hal_wps_init;

/* poison, call, unpoison */
static void test_sg_wifi_hal_wps_init(const hwr_wwi_case_t *t)
{
	poison_all(1, t);
	call_fn(t->radio_null ? NULL : radio, t->vap_null ? NULL : vap, t->conf_null ? NULL : conf);
	poison_all(0, t);
}

static const char *method_str(int m)
{
	return m == 0 ? "label display push_button keypad" :
	       m == 1 ? "display virtual_push_button physical_push_button push_button virtual_display" :
	       m == 2 ? "keypad label display" : NULL;
}

static int check(const hwr_wwi_case_t *t)
{
	static const u8 nsid[16] = { 0x52, 0x64, 0x80, 0xf8, 0xc9, 0x9b, 0x4b, 0xe5, 0xa6, 0x55, 0x58, 0xed, 0x5f, 0x5d, 0x60, 0x84 };
	const scen_t *s = &scens[t->scen];
	int enabled = !t->radio_null && !t->vap_null && t->enable && !t->ignore && t->rband != 0x10;
	char type[80] = "";
	int type_ok = 0;
	int want_state = 0, want_rf = 0, want_cred = 0, want_pbc = 0;
	u8 want_uuid[16]; char want_cm[512]; char want_pin[9];
	static const char *vnames[7] = { "private_ssid_2g", "private", "private_ssid_", "_", "public_ssid_5g", NULL, "" };

	if (t->conf_null) { for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; } return 1; }
	memset(want_uuid, t->uuid_pre ? 0x5A : 0, 16);
	memset(want_cm, 0, sizeof(want_cm)); strcpy(want_cm, "KEEP");
	memset(want_pin, 0, sizeof(want_pin)); strcpy(want_pin, "KEEP");
	if (enabled && t->vname != 5 && vnames[t->vname]) {
		const char *name = vnames[t->vname], *us = strrchr(name, '_');
		if (us) { memcpy(type, name, us - name + 1); type[us - name + 1] = 0; type_ok = 1; }
	}
	if (enabled && type_ok) {
		want_state = 2; want_cred = 1; want_pbc = 1;
		for (int i = 0; i < s->n; i++) {
			const rdesc_t *r = NULL;
			for (int j = 0; j < s->n; j++) if ((int)s->r[j].idx == i) { r = &s->r[j]; break; }
			if (!r || r->kind == 0) continue;
			char nm[40]; snprintf(nm, sizeof(nm), "%s_ssid_%dg", r->kind == 1 ? "private" : "public", 2);
			if (strncmp(nm, type, strlen(type)) != 0) continue;
			unsigned wb = r->band == 0x1 ? 0x01 : (r->band == 0x2 || r->band == 0x4 || r->band == 0x8) ? 0x02 : r->band == 0x10 ? 0 : 0xFF;
			if (wb == 0xFF) continue;
			want_rf |= wb;
			if (!t->uuid_pre) {
				int first = 1;
				for (int q = 0; q < i; q++) { /* an earlier matching radio already generated the UUID */
					const rdesc_t *rq = NULL;
					for (int j = 0; j < s->n; j++) if ((int)s->r[j].idx == q) { rq = &s->r[j]; break; }
					if (!rq || rq->kind == 0) continue;
					char nq[40]; snprintf(nq, sizeof(nq), "%s_ssid_%dg", rq->kind == 1 ? "private" : "public", 2);
					unsigned wq = rq->band == 0x1 || rq->band == 0x2 || rq->band == 0x4 || rq->band == 0x8 || rq->band == 0x10;
					if (strncmp(nq, type, strlen(type)) == 0 && wq) { first = 0; break; }
				}
				if (first) {
					unsigned char in[22], h[20];
					int ri = -1;
					for (int j = 0; j < s->n; j++) if ((int)s->r[j].idx == i) ri = j;
					memcpy(in, nsid, 16); memcpy(in + 16, macs[ri], 6);
					SHA1(in, 22, h);
					memcpy(want_uuid, h, 16);
				}
			}
		}
		if (method_str(t->methods) && !t->cm_null) { memset(want_cm, 0, sizeof(want_cm)); strncpy(want_cm, method_str(t->methods), 511); }
		{
			static const char *pins[5] = { "", "12345670", "1234567", "123456789", "87654321" };
			size_t pl = strnlen(pins[t->pin], 9);
			if (pl != 0 && !t->pin_null) { memset(want_pin, 0, 9); strncpy(want_pin, pins[t->pin], 8); }
		}
	}
	if (conf->wps_state != want_state) { snprintf(why, sizeof(why), "wps_state %d, expected %d", conf->wps_state, want_state); return 0; }
	if (conf->wps_rf_bands != want_rf) { snprintf(why, sizeof(why), "wps_rf_bands 0x%x, expected 0x%x", conf->wps_rf_bands, want_rf); return 0; }
	if (memcmp(conf->uuid, want_uuid, 16) != 0) { snprintf(why, sizeof(why), "uuid differs from the model"); return 0; }
	if (!t->cm_null && memcmp(cm_buf, want_cm, 512) != 0) { snprintf(why, sizeof(why), "config_methods is \"%.60s\", expected \"%.60s\"", cm_buf, want_cm); return 0; }
	if (!t->pin_null && memcmp(pin_buf, want_pin, 9) != 0) { snprintf(why, sizeof(why), "ap_pin is \"%.9s\", expected \"%.9s\"", pin_buf, want_pin); return 0; }
	if (conf->wps_cred_processing != want_cred) { snprintf(why, sizeof(why), "wps_cred_processing %d, expected %d", conf->wps_cred_processing, want_cred); return 0; }
	if (conf->pbc_in_m1 != want_pbc) { snprintf(why, sizeof(why), "pbc_in_m1 %d, expected %d", conf->pbc_in_m1, want_pbc); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wwi_case_t *t)
{
	const scen_t *s = &scens[t->scen];
	static const char *pins[5] = { "", "12345670", "1234567", "123456789", "87654321" };
	static const unsigned short meths[6] = { 0x180, 0x80, 0x100, 0, 0x1, 0x184 };

	memset(&hwr_wwi_hal, 0, sizeof(hwr_wwi_hal));
	hwr_wwi_hal.num_radios = s->n;
	for (int r = 0; r < 3; r++) { ifaces[r] = NULL; maps[r] = NULL; }
	for (int r = 0; r < s->n; r++) {
		hwr_wwi_hal.radio_info[r].rdk_radio_index = s->r[r].idx;
		hwr_wwi_hal.radio_info[r].oper_param.band = (wifi_freq_bands_t)s->r[r].band;
		maps[r] = (hwr_wwi_map_t *)calloc(1, sizeof(*maps[r]));
		hwr_wwi_hal.radio_info[r].interface_map = maps[r];
		for (int k = 0; k < 6; k++) macs[r][k] = (unsigned char)(k == 0 ? 0xA0 + r : k == 5 ? 5 + r : k);
		if (s->r[r].kind) {
			ifaces[r] = (hwr_wwi_iface_t *)calloc(1, sizeof(*ifaces[r]));
			snprintf(ifaces[r]->vap_info.vap_name, sizeof(ifaces[r]->vap_info.vap_name), "%s_ssid_%dg", s->r[r].kind == 1 ? "private" : "public", 2);
			memcpy(ifaces[r]->mac, macs[r], 6);
			maps[r]->first = ifaces[r];
		}
	}
	vap = (wifi_vap_info_t *)calloc(1, sizeof(*vap));
	switch (t->vname) {
	case 0: strcpy(vap->vap_name, "private_ssid_2g"); break;
	case 1: strcpy(vap->vap_name, "private"); break;
	case 2: strcpy(vap->vap_name, "private_ssid_"); break;
	case 3: strcpy(vap->vap_name, "_"); break;
	case 4: strcpy(vap->vap_name, "public_ssid_5g"); break;
	case 5: memset(vap->vap_name, 'a', sizeof(vap->vap_name)); memcpy(vap->vap_name, "private_ssid_", 13); vap->vap_name[sizeof(vap->vap_name) - 1] = '_'; break;
	default: break;
	}
	vap->u.bss_info.wps.enable = t->enable;
	vap->u.bss_info.wps.methods = (wifi_onboarding_methods_t)meths[t->methods];
	memset(vap->u.bss_info.wps.pin, 0, sizeof(vap->u.bss_info.wps.pin));
	memcpy(vap->u.bss_info.wps.pin, pins[t->pin], strnlen(pins[t->pin], 9));
	radio = (hwr_wwi_radio_t *)calloc(1, sizeof(*radio));
	radio->oper_param.band = (wifi_freq_bands_t)t->rband;
	conf = (struct hwr_wwi_conf *)calloc(1, sizeof(*conf));
	conf->wps_state = 2; conf->wps_rf_bands = 3; conf->ignore_broadcast_ssid = t->ignore;
	memset(conf->uuid, t->uuid_pre ? 0x5A : 0, 16);
	cm_buf = (char *)calloc(1, 512); strcpy(cm_buf, "KEEP");
	pin_buf = (char *)calloc(1, 9); strcpy(pin_buf, "KEEP");
	conf->config_methods = t->cm_null ? NULL : cm_buf;
	conf->ap_pin = t->pin_null ? NULL : pin_buf;
}

static void teardown(void)
{
	for (int r = 0; r < 3; r++) { free(ifaces[r]); free(maps[r]); ifaces[r] = NULL; maps[r] = NULL; }
	free(vap); free(radio); free(conf); free(cm_buf); free(pin_buf);
	vap = NULL; radio = NULL; conf = NULL; cm_buf = pin_buf = NULL;
}

extern "C" void run_all_tests_sg_wifi_hal_wps_init(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_wps_init_suite[i].test_name != NULL; i++) {
			hwr_wwi_case_t *test = &sg_wifi_hal_wps_init_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			setup(test);

			test_sg_wifi_hal_wps_init(test);

			int ok = check(test);
			teardown();
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_wps_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
