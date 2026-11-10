/*
 * TEST RUNNER: sg_wifi_hal_setRadioOperatingParameters_test
 *
 * test_sg_wifi_hal_setRadioOperatingParameters() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in radio slots other than the addressed one, the
 * interface slots beyond the ones in the radio's interface map, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The radio's own state and the caller's operationParam are
 * written by the function (the operating class is stored back into it), so they stay readable.  run_all_tests compares the result with the table's CORRECT behaviour: return value, number of
 * nl80211_switch_channel / nl80211_update_wiphy / platform nvram / update_hostap_config_params calls, the radio's channel / enable state and configured flag afterwards, no allocation left
 * over (the counted malloc / free), the configuration_in_progress flag cleared and the guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wro.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static wifi_radio_operationParam_t param;
static int ret_val;

static int radio_slot(const hwr_wro_case_t *t) { return (t->index >= 0 && t->index < HWR_WRO_MAXR) ? t->index : 0; }

static void poison(int on, const hwr_wro_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	int nif = t->n_ap + t->n_sta; if (nif < 1) nif = 1;

	for (int i = 0; i < HWR_WRO_MAXR; i++) if (i != radio_slot(t)) fn(&hwr_wro_world.radios[i], sizeof(hwr_wro_world.radios[i]));
	for (int i = nif; i < HWR_WRO_MAXI; i++) fn(&hwr_wro_world.ifs[i], sizeof(hwr_wro_world.ifs[i]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_setRadioOperatingParameters(const hwr_wro_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_setRadioOperatingParameters((wifi_radio_index_t)t->index, t->param_null ? NULL : &param);
	poison(0, t);
}

static void fill_param(const hwr_wro_case_t *t, wifi_radio_operationParam_t *p)
{
	memset(p, 0, sizeof(*p));
	p->enable = t->enable_new;
	p->band = t->band ? (wifi_freq_bands_t)t->band : WIFI_FREQUENCY_5_BAND;
	p->channel = t->channel;
	p->channelWidth = (wifi_channelBandwidth_t)t->width;
	p->countryCode = t->bad_country ? (wifi_countrycode_type_t)(wifi_countrycode_ZW + 1) : wifi_countrycode_US;
	p->DfsEnabled = t->dfs_new;
	p->EcoPowerDown = t->eco;
	p->transmitPower = t->power_new;
	p->DfsEnabledBootup = 1;
	p->operatingClass = 115;
}

static int check(const hwr_wro_case_t *t)
{
	const hwr_wro_world_t *w = &hwr_wro_world;
	const wifi_radio_info_t *r = &w->radios[radio_slot(t)];

	if (ret_val != t->exp_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, t->exp_ret); return 0; }
	if (w->c_switch != t->exp_sw) { snprintf(why, sizeof(why), "nl80211_switch_channel ran %d times, expected %d", w->c_switch, t->exp_sw); return 0; }
	if (w->c_wiphy != t->exp_wiphy) { snprintf(why, sizeof(why), "nl80211_update_wiphy ran %d times, expected %d", w->c_wiphy, t->exp_wiphy); return 0; }
	if (w->c_nvram != t->exp_nvram) { snprintf(why, sizeof(why), "platform nvram hook ran %d times, expected %d", w->c_nvram, t->exp_nvram); return 0; }
	if (w->c_cfg != t->exp_cfg) { snprintf(why, sizeof(why), "update_hostap_config_params ran %d times, expected %d", w->c_cfg, t->exp_cfg); return 0; }
	if (t->exp_ch && r->oper_param.channel != (unsigned)t->exp_ch) { snprintf(why, sizeof(why), "radio channel %u afterwards, expected %d", r->oper_param.channel, t->exp_ch); return 0; }
	if (t->exp_en && (r->oper_param.enable ? 2 : 1) != t->exp_en) { snprintf(why, sizeof(why), "radio enable %d afterwards, expected %d", r->oper_param.enable, t->exp_en == 2); return 0; }
	if ((int)r->configured != t->exp_cfgd) { snprintf(why, sizeof(why), "radio configured %d afterwards, expected %d", r->configured, t->exp_cfgd); return 0; }
	if (r->configuration_in_progress) { snprintf(why, sizeof(why), "configuration_in_progress left set"); return 0; }
	if (w->live_alloc != 0) { snprintf(why, sizeof(why), "%d allocation(s) not freed", w->live_alloc); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wro_case_t *t)
{
	hwr_wro_world_t *w = &hwr_wro_world;
	int slot = radio_slot(t);

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	w->no_radio = t->no_radio; w->no_primary = t->no_primary; w->pre_mode = t->pre_mode; w->nvram_fn = t->nvram_fn; w->dfs_fn = t->dfs_fn;
	w->hostap_fail = t->hostap_fail; w->wiphy_fail = t->wiphy_fail; w->switch_ret = t->switch_ret; w->ifparam_fail = t->ifparam_fail; w->malloc_fail = t->malloc_fail;
	fill_param(t, &param);
	for (int i = 0; i < HWR_WRO_MAXR; i++) { w->radios[i].index = i; w->radios[i].radio_presence = true; w->radios[i].interface_map = &w->map; }
	wifi_radio_info_t *r = &w->radios[slot];
	r->radio_presence = !t->sleeping;
	r->configured = t->configured;
	fill_param(t, &r->oper_param);                       /* same parameters ... */
	r->oper_param.enable = t->r_enable;                  /* ... except the state the row says differs */
	r->oper_param.DfsEnabled = t->r_dfs;
	if (t->r_channel) r->oper_param.channel = t->r_channel;
	if (t->r_width) r->oper_param.channelWidth = (wifi_channelBandwidth_t)t->r_width;
	r->oper_param.transmitPower = t->r_power ? t->r_power : t->power_new;
	if (t->country_new) r->oper_param.countryCode = wifi_countrycode_CA;
	int n = 0;
	for (int i = 0; i < t->n_ap && n < HWR_WRO_MAXI; i++, n++) {
		wifi_interface_info_t *f = &w->ifs[n];
		f->vap_info.vap_index = n; f->vap_info.radio_index = slot; f->vap_info.vap_mode = wifi_vap_mode_ap;
		f->vap_info.u.bss_info.enabled = t->ap_enabled; f->bss_started = t->ap_started; f->vap_initialized = true;
		f->u.ap.hapd.iface = &w->hiface; f->u.ap.hapd.conf = &w->hconf;
		snprintf(f->name, sizeof(f->name), "wlan%d", n);
		w->map.items[w->map.n++] = f;
	}
	for (int i = 0; i < t->n_sta && n < HWR_WRO_MAXI; i++, n++) {
		wifi_interface_info_t *f = &w->ifs[n];
		f->vap_info.vap_index = n; f->vap_info.radio_index = slot; f->vap_info.vap_mode = wifi_vap_mode_sta;
		f->u.sta.state = t->sta_completed ? WPA_COMPLETED : 0;
		snprintf(f->name, sizeof(f->name), "sta%d", n);
		w->map.items[w->map.n++] = f;
	}
	snprintf(w->ifs[0].name, sizeof(w->ifs[0].name), "%s", w->ifs[0].name[0] ? w->ifs[0].name : "wlan0");
}

extern "C" void run_all_tests_sg_wifi_hal_setRadioOperatingParameters(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_setRadioOperatingParameters_suite[i].test_name != NULL; i++) {
			hwr_wro_case_t *test = &sg_wifi_hal_setRadioOperatingParameters_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_setRadioOperatingParameters(test);

			if (check(test)) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_setRadioOperatingParameters: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
