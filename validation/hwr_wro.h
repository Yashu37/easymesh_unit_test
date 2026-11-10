/* hwr_wro.h - plumbing for the sg_wifi_hal_setRadioOperatingParameters harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t / g_wifi_hal / hash_map_t are minimal STAND-INS with the members the function uses; wifi_radio_operationParam_t and wifi_vap_info_t are the REAL
 * types from wifi_hal.h.  Every driver / netlink / hostapd / platform helper the function calls is a recording stub over runner data (hwr_wro_world). */
#ifndef HWR_WRO_H
#define HWR_WRO_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#define HWR_WRO_MAXR 4          /* radio slots in the world (valid indexes are 0 .. MAX_NUM_RADIOS-1) */
#define HWR_WRO_MAXI 4          /* interface slots per radio */
#define WPA_COMPLETED 9

struct hwr_wro_wpa_psk { struct hwr_wro_wpa_psk *next; };
struct hostapd_ssid { struct hwr_wro_wpa_psk *wpa_psk; };
struct hostapd_bss_config { struct hostapd_ssid ssid; };
struct hostapd_iface { int dummy; };
struct hostapd_data { struct hostapd_iface *iface; struct hostapd_bss_config *conf; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	bool vap_initialized, bss_started;
	int beacon_set;
	char name[16];
	union {
		struct { struct hostapd_data hapd; } ap;
		struct { int state; } sta;
	} u;
} wifi_interface_info_t;
typedef struct { wifi_interface_info_t *items[HWR_WRO_MAXI]; int n; int itr; } hash_map_t;
typedef struct wifi_radio_info_t {
	unsigned int index;
	bool radio_presence, configured, configuration_in_progress;
	wifi_radio_operationParam_t oper_param;
	hash_map_t *interface_map;
} wifi_radio_info_t;
typedef int (*platform_set_radio_params_t)(wifi_radio_index_t, wifi_radio_operationParam_t *);
typedef int (*platform_set_radio_pre_init_t)(wifi_radio_index_t, wifi_radio_operationParam_t *);
typedef int (*platform_set_dfs_t)(wifi_radio_index_t, wifi_radio_operationParam_t *);
typedef struct { pthread_mutex_t hapd_lock; } hwr_wro_hal_t;
typedef struct {
	hwr_wro_hal_t hal;
	wifi_radio_info_t radios[HWR_WRO_MAXR];
	wifi_interface_info_t ifs[HWR_WRO_MAXI];
	hash_map_t map;
	struct hostapd_iface hiface;
	struct hostapd_bss_config hconf;
	int no_radio, no_primary, pre_mode, nvram_fn, dfs_fn, hostap_fail, wiphy_fail, switch_ret, ifparam_fail, malloc_fail, opclass_calls;
	int live_alloc;
	int c_cfg, c_wiphy, c_switch, c_nvram, c_dfs, c_txpow, c_regdom, c_start, c_reload, c_deinit, c_disc, c_operstate, c_pre, c_ifen_true, c_ifen_false, c_hradio, c_dfsboot;
	unsigned last_txpow; int last_regdom;
} hwr_wro_world_t;
extern hwr_wro_world_t hwr_wro_world;
extern "C" int hwr_sg_wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef struct {
	const char *test_name;
	int index;                     /* radio index argument */
	int param_null;
	int bad_country;               /* countryCode beyond wifi_countrycode_ZW */
	unsigned channel;              /* new channel (0 -> the op class lookup fails) */
	int width;                     /* new channel width (0 -> invalid) */
	int band;                      /* 0 -> 5 GHz */
	int dfs_new, enable_new, eco;
	unsigned power_new;
	int country_new;               /* 1: countryCode differs from the radio's current one */
	/* radio state */
	int no_radio, sleeping, configured, r_enable, r_dfs;
	unsigned r_channel; int r_width; unsigned r_power;
	int no_primary;
	/* platform hooks / driver behaviour */
	int pre_mode;                  /* 0 no hook, 1 hook ok, 2 hook fails */
	int nvram_fn, dfs_fn;
	int hostap_fail;               /* update_hostap_config_params(): 1 fails every call, 2 fails the first call only */
	int wiphy_fail, switch_ret, ifparam_fail, malloc_fail;
	int n_ap, ap_started, ap_enabled, n_sta, sta_completed;
	/* expected (CORRECT) behaviour */
	int exp_ret;
	int exp_sw, exp_wiphy, exp_nvram, exp_cfg;
	int exp_ch;                    /* radio->oper_param.channel afterwards (0: not checked) */
	int exp_en;                    /* radio->oper_param.enable afterwards (0: not checked, 1: disabled, 2: enabled) */
	int exp_cfgd;                  /* radio->configured afterwards */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wro_case_t;
extern hwr_wro_case_t sg_wifi_hal_setRadioOperatingParameters_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setRadioOperatingParameters(void);
#endif
