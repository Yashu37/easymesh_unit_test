/* hwr_wcv.h - plumbing for the sg_wifi_hal_createVAP harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t are minimal STAND-INS with the members the function uses; wifi_vap_info_t, wifi_vap_info_map_t and wifi_radio_operationParam_t are the REAL types
 * from wifi_hal.h.  Every driver / netlink / hostapd / platform helper the function calls is a recording stub over runner data (hwr_wcv_world). */
#ifndef HWR_WCV_H
#define HWR_WCV_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#define HWR_WCV_MAXR 4
#define HWR_WCV_MAXI 10          /* interface slots: vap_index k uses ifs[k] */
#define WPA_DRIVER_FLAGS_BEACON_PROTECTION 0x1ul
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	unsigned char mac[6];
	char name[16];
	bool vap_initialized, bss_started;
	int beacon_set;
	union {
		struct { struct { unsigned long drv_flags; } iface; } ap;
		struct { int sta_4addr; } sta;
	} u;
} wifi_interface_info_t;
typedef struct wifi_radio_info_t {
	unsigned int index;
	bool radio_presence, configured;
	wifi_radio_operationParam_t oper_param;
} wifi_radio_info_t;
typedef int (*platform_pre_create_vap_t)(wifi_radio_index_t, wifi_vap_info_map_t *);
typedef int (*platform_create_vap_t)(wifi_radio_index_t, wifi_vap_info_map_t *);
typedef int (*platform_set_beacon_prot_t)(int, int);
typedef struct {
	wifi_radio_info_t radios[HWR_WCV_MAXR];
	wifi_interface_info_t ifs[HWR_WCV_MAXI];
	int exists[HWR_WCV_MAXI];                      /* get_interface_by_vap_index() finds ifs[k] */
	int no_radio, pre_fn, post_fn, beacon_fn, create_mode, update_fail_at, bridge_fail, hostap_if_fail, hostapd_ifs_fail, mac_ret, start_ret, reload_ret, tx_other;
	int c_create, c_update, c_start, c_reload, c_macctl, c_pre, c_post, c_hostapd_ifs, c_hostap_if, c_bridge, c_operstate, c_remove_bridge, c_mbssid, c_power, c_steer;
	int last_filtermode;
} hwr_wcv_world_t;
extern hwr_wcv_world_t hwr_wcv_world;
extern "C" int hwr_sg_wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef struct { int mode; int exists; int enabled; int bridge; int ignite; int invalid; int macf; } hwr_wcv_vap_t;   /* mode 0 ap / 1 sta / 2 monitor; macf 0 off / 1 black / 2 white */
typedef struct {
	const char *test_name;
	int index;
	int null_map;
	unsigned num_vaps;             /* map->num_vaps (more than 8: beyond the array, the map is allocated exactly) */
	hwr_wcv_vap_t v[3];            /* vap k < 3 uses v[k]; vap k >= 3 uses v[2] */
	int no_radio, sleeping, unconfigured, r_disabled;
	int init_state;                /* existing AP interfaces: 0 not initialised, 1 initialised and bss not started, 2 initialised and bss started */
	int pre_fn, post_fn, beacon_fn;
	int create_mode;               /* 0 ok, 1 fails, 2 reports success with a NULL interface */
	int update_fail_at;            /* nl80211_update_interface fails on this call (1-based; 0 never) */
	int bridge_fail;               /* 1: nl80211_create_bridge fails, 2: bringing the bridge up fails */
	int hostap_if_fail, hostapd_ifs_fail, mac_ret, start_ret, reload_ret;
	/* expected (CORRECT) behaviour */
	int exp_ret, exp_create, exp_update, exp_start, exp_reload, exp_macctl, exp_pre, exp_post;
	int exp_bssid0;                /* map->vap_array[0].u.bss_info.bssid is the interface's mac afterwards */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wcv_case_t;
extern hwr_wcv_case_t sg_wifi_hal_createVAP_suite[];
extern "C" void run_all_tests_sg_wifi_hal_createVAP(void);
#endif
