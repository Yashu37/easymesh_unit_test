/* hwr_wam.h - plumbing for the sg_wifi_hal_setApMacAddressControlMode harness (src/wifi_hal.c).
 * wifi_interface_info_t is a minimal STAND-IN with the member the function uses (vap_info); wifi_vap_info_t and the mac filter enum are the REAL types from the HAL headers.  get_interface_by_vap_index is a
 * lookup over the runner's interfaces (vap indexes 0, 1, 5, 14; NULL for any other); nl80211_set_acl (wifi_hal_priv.h:1074) is a recording stub that captures the interface and the filter fields it
 * would apply. */
#ifndef HWR_WAM_H
#define HWR_WAM_H
#include "hwr_defs.h"
#include <stdint.h>
#include <stdbool.h>
#define HWR_WAM_MAXI 4
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	char tail[24];
} wifi_interface_info_t;
typedef struct {
	wifi_interface_info_t ifs[HWR_WAM_MAXI];
	int vap_ids[HWR_WAM_MAXI];
	int acl_calls, acl_ret; wifi_interface_info_t *acl_if; int acl_enable; int acl_mode;
} hwr_wam_world_t;
extern hwr_wam_world_t hwr_wam_world;
extern "C" int hwr_sg_wifi_hal_setApMacAddressControlMode(uint32_t apIndex, uint32_t mac_filter_mode);
typedef struct {
	const char *test_name;
	uint32_t ap_index;             /* vap index argument (interfaces exist for 0, 1, 5, 14) */
	uint32_t mode;                 /* mac_filter_mode argument */
	int enabled;                   /* vap bss enabled */
	int sta_mode;                  /* vap_mode is STA instead of AP */
	int pre_enable, pre_mode;      /* mac filter enable / mode before the call (mode: 0 black list, 1 white list) */
	int acl_ret;                   /* nl80211_set_acl result */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wam_case_t;
extern hwr_wam_case_t sg_wifi_hal_setApMacAddressControlMode_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setApMacAddressControlMode(void);
#endif
