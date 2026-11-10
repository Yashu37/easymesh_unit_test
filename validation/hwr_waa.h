/* hwr_waa.h - plumbing for the sg_wifi_hal_addApAclDevice harness (src/wifi_hal.c, WIFI_HAL_VERSION_3_PHASE2 variant).
 * wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (interface->vap_info REAL wifi_vap_info_t, name, acl_map); acl_map_t and mac_addr_str_t have the real layout
 * of wifi_hal_priv.h / wifi_hal_generic.h.  get_interface_by_vap_index, hash_map_create / get / put, nl80211_set_acl and nl80211_kick_device are stubs over runner data; to_mac_str is the real
 * implementation (snprintf "%02x:..." into the 18-byte key); malloc is counted and can be made to fail. */
#ifndef HWR_WAA_H
#define HWR_WAA_H
#include "hwr_defs.h"
#include <stdint.h>
#define HWR_WAA_MAXI 4
#define HWR_WAA_MAXE 64
typedef struct { mac_addr_str_t mac_addr_str; mac_address_t mac_addr; } acl_map_t;
typedef struct { char *keys[HWR_WAA_MAXE]; void *data[HWR_WAA_MAXE]; int n; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	char name[32];
	hash_map_t *acl_map;
} wifi_interface_info_t;
typedef struct {
	wifi_interface_info_t ifs[HWR_WAA_MAXI];
	hash_map_t maps[HWR_WAA_MAXI], created;
	int n_if, malloc_fail, create_fail, set_acl_ret, kick_ret;
	int set_acl_calls, kick_calls, put_calls, create_calls;
} hwr_waa_world_t;
extern hwr_waa_world_t hwr_waa_world;
extern "C" int hwr_sg_wifi_hal_addApAclDevice(INT apIndex, mac_address_t DeviceMacAddress);
typedef struct {
	const char *test_name;
	int apIndex;
	int no_iface;                  /* no interface has this vap index */
	int vap_mode_sta;
	int mac_null;
	int acl_map_null;              /* interface->acl_map is NULL */
	int create_fail;               /* hash_map_create() fails */
	int pre_n;                     /* entries already in the ACL map */
	int mac_kind;                  /* 0 no zero byte, 1 all 0xff, 2 first byte 0, 3 zero in the middle, 4 the first entry already in the map */
	int filter_enable, filter_mode;/* vap->u.bss_info.mac_filter_enable / mac_filter_mode (0 black list, 1 white list) */
	int set_acl_ret, kick_ret;
	int malloc_fail;
	int n_if, ap_pos;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_waa_case_t;
extern hwr_waa_case_t sg_wifi_hal_addApAclDevice_suite[];
extern "C" void run_all_tests_sg_wifi_hal_addApAclDevice(void);
#endif
