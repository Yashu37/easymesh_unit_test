/* hwr_wdm.h - plumbing for the sg_wifi_hal_delApAclDevices harness (src/wifi_hal.c).
 * wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (interface->vap_info REAL wifi_vap_info_t, name, acl_map); acl_map_t and mac_addr_str_t have the real layout
 * of wifi_hal_priv.h / wifi_hal_generic.h.  get_interface_by_vap_index, hash_map_get_first / get_next / remove and nl80211_set_acl are stubs over runner data that follow src/collection.c: the iterator
 * (map->itr) is advanced by get_next, get_next(map, data) continues after the element holding data, remove(map, key) compares keys with strncmp(.., 100), frees the stored key and returns the data. */
#ifndef HWR_WDM_H
#define HWR_WDM_H
#include "hwr_defs.h"
#include <stdint.h>
#define HWR_WDM_MAXI 4
#define HWR_WDM_MAXE 64
typedef struct { mac_addr_str_t mac_addr_str; mac_address_t mac_addr; } acl_map_t;
typedef struct { char *keys[HWR_WDM_MAXE]; void *data[HWR_WDM_MAXE]; int n; int itr; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	char name[32];
	hash_map_t *acl_map;
} wifi_interface_info_t;
typedef struct {
	wifi_interface_info_t ifs[HWR_WDM_MAXI];
	hash_map_t maps[HWR_WDM_MAXI];
	int n_if, set_acl_ret, set_acl_calls, remove_calls;
} hwr_wdm_world_t;
extern hwr_wdm_world_t hwr_wdm_world;
extern "C" int hwr_sg_wifi_hal_delApAclDevices(INT apIndex);
typedef struct {
	const char *test_name;
	int apIndex;
	int no_iface;                  /* no interface has this vap index */
	int vap_mode_sta;
	int acl_map_null;              /* interface->acl_map is NULL */
	int n_entries;                 /* entries in the ACL map: key "02:aa:bb:cc:dd:<i+1>" == mac_addr_str */
	int long_kind;                 /* 0 none; 1 one more entry whose key is 18 characters; 2 one more entry whose key is longer ("... VLAN_ID=5"): mac_addr_str holds its first 18 characters, no terminator */
	int set_acl_ret;
	int n_if, ap_pos;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdm_case_t;
extern hwr_wdm_case_t sg_wifi_hal_delApAclDevices_suite[];
extern "C" void run_all_tests_sg_wifi_hal_delApAclDevices(void);
#endif
