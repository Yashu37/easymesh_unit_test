/* hwr_wdl.h - plumbing for the sg_wifi_hal_delApAclDevice harness (src/wifi_hal.c, the CHAR * variant: the WIFI_HAL_VERSION_3_PHASE2 variant does not compile, see the handler file).
 * wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (interface->vap_info REAL wifi_vap_info_t, name, acl_map); acl_map_t and mac_addr_str_t have the real layout
 * of wifi_hal_priv.h / wifi_hal_generic.h.  get_interface_by_vap_index, hash_map_get / remove / put and nl80211_set_acl are stubs over runner data (get compares keys with strncmp(.., 100) and
 * remove frees the stored key and returns the data, like src/collection.c); to_mac_bytes is the real implementation (sscanf "%02x:..."); malloc is counted and can be made to fail. */
#ifndef HWR_WDL_H
#define HWR_WDL_H
#include "hwr_defs.h"
#include <stdint.h>
#define HWR_WDL_MAXI 4
#define HWR_WDL_MAXE 64
typedef struct { mac_addr_str_t mac_addr_str; mac_address_t mac_addr; } acl_map_t;
typedef struct { char *keys[HWR_WDL_MAXE]; void *data[HWR_WDL_MAXE]; int n; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	char name[32];
	hash_map_t *acl_map;
} wifi_interface_info_t;
typedef struct {
	wifi_interface_info_t ifs[HWR_WDL_MAXI];
	hash_map_t maps[HWR_WDL_MAXI];
	int n_if, malloc_fail, set_acl_ret;
	int set_acl_calls, put_calls, remove_calls;
} hwr_wdl_world_t;
extern hwr_wdl_world_t hwr_wdl_world;
extern "C" int hwr_sg_wifi_hal_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress);
typedef struct {
	const char *test_name;
	int apIndex;
	int no_iface;                  /* no interface has this vap index */
	int vap_mode_sta;
	int mac_null;
	int acl_map_null;              /* interface->acl_map is NULL */
	int pre_n;                     /* entries in the ACL map: "02:aa:bb:cc:dd:0<i+1>" */
	int mac_kind;                  /* 0 the first entry, 1 the second entry, 2 the third entry, 3 valid but not in the map, 4 upper-case form of the first entry, 5 short string "ab:cd" present in the map as an extra entry, 6 short string "ab:cd" not in the map, 7 empty string */
	int set_acl_ret;
	int malloc_fail;
	int n_if, ap_pos;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdl_case_t;
extern hwr_wdl_case_t sg_wifi_hal_delApAclDevice_suite[];
extern "C" void run_all_tests_sg_wifi_hal_delApAclDevice(void);
#endif
