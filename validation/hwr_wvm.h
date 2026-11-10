/* hwr_wvm.h - plumbing for the sg_wifi_hal_getRadioVapInfoMap harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (radio->interface_map, interface->vap_info / mac); wifi_vap_info_t and
 * wifi_vap_info_map_t are the REAL types from wifi_hal.h.  get_radio_by_rdk_index / hash_map_get_first / hash_map_get_next are stubs over runner data. */
#ifndef HWR_WVM_H
#define HWR_WVM_H
#include "hwr_defs.h"
#include <stdint.h>
#define HWR_WVM_MAXR 4
#define HWR_WVM_MAXI 20          /* interface slots (the vap_array of the map holds 8) */
#define HWR_WVM_MAPSZ 8
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	unsigned char mac[6];
} wifi_interface_info_t;
typedef struct { wifi_interface_info_t *items[HWR_WVM_MAXI]; int n; int itr; } hash_map_t;
typedef struct wifi_radio_info_t { unsigned int index; hash_map_t *interface_map; } wifi_radio_info_t;
typedef struct {
	wifi_radio_info_t radios[HWR_WVM_MAXR];
	wifi_interface_info_t ifs[HWR_WVM_MAXI];
	hash_map_t maps[HWR_WVM_MAXR];
	int no_radio;
} hwr_wvm_world_t;
extern hwr_wvm_world_t hwr_wvm_world;
extern "C" int hwr_sg_wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef struct {
	const char *test_name;
	int index;
	int null_map;
	int no_radio, null_imap;       /* get_radio_by_rdk_index() returns NULL / radio->interface_map is NULL */
	unsigned n_if;                 /* interfaces in the radio's interface map */
	unsigned neg_mask;             /* bit k: interface k has a negative vap_index (a radio interface, not a VAP) */
	int name_kind;                 /* vap_name of every VAP: 0 "wl_ap<k>", 1 "sim_sta<k>", 2 "mesh_sta<k>", 3 "mesh_st" (too short for the prefix), 4 empty, 5 32 characters without a terminator, 6 "sim_stax", 7 mixed per index */
	unsigned vap_index0;           /* vap_index of interface 0 (the others follow); 0x7fffffff: INT_MAX */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wvm_case_t;
extern hwr_wvm_case_t sg_wifi_hal_getRadioVapInfoMap_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getRadioVapInfoMap(void);
#endif
