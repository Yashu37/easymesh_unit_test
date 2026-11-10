/* hwr_gim.h - plumbing for the sg_wifi_hal_getInterfaceMap harness (src/wifi_hal.c) */
#ifndef HWR_GIM_H
#define HWR_GIM_H
#include "hwr_defs.h"
#define HWR_GIM_MAX_TABLE 40
typedef char hwr_gim_name_t[32];
typedef char hwr_gim_vap_name_t[64];
typedef struct {
	unsigned int phy_index; unsigned int rdk_radio_index;
	hwr_gim_name_t interface_name; hwr_gim_name_t mld_interface_name; hwr_gim_name_t bridge_name;
	int vlan_id; unsigned int index; hwr_gim_vap_name_t vap_name;
} __attribute__((packed)) hwr_gim_entry_t;           /* same layout as wifi_interface_name_idex_map_t (176 bytes) */
typedef struct { unsigned int size; hwr_gim_entry_t table[HWR_GIM_MAX_TABLE]; int size_calls, map_calls; } hwr_gim_world_t;
extern hwr_gim_world_t hwr_gim_world;
extern "C" int hwr_sg_wifi_hal_getInterfaceMap(hwr_gim_entry_t *if_map, unsigned int max_entries, unsigned int *if_map_size);
typedef struct {
	const char *test_name;
	unsigned size;                 /* number of entries the interface map holds */
	unsigned max_entries;
	int map_mode;                  /* 0 NULL, 1 exact-size slab (size entries): the bytes around it are POISONED during the call, 2 dangling pointer */
	int size_mode;                 /* 0 if_map_size NULL, 1 valid */
	int calls;
	int expected_ret;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_gim_case_t;
extern hwr_gim_case_t sg_wifi_hal_getInterfaceMap_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getInterfaceMap(void);
#endif
