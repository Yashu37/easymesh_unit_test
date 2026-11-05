/* hwr_grm.h - types / plumbing for the wifi_hal_steering_clientRemove harness */
#ifndef HWR_GRM_H
#define HWR_GRM_H
#include "hwr_gcs.h"          /* real bm_sta_list_t layout (hwr_bm_sta_list_t), BM_STA_TYPE_CLIENT_SET, steering lock world type */
#undef wifi_interface_info_t
typedef struct hwr_grm_map { int n; char key[4][18]; hwr_bm_sta_list_t *data[4]; } hwr_grm_map_t;
typedef struct { int vap_index; hwr_grm_map_t *bm_sta_map; } hwr_grm_if_t;
#define wifi_interface_info_t hwr_grm_if_t
extern hwr_gcs_world_t hwr_grm_world;
extern "C" hwr_grm_if_t *hwr_grm_get_interface(unsigned int vap_index);
extern "C" void *hwr_grm_hash_map_get(hwr_grm_map_t *map, const char *key);
extern "C" int hwr_grm_del_mac_list(uint32_t vap_index, hwr_bm_sta_list_t *sta_info);
extern "C" void hwr_grm_del_stalist(hwr_grm_if_t *interface, mac_address_t client_mac, uint8_t type);
extern "C" int hwr_grm_kick_device(hwr_grm_if_t *interface, mac_address_t addr);
extern "C" INT hwr_wifi_hal_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac);   /* renamed, see the handler file */

typedef struct {
	const char *test_name;
	unsigned group; int ap; unsigned char mac[6];
	unsigned null_mask;            /* 1: client_mac passed as NULL */
	int entry_type;                /* type bits of the client's entry in the AP's map; 0 = no entry */
	int other_entry;               /* a second entry (another MAC) in the same map */
	int map_null;                  /* the interface's bm_sta_map is NULL */
	int kick_ret, del_ret;
	int calls; int check_log;
	int expected_ret;
	int expect_del;                /* wifi_steering_del_mac_list + steering_del_stalist called */
	int expect_removed;            /* entry removed ("freed") from the map */
	int expect_kick;
	int forked;
} hwr_grm_case_t;
extern hwr_grm_case_t wifi_hal_steering_clientRemove_suite[];
extern "C" void run_all_tests_wifi_hal_steering_clientRemove(void);
typedef struct {
	int seq; int del_calls, del_seq; uint32_t del_vap; hwr_bm_sta_list_t *del_sta; unsigned char del_mac[6];
	int sl_calls, sl_seq; hwr_grm_if_t *sl_if; unsigned char sl_mac[6]; int sl_type;
	int kick_calls; hwr_grm_if_t *kick_if; unsigned char kick_mac[6];
	hwr_bm_sta_list_t *freed;
} hwr_grm_rec_t;
extern hwr_grm_rec_t hwr_grm_rec;
void hwr_grm_configure(int ap, int map_null, hwr_bm_sta_list_t *sta, const unsigned char *mac, hwr_bm_sta_list_t *other, int kick_ret, int del_ret);
hwr_grm_map_t *hwr_grm_map(int ap);
#endif
