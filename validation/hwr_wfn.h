/* hwr_wfn.h - plumbing for the sg_wifi_hal_findNetworks harness (src/wifi_hal.c).
 * wifi_interface_info_t / hash_map_t are minimal STAND-INS with the members the function uses (vap_info, scan_info_mutex, scan_info_map); wifi_bss_info_t, wifi_channel_t and wifi_vap_info_t are the
 * REAL types from wifi_hal.h.  calloc is counted (and can fail) so the runner sees a leak or a failed allocation. */
#ifndef HWR_WFN_H
#define HWR_WFN_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WFN_MAXI 4
#define HWR_WFN_MAXS 6
typedef uint8_t u8;
typedef struct { wifi_bss_info_t *items[HWR_WFN_MAXS]; int n; int itr; } hash_map_t;
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	pthread_mutex_t scan_info_mutex;
	hash_map_t *scan_info_map;
	union { struct { int state; uint8_t pad[60]; } sta; struct { uint8_t blob[64]; } ap; } u;
} wifi_interface_info_t;
typedef struct {
	unsigned int num_ifs;
	wifi_interface_info_t ifs[HWR_WFN_MAXI];
	hash_map_t maps[HWR_WFN_MAXI];
	wifi_bss_info_t scan[HWR_WFN_MAXI][HWR_WFN_MAXS];
	int calloc_fail, live_alloc;
} hwr_wfn_world_t;
extern hwr_wfn_world_t hwr_wfn_world;
extern "C" int hwr_sg_wifi_hal_findNetworks(int ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss_array, unsigned int *num_bss);
typedef struct {
	const char *test_name;
	int vap_index;
	unsigned n_if;                 /* interfaces that exist (vap indexes 0 .. n_if-1) */
	int sta_mask;                  /* bit k: interface k is a STA VAP (the others are AP VAPs) */
	int chan;                      /* channel filter (0: every entry) */
	int null_chan, null_arr, null_num;   /* pass NULL for channel / bss_array / num_bss */
	unsigned n_scan;               /* scan list entries of every interface */
	unsigned freq[HWR_WFN_MAXS];   /* frequency of scan entry k */
	int calloc_fail;
	int prefill;                   /* bytes of the log slot already used before the call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wfn_case_t;
extern hwr_wfn_case_t sg_wifi_hal_findNetworks_suite[];
extern "C" void run_all_tests_sg_wifi_hal_findNetworks(void);
#endif
