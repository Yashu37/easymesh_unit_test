/* hwr_gsr.h - types / plumbing for the wifi_hal_getSSIDRadioIndex harness */
#ifndef HWR_GSR_H
#define HWR_GSR_H
#include "hwr_defs.h"
#define HWR_GSR_MAX_RADIOS 3
#define HWR_GSR_MAX_IFACES 5
typedef struct { wifi_vap_info_t vap_info; } hwr_gsr_iface_t;                 /* REAL wifi_vap_info_t */
typedef struct { hwr_gsr_iface_t *items[4]; int n; } hwr_gsr_map_t;
typedef struct { hwr_gsr_map_t *interface_map; } hwr_gsr_radio_t;
typedef struct { unsigned int num_radios; hwr_gsr_radio_t *radio_info; } hwr_gsr_world_t;
extern hwr_gsr_world_t hwr_gsr_world;
extern "C" INT hwr_wifi_hal_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex);   /* renamed, see the handler file */

typedef struct { unsigned vap_index; int mode; unsigned radio_index; } hwr_gsr_if_t;   /* mode 0 ap, 1 sta, 2 monitor */
typedef struct { int n; hwr_gsr_if_t ifs[3]; } hwr_gsr_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gsr_rd_t r[HWR_GSR_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; long long expected_out; int forked;       /* expected_out: LLONG_MIN = *radioIndex must stay untouched */
} hwr_gsr_case_t;
extern hwr_gsr_case_t wifi_hal_getSSIDRadioIndex_suite[];
extern "C" void run_all_tests_wifi_hal_getSSIDRadioIndex(void);
#endif
