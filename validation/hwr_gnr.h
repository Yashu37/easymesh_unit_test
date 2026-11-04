/* hwr_gnr.h - types / plumbing for the wifi_hal_getNeighborReportActivation harness */
#ifndef HWR_GNR_H
#define HWR_GNR_H
#include "hwr_defs.h"
#define HWR_GNR_MAX_RADIOS 3
#define HWR_GNR_MAX_IFACES 5
typedef struct { wifi_vap_info_t vap_info; } hwr_gnr_iface_t;                 /* REAL wifi_vap_info_t (packed union u) */
typedef struct { hwr_gnr_iface_t *items[4]; int n; } hwr_gnr_map_t;
typedef struct { hwr_gnr_map_t *interface_map; } hwr_gnr_radio_t;
typedef struct { unsigned int num_radios; hwr_gnr_radio_t *radio_info; } hwr_gnr_world_t;
extern hwr_gnr_world_t hwr_gnr_world;
extern "C" INT hwr_wifi_hal_getNeighborReportActivation(UINT apIndex, BOOL *activate);   /* renamed, see the handler file */

typedef struct { unsigned vap_index; int mode; int enabled; int fill; } hwr_gnr_if_t;   /* mode 0 ap, 1 sta, 2 monitor; fill: byte the union is filled with before `enabled` is set */
typedef struct { int n; hwr_gnr_if_t ifs[3]; } hwr_gnr_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gnr_rd_t r[HWR_GNR_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; int expected_out; int forked;       /* expected_out: -1 = *output_bool must stay untouched */
} hwr_gnr_case_t;
extern hwr_gnr_case_t wifi_hal_getNeighborReportActivation_suite[];
extern "C" void run_all_tests_wifi_hal_getNeighborReportActivation(void);
#endif
