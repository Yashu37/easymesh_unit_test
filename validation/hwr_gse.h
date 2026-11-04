/* hwr_gse.h - types / plumbing for the wifi_hal_getSSIDEnable harness */
#ifndef HWR_GSE_H
#define HWR_GSE_H
#include "hwr_defs.h"
#define HWR_GSE_MAX_RADIOS 3
#define HWR_GSE_MAX_IFACES 5
typedef struct { wifi_vap_info_t vap_info; } hwr_gse_iface_t;                 /* REAL wifi_vap_info_t (packed union u) */
typedef struct { hwr_gse_iface_t *items[4]; int n; } hwr_gse_map_t;
typedef struct { hwr_gse_map_t *interface_map; } hwr_gse_radio_t;
typedef struct { unsigned int num_radios; hwr_gse_radio_t *radio_info; } hwr_gse_world_t;
extern hwr_gse_world_t hwr_gse_world;
extern "C" INT hwr_wifi_hal_getSSIDEnable(INT ssidIndex, BOOL *output_bool);   /* renamed, see the handler file */

typedef struct { unsigned vap_index; int mode; int enabled; int fill; } hwr_gse_if_t;   /* mode 0 ap, 1 sta, 2 monitor; fill: byte the union is filled with before `enabled` is set */
typedef struct { int n; hwr_gse_if_t ifs[3]; } hwr_gse_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gse_rd_t r[HWR_GSE_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; int expected_out; int forked;       /* expected_out: -1 = *output_bool must stay untouched */
} hwr_gse_case_t;
extern hwr_gse_case_t wifi_hal_getSSIDEnable_suite[];
extern "C" void run_all_tests_wifi_hal_getSSIDEnable(void);
#endif
