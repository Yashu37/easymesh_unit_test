/* hwr_gbt.h - types / plumbing for the wifi_hal_getBSSTransitionActivation harness */
#ifndef HWR_GBT_H
#define HWR_GBT_H
#include "hwr_defs.h"
#define HWR_GBT_MAX_RADIOS 3
#define HWR_GBT_MAX_IFACES 5
typedef struct { wifi_vap_info_t vap_info; } hwr_gbt_iface_t;                 /* REAL wifi_vap_info_t (packed union u) */
typedef struct { hwr_gbt_iface_t *items[4]; int n; } hwr_gbt_map_t;
typedef struct { hwr_gbt_map_t *interface_map; } hwr_gbt_radio_t;
typedef struct { unsigned int num_radios; hwr_gbt_radio_t *radio_info; } hwr_gbt_world_t;
extern hwr_gbt_world_t hwr_gbt_world;
extern "C" INT hwr_wifi_hal_getBSSTransitionActivation(UINT apIndex, BOOL *activate);   /* renamed, see the handler file */

typedef struct { unsigned vap_index; int mode; int enabled; int fill; } hwr_gbt_if_t;   /* mode 0 ap, 1 sta, 2 monitor; fill: byte the union is filled with before `enabled` is set */
typedef struct { int n; hwr_gbt_if_t ifs[3]; } hwr_gbt_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gbt_rd_t r[HWR_GBT_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; int expected_out; int forked;       /* expected_out: -1 = *output_bool must stay untouched */
} hwr_gbt_case_t;
extern hwr_gbt_case_t wifi_hal_getBSSTransitionActivation_suite[];
extern "C" void run_all_tests_wifi_hal_getBSSTransitionActivation(void);
#endif
