/* hwr_snr.h - types / plumbing for the wifi_hal_setNeighborReportActivation harness */
#ifndef HWR_SNR_H
#define HWR_SNR_H
#include "hwr_defs.h"
#define HWR_SNR_MAX_RADIOS 3
#define HWR_SNR_MAX_IFACES 5
typedef struct { wifi_vap_info_t vap_info; } hwr_snr_iface_t;                 /* REAL wifi_vap_info_t (packed union u) */
typedef struct { hwr_snr_iface_t *items[4]; int n; } hwr_snr_map_t;
typedef struct { hwr_snr_map_t *interface_map; } hwr_snr_radio_t;
typedef struct { unsigned int num_radios; hwr_snr_radio_t *radio_info; } hwr_snr_world_t;
extern hwr_snr_world_t hwr_snr_world;
extern "C" INT hwr_wifi_hal_setNeighborReportActivation(UINT apIndex, BOOL activate);   /* renamed, see the handler file */

typedef struct { unsigned vap_index; int mode; int enabled; int fill; } hwr_snr_if_t;   /* mode 0 ap, 1 sta, 2 monitor; fill: byte the union is filled with before `enabled` is set */
typedef struct { int n; hwr_snr_if_t ifs[3]; } hwr_snr_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_snr_rd_t r[HWR_SNR_MAX_RADIOS];
	unsigned query; int activate; int calls; int check_log;
	int expected_ret;
	int expected_set;              /* index (in creation order) of the interface whose flag must equal (BOOL)activate afterwards; -1 = nothing may change */
} hwr_snr_case_t;
extern hwr_snr_case_t wifi_hal_setNeighborReportActivation_suite[];
extern "C" void run_all_tests_wifi_hal_setNeighborReportActivation(void);
#endif
