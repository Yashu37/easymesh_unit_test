/* hwr_gsm.h - types / plumbing for the wifi_hal_getSSIDName harness */
#ifndef HWR_GSM_H
#define HWR_GSM_H
#include "hwr_defs.h"
#define HWR_GSM_MAX_RADIOS 3
#define HWR_GSM_MAX_IFACES 5
typedef struct { wifi_vap_info_t vap_info; } hwr_gsm_iface_t;                 /* REAL wifi_vap_info_t (packed union u) */
typedef struct { hwr_gsm_iface_t *items[4]; int n; } hwr_gsm_map_t;
typedef struct { hwr_gsm_map_t *interface_map; } hwr_gsm_radio_t;
typedef struct { unsigned int num_radios; hwr_gsm_radio_t *radio_info; } hwr_gsm_world_t;
extern hwr_gsm_world_t hwr_gsm_world;
extern "C" INT hwr_wifi_hal_getSSIDName(INT apIndex, CHAR *output_string);   /* renamed, see the handler file */

/* ssid is copied byte for byte into the member valid for the mode (AP: 33 bytes, STA: 32 bytes; the NUL is copied only if it fits);
 * the rest of the union is pre-filled with `fill`, so a string that is not NUL terminated runs into it. */
typedef struct { unsigned vap_index; int mode; const char *ssid; int fill; } hwr_gsm_if_t;   /* mode 0 ap, 1 sta, 2 monitor */
typedef struct { int n; hwr_gsm_if_t ifs[3]; } hwr_gsm_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gsm_rd_t r[HWR_GSM_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;
	int expected_ret; const char *expected_out; int forked;       /* expected_out: NULL = output must stay untouched */
} hwr_gsm_case_t;
extern hwr_gsm_case_t wifi_hal_getSSIDName_suite[];
extern "C" void run_all_tests_wifi_hal_getSSIDName(void);
#endif
