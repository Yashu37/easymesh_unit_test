/* hwr_gnd.h - types / plumbing for the wifi_hal_getApNumDevicesAssociated harness */
#ifndef HWR_GND_H
#define HWR_GND_H
#include "hwr_defs.h"
#include <pthread.h>
#define HWR_GND_MAX_RADIOS 3
#define HWR_GND_MAX_IFACES 5
typedef struct { char pad[200]; int num_sta; char pad2[56]; } hwr_gnd_hapd_t;     /* stands for struct hostapd_data: num_sta somewhere inside */
typedef struct { hwr_gnd_hapd_t hapd; char pad[256]; } hwr_gnd_ap_t;               /* wifi_ap_priv_t: hapd first */
typedef struct { char junk[sizeof(hwr_gnd_ap_t)]; } hwr_gnd_sta_t;                 /* wifi_sta_priv_t: other state in the same bytes */
typedef struct { wifi_vap_info_t vap_info; union { hwr_gnd_ap_t ap; hwr_gnd_sta_t sta; } u; } hwr_gnd_iface_t;   /* REAL wifi_vap_info_t */
typedef struct { hwr_gnd_iface_t *items[4]; int n; } hwr_gnd_map_t;
typedef struct { hwr_gnd_map_t *interface_map; } hwr_gnd_radio_t;
typedef struct { unsigned int num_radios; hwr_gnd_radio_t *radio_info; pthread_mutex_t hapd_lock; } hwr_gnd_world_t;
extern hwr_gnd_world_t hwr_gnd_world;
extern "C" INT hwr_wifi_hal_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong);   /* renamed, see the handler file */

typedef struct { unsigned vap_index; int mode; int num_sta; int fill; } hwr_gnd_if_t;   /* mode 0 ap, 1 sta, 2 monitor; fill: byte the u union is filled with (num_sta only set for an AP) */
typedef struct { int n; hwr_gnd_if_t ifs[3]; } hwr_gnd_rd_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gnd_rd_t r[HWR_GND_MAX_RADIOS];
	int query; int null_out; int calls; int check_log;       /* check_log 1: Enter + AP index line, 2: error line */
	int expected_ret;
	long expected_out;             /* -1 = output must stay untouched */
	int forked;
} hwr_gnd_case_t;
extern hwr_gnd_case_t wifi_hal_getApNumDevicesAssociated_suite[];
extern "C" void run_all_tests_wifi_hal_getApNumDevicesAssociated(void);
#endif
