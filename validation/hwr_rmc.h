/* hwr_rmc.h - plumbing for the raspberry-pi wifi_setApMacAddressControlMode harness (platform/raspberry-pi) */
#ifndef HWR_RMC_H
#define HWR_RMC_H
#include "hwr_defs.h"
/* stand-in for wifi_interface_info_t: only vap_info (the real wifi_vap_info_t) is used */
typedef struct { unsigned char pre[24]; wifi_vap_info_t vap_info; unsigned char post[24]; } rmc_iface_t;
extern "C" INT hwr_rp_wifi_setApMacAddressControlMode(INT apIndex, INT filterMode);
typedef struct { rmc_iface_t *iface; int iface_vap; int lookups; int last_lookup; } hwr_rmc_world_t;   /* iface_vap: copy of the VAP index the lookup answers to */
extern hwr_rmc_world_t hwr_rmc_world;
typedef struct {
	const char *test_name;
	int ap_index;
	int has_iface;                 /* 0 no interface, 1 interface for ap_index, 2 only an interface with another VAP index */
	int vap_mode;                  /* wifi_vap_mode_t of the interface (0 ap, 1 sta, 2 monitor) */
	int filter_mode;
	int pre_enable;                /* stale mac_filter_enable before the call */
	int pre_mode;                  /* stale mac_filter_mode before the call */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
} hwr_rmc_case_t;
extern hwr_rmc_case_t rp_wifi_setApMacAddressControlMode_suite[];
extern "C" void run_all_tests_rp_wifi_setApMacAddressControlMode(void);
#endif
