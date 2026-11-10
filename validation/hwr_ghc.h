/* hwr_ghc.h - plumbing for the sg_wifi_hal_getHalCapability harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t / hash_map_t / g_wifi_hal are minimal STAND-INS with the members the function uses; the capability types
 * (wifi_hal_capability_t, wifi_radio_capabilities_t, mac_address_t ...) are the REAL ones from wifi_hal.h. */
#ifndef HWR_GHC_H
#define HWR_GHC_H
#include "hwr_defs.h"
#include <stddef.h>
#include <stdbool.h>
#define HWR_GHC_MAXR 8                      /* radios the stand-in table can hold (the real hal has MAX_NUM_RADIOS) */
#define HWR_GHC_MAXI 4
typedef struct wifi_interface_info_t {
	char name[16];
	wifi_vap_info_t vap_info;
	char firmware_version[64];
} wifi_interface_info_t;
typedef struct { int n; wifi_interface_info_t *items[HWR_GHC_MAXI]; } hwr_ghc_map_t;
typedef struct {
	unsigned int index; unsigned int rdk_radio_index;
	wifi_radio_capabilities_t capab;
	bool radio_presence;
	hwr_ghc_map_t *interface_map;
} hwr_ghc_radio_t;
typedef struct { unsigned int num_radios; hwr_ghc_radio_t radio_info[HWR_GHC_MAXR]; } hwr_ghc_hal_t;
typedef struct {
	hwr_ghc_hal_t hal;
	hwr_ghc_map_t maps[HWR_GHC_MAXR];
	wifi_interface_info_t ifs[HWR_GHC_MAXR][HWR_GHC_MAXI];
	const char *serial, *model, *image, *cm;      /* _syscmd replies per command */
	int off_flag, access_errno;                   /* access(EASYMESH_OFF_FLAG): file exists / errno of a failure */
	int js_ret; const char *js_val;               /* json_parse_string("Al_MAC_ADDR") */
	int ji_ret; int ji_val;                       /* json_parse_integer("Colocated_Mode") */
	int found; const char *ifname; int conf_ret;  /* get_ifname_from_mac / configure_vap_name_basedon_colocated_mode */
	int eth_ret; unsigned char eth_mac[6];        /* get_mac_address("eth0") */
	unsigned int band_calls, adjust_calls, syscmd_calls, size_calls;
} hwr_ghc_world_t;
extern hwr_ghc_world_t hwr_ghc_world;
extern "C" int hwr_sg_wifi_hal_getHalCapability(wifi_hal_capability_t *hal);
typedef struct {
	const char *test_name;
	int hal_mode;                  /* 0 NULL, 1 exact-size heap object (redzones: any write beyond the struct aborts under ASan) */
	unsigned nrad;                 /* g_wifi_hal.num_radios */
	int shift;                     /* radio k has rdk_radio_index k + shift (shift != 0: get_radio_by_rdk_index(0) is NULL) */
	int ifaces;                    /* interfaces per radio */
	const char *serial, *model, *image, *cm;   /* canned _syscmd output (NULL = empty) */
	int off_flag, access_errno;
	int js_ret; const char *js_val;
	int ji_ret; int ji_val;
	int found; const char *ifname; int conf_ret;
	int eth_ret;
	int expected_ret;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_ghc_case_t;
extern hwr_ghc_case_t sg_wifi_hal_getHalCapability_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getHalCapability(void);
#endif
