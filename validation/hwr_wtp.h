/* hwr_wtp.h - plumbing for the sg_wifi_hal_setRadioTransmitPower harness (src/wifi_hal.c).
 * wifi_radio_info_t / wifi_interface_info_t / g_wifi_hal are minimal STAND-INS with the members the function uses (radio->index, g_wifi_hal.platform_flags); get_radio_by_rdk_index,
 * get_primary_interface, get_private_vap_interface and wifi_drv_set_txpower are recording stubs over runner data. */
#ifndef HWR_WTP_H
#define HWR_WTP_H
#include "hwr_defs.h"
#include <stdint.h>
#include <sys/types.h>
#define HWR_WTP_MAXR 4
#define PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY (0x1 << 3)
typedef struct wifi_interface_info_t { int tag; char pad[64]; } wifi_interface_info_t;
typedef struct wifi_radio_info_t { unsigned int index; } wifi_radio_info_t;
typedef struct { unsigned int platform_flags; } hwr_wtp_hal_t;
typedef struct {
	hwr_wtp_hal_t hal;
	wifi_radio_info_t radios[HWR_WTP_MAXR];
	wifi_interface_info_t primary[HWR_WTP_MAXR], priv[HWR_WTP_MAXR];
	int no_radio, has_primary, has_private, drv_ret;
	int primary_calls, private_calls, drv_calls;
	void *drv_iface; uint drv_txpower;
	wifi_radio_info_t *primary_arg, *private_arg;
} hwr_wtp_world_t;
extern hwr_wtp_world_t hwr_wtp_world;
extern "C" int hwr_sg_wifi_hal_setRadioTransmitPower(wifi_radio_index_t radioIndex, uint txpower);
typedef struct {
	const char *test_name;
	unsigned radioIndex;
	int no_radio;                  /* get_radio_by_rdk_index() finds nothing */
	unsigned flags;                /* g_wifi_hal.platform_flags */
	int has_primary, has_private;  /* the interface finders return an interface */
	uint txpower;
	int drv_ret;                   /* result of wifi_drv_set_txpower */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wtp_case_t;
extern hwr_wtp_case_t sg_wifi_hal_setRadioTransmitPower_suite[];
extern "C" void run_all_tests_sg_wifi_hal_setRadioTransmitPower(void);
#endif
