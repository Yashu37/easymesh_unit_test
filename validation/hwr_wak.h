/* hwr_wak.h - plumbing for the sg_wifi_hal_set_acs_keep_out_chans harness (src/wifi_hal.c).
 * wifi_radio_operationParam_t, wifi_channels_list_per_bandwidth_t and wifi_channels_list_t are the REAL types from wifi_hal.h.  wifi_drv_get_chspc_configs is a stand-in for the platform chanspec hook with
 * the behaviour of the Broadcom one (convert_from_channellist_to_chspeclist: appends "0x%04x," per channel to buff with strcat, no size argument); wifi_drv_set_acs_exclusion_list records its argument. */
#ifndef HWR_WAK_H
#define HWR_WAK_H
#include "hwr_defs.h"
#define HWR_WAK_STR 4096
typedef struct {
	int get_calls, fail_at, set_calls, set_ret, set_null, set_radio;
	char set_str[HWR_WAK_STR];
	int seen_bw[400], seen_n[400];
} hwr_wak_world_t;
extern hwr_wak_world_t hwr_wak_world;
extern "C" int hwr_sg_wifi_hal_set_acs_keep_out_chans(wifi_radio_operationParam_t *wifi_radio_oper_param, int radioIndex);
typedef struct {
	const char *test_name;
	int radio_index;
	int null_param;
	int nlist[6];                  /* num_channels_list of channels_per_bandwidth[i] (bandwidth 1 << i) */
	int nch[6];                    /* num_channels of every list of bandwidth i */
	int fail_at;                   /* the platform chanspec hook fails on this call (1-based; 0 never) */
	int set_ret;                   /* result of wifi_drv_set_acs_exclusion_list */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wak_case_t;
extern hwr_wak_case_t sg_wifi_hal_set_acs_keep_out_chans_suite[];
extern "C" void run_all_tests_sg_wifi_hal_set_acs_keep_out_chans(void);
#endif
