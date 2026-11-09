/* hwr_bgk.h - plumbing for the broadcom wifi_getRadioChannelStats harness (platform/broadcom) */
#ifndef HWR_BGK_H
#define HWR_BGK_H
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include "hso_hal_ipc.h"
#ifdef __cplusplus
#include "hwr_defs.h"
#else
void hwr_print(int level, const char *format, ...);
#endif

#define BGK_MAXE 4
typedef struct { unsigned int index; unsigned int phy_index; } bgk_iface_t;
typedef struct { int rdk_index; bgk_iface_t *primary; } bgk_radio_t;

typedef struct { unsigned freq; int ch; int omit_attr; } bgk_ent_t;   /* wire frequency, channel the code must derive (0 = none), survey attribute left out (0 = none) */

typedef struct {
    bgk_radio_t *radio; int cmd_fail, dump_rc, omit_reply;    /* omit_reply: 0 none, 1 no vendor data, 2 no survey-info nest */
    int nent; bgk_ent_t e[BGK_MAXE];
    int cmd_calls, send_calls;
} bgk_world_t;
extern bgk_world_t hwr_bgk_world;

#ifdef __cplusplus
extern "C" {
#endif
INT hwr_bcm_wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size);
#ifdef __cplusplus
}
#endif

typedef struct {
    const char *test_name;
    int radio_index, has_radio, has_iface;
    int array_mode;               /* 0 NULL, 1 heap block of exactly max(array_size,1) entries */
    int array_size, arr_first, arr_step;
    int nent; bgk_ent_t e[BGK_MAXE];
    int cmd_fail, dump_rc, omit_reply;
    int expected_ret, exp_untouched, calls, last;
} bgk_case_t;
extern bgk_case_t bcm_wifi_getRadioChannelStats_suite[];
#ifdef __cplusplus
extern "C" void run_all_tests_bcm_wifi_getRadioChannelStats(void);
#endif
#endif
