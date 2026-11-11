/* hwr_wcb.h - plumbing for the sg_wifi_hal_cancelRMBeaconRequest harness (src/wifi_hal.c).
 * The dialog-token tables g_DialogToken (u8_bitmap per VAP) and g_DialogTokenSender, the bit helpers get_bit_u8 / set_bit_u8 / reset_bit_u8 (wifi_hal_priv.h:1444-1471) and the real MAX_AP_INDEX (15)
 * live in the handler file; the runner reaches them through the accessors below.  g_wifi_hal.hapd_lock is a stand-in mutex (hwr_wcb_lock_free() tells whether it was released). */
#ifndef HWR_WCB_H
#define HWR_WCB_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WCB_MAXV 15            /* MAX_AP_INDEX when VAP_REINDEX is off */
extern "C" int hwr_wcb_lock_free(void);   /* 1 when g_wifi_hal.hapd_lock can be taken (released by the function) */
extern "C" int hwr_sg_wifi_hal_cancelRMBeaconRequest(UINT apIndex, UCHAR dialogToken);
extern "C" void hwr_wcb_reset_tables(void);
extern "C" void hwr_wcb_set_token(int vap, unsigned token);
extern "C" int hwr_wcb_get_token(int vap, unsigned token);
extern "C" void hwr_wcb_set_sender(int orig_vap, unsigned token, int sent_vap);   /* g_DialogTokenSender[orig][token] = sent + 1 */
extern "C" int hwr_wcb_get_sender(int orig_vap, unsigned token);
extern "C" void hwr_wcb_tables(void **bitmaps, size_t *bitmaps_row, unsigned char **sender);
typedef struct {
	const char *test_name;
	unsigned apIndex;
	unsigned token;
	int bits_mask;                 /* bit v: g_DialogToken[v] has the token set */
	int s_orig[3], s_sent[3];      /* sender entries for the token: g_DialogTokenSender[s_orig][token] = s_sent + 1 (-1: unused) */
	int other_token;               /* a second token set on VAP apIndex (-1: none) to check bits are independent */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wcb_case_t;
extern hwr_wcb_case_t sg_wifi_hal_cancelRMBeaconRequest_suite[];
extern "C" void run_all_tests_sg_wifi_hal_cancelRMBeaconRequest(void);
#endif
