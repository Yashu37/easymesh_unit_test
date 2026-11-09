/*
 * HANDLER: wifi_setApRetrylimit (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1271-1295 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is
 * applied.  The intel version (unlike the banana-pi stub) rejects a NULL priv and sends the vendor command LTQ_NL80211_VENDOR_SUBCMD_SET_AP_RETRY_LIMIT with the
 * 8-byte payload {4, 7} (two ints: the retry limits) through wifi_drv_vendor_cmd, returns its result and logs the failure with strerror(res).
 *
 * Scaffolding only: wifi_drv_vendor_cmd (hostap driver call, not in this tree) is a recording stub (HOSTAPD_VERSION >= 210 form, 7 arguments) that copies
 * the payload and returns the runner's result; OUI_LTQ / the sub-command number are the harness's own values; the print macros map to the log sink
 * hwr_print (runner-poisoned slot).  Renamed hwr_int_wifi_setApRetrylimit because other harnesses use the real name.
 */
#include "hwr_irl.h"
#include <string.h>
#include <stdio.h>

typedef unsigned char u8;
#define HOSTAPD_VERSION 211
#define OUI_LTQ IRL_OUI_LTQ
#define LTQ_NL80211_VENDOR_SUBCMD_SET_AP_RETRY_LIMIT IRL_SUBCMD_RETRY_LIMIT
#define NESTED_ATTR_NOT_USED (-1)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_setApRetrylimit hwr_int_wifi_setApRetrylimit

hwr_irl_world_t hwr_irl_world;

static int wifi_drv_vendor_cmd(void *priv, unsigned oui, unsigned subcmd, const u8 *data, unsigned long len, int nested, void *extra)
{
	hwr_irl_world_t *w = &hwr_irl_world;

	w->calls++; w->last_priv = priv; w->last_oui = oui; w->last_subcmd = subcmd; w->last_len = len; w->last_nested = nested; w->last_extra = extra;
	memset(w->last_data, 0xEE, sizeof(w->last_data));
	if (data != NULL) memcpy(w->last_data, data, len < sizeof(w->last_data) ? len : sizeof(w->last_data));
	return w->ret;
}

/* --- platform.c:1271-1295 --- */
extern "C" {
int wifi_setApRetrylimit(void* priv)
{
    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    int res = 0;
    int RL[2]; // RL means RetryLimit
    RL[0]=4;
    RL[1]=7;
#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_AP_RETRY_LIMIT,
                                (u8*)RL, sizeof(RL), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_AP_RETRY_LIMIT,
                               (u8*)RL, sizeof(RL), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending _AP_RETRY_LIMIT failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }

    return res;
}
}
