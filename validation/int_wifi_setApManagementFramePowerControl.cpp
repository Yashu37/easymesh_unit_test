/*
 * HANDLER: wifi_setApManagementFramePowerControl (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1762-1785 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is
 * applied.  The intel version (unlike the banana-pi stub and the Broadcom netlink version) looks up the VAP interface, sends the vendor command
 * LTQ_NL80211_VENDOR_SUBCMD_SET_MGMT_FRAME_PWR_CTRL with the 4-byte dBm value through wifi_drv_vendor_cmd, returns its result and logs a failure with
 * strerror(res).
 *
 * KNOWN, NOT COUNTED (user decision, Low severity, diagnostics only): as in the intel wifi_setQamPlus / wifi_setApRetrylimit, the failure line is printed with
 * strerror(res) although res is a negative errno, so the log says "Unknown error -22" instead of "Invalid argument".  The harness does not check the error text.
 *
 * Scaffolding only: wifi_drv_vendor_cmd (hostap driver call, not in this tree) is a recording stub (HOSTAPD_VERSION >= 210 form, 7 arguments) that copies
 * the payload and returns the runner's result; get_interface_by_vap_index is a runner-controlled lookup that answers from a copy of the VAP index (so the
 * runner can keep the interface object POISONED); OUI_LTQ / the sub-command number are the harness's own values; the print macros map to the log sink
 * hwr_print (runner-poisoned slot).  Renamed hwr_int_wifi_setApManagementFramePowerControl because other harnesses use the real name.
 */
#include "hwr_imp.h"
#include <string.h>
#include <stdio.h>

typedef unsigned char u8;
#define HOSTAPD_VERSION 211
#define OUI_LTQ IMP_OUI_LTQ
#define LTQ_NL80211_VENDOR_SUBCMD_SET_MGMT_FRAME_PWR_CTRL IMP_SUBCMD_PWR
#define NESTED_ATTR_NOT_USED (-1)
#define wifi_interface_info_t imp_iface_t
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_setApManagementFramePowerControl hwr_int_wifi_setApManagementFramePowerControl

hwr_imp_world_t hwr_imp_world;

static imp_iface_t *get_interface_by_vap_index(unsigned int vap_index)
{
	return (hwr_imp_world.iface != NULL && hwr_imp_world.iface_vap == vap_index) ? hwr_imp_world.iface : NULL;
}

static int wifi_drv_vendor_cmd(void *priv, unsigned oui, unsigned subcmd, const u8 *data, unsigned long len, int nested, void *extra)
{
	hwr_imp_world_t *w = &hwr_imp_world;

	w->calls++; w->last_priv = priv; w->last_oui = oui; w->last_subcmd = subcmd; w->last_len = len; w->last_nested = nested; w->last_extra = extra;
	memset(w->last_data, 0xEE, sizeof(w->last_data));
	if (data != NULL) memcpy(w->last_data, data, len < sizeof(w->last_data) ? len : sizeof(w->last_data));
	return w->ret;
}

/* --- platform.c:1762-1785 --- */
extern "C" {
INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    wifi_interface_info_t *interface = NULL;
    int res = 0;

    if ((interface = get_interface_by_vap_index(apIndex)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(interface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_MGMT_FRAME_PWR_CTRL,
                                (u8*) &dBm, sizeof(dBm), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(interface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_MGMT_FRAME_PWR_CTRL,
                               (u8*) &dBm, sizeof(dBm), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending _MGMT_FRAME_PWR_CTRL failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }
    return res;
}
}
