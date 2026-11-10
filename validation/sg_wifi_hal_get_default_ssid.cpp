/*
 * HANDLER: wifi_hal_get_default_ssid (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:618-627 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_ssid_default_fn() for the platform hook; without a hook it returns RETURN_ERR, otherwise it logs and returns the hook's result.  ssid and vap_index are
 * only forwarded (the wrapper never dereferences ssid; the platform hook does, e.g. banana-pi platform_get_ssid_default, which has its own findings #98-#99).
 *
 * Scaffolding only: get_platform_ssid_default_fn is a stub returning a hook or NULL (the hook counts its calls, records its arguments and returns the runner's value); the
 * print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_get_default_ssid.
 */
#include "hwr_wds.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
typedef int (*platform_ssid_default_t)(char *ssid, int vap_index);
#define get_platform_ssid_default_fn hwr_wds_get_platform_ssid_default_fn
#define wifi_hal_get_default_ssid hwr_sg_wifi_hal_get_default_ssid

hwr_wds_world_t hwr_wds_world;

extern "C" {
static int wds_hook(char *ssid, int vap_index)
{
    hwr_wds_world.hook_calls++; hwr_wds_world.last_ssid = ssid; hwr_wds_world.last_vap = vap_index;
    return hwr_wds_world.hook_ret;
}
platform_ssid_default_t hwr_wds_get_platform_ssid_default_fn() { hwr_wds_world.getter_calls++; return hwr_wds_world.hook_present ? wds_hook : NULL; }

/* --- wifi_hal.c:618-627 --- */
INT wifi_hal_get_default_ssid(char *ssid, int vap_index)
{
    platform_ssid_default_t platform_ssid_default_fn;
    if ((platform_ssid_default_fn = get_platform_ssid_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform ssid init\n", __func__, __LINE__);
        return (platform_ssid_default_fn(ssid, vap_index));
    }

    return RETURN_ERR;
}
}
