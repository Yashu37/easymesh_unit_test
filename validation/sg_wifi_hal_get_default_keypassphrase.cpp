/*
 * HANDLER: wifi_hal_get_default_keypassphrase (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:639-648 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_keypassphrase_default_fn() for the platform hook; without a hook it returns RETURN_ERR, otherwise it logs and returns the hook's result.  password and vap_index are
 * only forwarded (the wrapper never dereferences password; the platform hook does, e.g. banana-pi platform_get_keypassphrase_default, which has its own findings #95-#97).
 *
 * Scaffolding only: get_platform_keypassphrase_default_fn is a stub returning a hook or NULL (the hook counts its calls, records its arguments and returns the runner's value); the
 * print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_get_default_keypassphrase.
 */
#include "hwr_wkp.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
typedef int (*platform_keypassphrase_default_t)(char *password, int vap_index);
#define get_platform_keypassphrase_default_fn hwr_wkp_get_platform_keypassphrase_default_fn
#define wifi_hal_get_default_keypassphrase hwr_sg_wifi_hal_get_default_keypassphrase

hwr_wkp_world_t hwr_wkp_world;

extern "C" {
static int wkp_hook(char *password, int vap_index)
{
    hwr_wkp_world.hook_calls++; hwr_wkp_world.last_pw = password; hwr_wkp_world.last_vap = vap_index;
    return hwr_wkp_world.hook_ret;
}
platform_keypassphrase_default_t hwr_wkp_get_platform_keypassphrase_default_fn() { hwr_wkp_world.getter_calls++; return hwr_wkp_world.hook_present ? wkp_hook : NULL; }

/* --- wifi_hal.c:639-648 --- */
INT wifi_hal_get_default_keypassphrase(char *password, int vap_index)
{
    platform_keypassphrase_default_t platform_keypassphrase_default_fn;
    if ((platform_keypassphrase_default_fn = get_platform_keypassphrase_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform passphrase init\n", __func__, __LINE__);
        return (platform_keypassphrase_default_fn(password, vap_index));
    }

    return RETURN_ERR;
}
}
