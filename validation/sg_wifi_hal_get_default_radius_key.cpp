/*
 * HANDLER: wifi_hal_get_default_radius_key (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:649-658 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_radius_key_default_fn() for the platform hook; without a hook it returns RETURN_ERR, otherwise it logs and returns the hook's result.  radius_key is only
 * forwarded (the wrapper never dereferences it; the platform hook does).
 *
 * Scaffolding only: get_platform_radius_key_default_fn is a stub returning a hook or NULL (the hook counts its calls, records its argument and returns the runner's value); the
 * print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_get_default_radius_key.
 */
#include "hwr_wrk.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
typedef int (*platform_radius_key_default_t)(char *radius_key);
#define get_platform_radius_key_default_fn hwr_wrk_get_platform_radius_key_default_fn
#define wifi_hal_get_default_radius_key hwr_sg_wifi_hal_get_default_radius_key

hwr_wrk_world_t hwr_wrk_world;

extern "C" {
static int wrk_hook(char *radius_key)
{
    hwr_wrk_world.hook_calls++; hwr_wrk_world.last_key = radius_key;
    return hwr_wrk_world.hook_ret;
}
platform_radius_key_default_t hwr_wrk_get_platform_radius_key_default_fn() { hwr_wrk_world.getter_calls++; return hwr_wrk_world.hook_present ? wrk_hook : NULL; }

/* --- wifi_hal.c:649-658 --- */
INT wifi_hal_get_default_radius_key(char *radius_key)
{
    platform_radius_key_default_t platform_radius_key_default_fn;
    if ((platform_radius_key_default_fn = get_platform_radius_key_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform  default_radius_key\n", __func__, __LINE__);
        return (platform_radius_key_default_fn(radius_key));
    }

    return RETURN_ERR;
}
}
