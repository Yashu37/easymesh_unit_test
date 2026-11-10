/*
 * HANDLER: wifi_hal_get_default_wps_pin (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:660-669 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_wps_pin_default_fn() for the platform hook; without a hook it returns RETURN_ERR, otherwise it logs and returns the hook's result.  pin is only
 * forwarded (the wrapper never dereferences it; the platform hook does, e.g. banana-pi platform_get_wps_pin_default, findings #100-#102).
 *
 * Scaffolding only: get_platform_wps_pin_default_fn is a stub returning a hook or NULL (the hook counts its calls, records its argument and returns the runner's value); the
 * print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_get_default_wps_pin.
 */
#include "hwr_wwp.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
typedef int (*platform_wps_pin_default_t)(char *pin);
#define get_platform_wps_pin_default_fn hwr_wwp_get_platform_wps_pin_default_fn
#define wifi_hal_get_default_wps_pin hwr_sg_wifi_hal_get_default_wps_pin

hwr_wwp_world_t hwr_wwp_world;

extern "C" {
static int wwp_hook(char *pin)
{
    hwr_wwp_world.hook_calls++; hwr_wwp_world.last_key = pin;
    return hwr_wwp_world.hook_ret;
}
platform_wps_pin_default_t hwr_wwp_get_platform_wps_pin_default_fn() { hwr_wwp_world.getter_calls++; return hwr_wwp_world.hook_present ? wwp_hook : NULL; }

/* --- wifi_hal.c:660-669 --- */
INT wifi_hal_get_default_wps_pin(char *pin)
{
    platform_wps_pin_default_t platform_wps_pin_default_fn;
    if ((platform_wps_pin_default_fn = get_platform_wps_pin_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform wps pin init\n", __func__, __LINE__);
        return (platform_wps_pin_default_fn(pin));
    }

    return RETURN_ERR;
}
}
