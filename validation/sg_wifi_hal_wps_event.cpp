/*
 * HANDLER: wifi_hal_wps_event (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:671-680 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_wps_event_fn() for the platform hook; without a hook it returns RETURN_ERR, otherwise it logs and returns the hook's result.  The event structure
 * (vap_index, event, wps_data pointer; passed BY VALUE) is only forwarded: the wrapper never dereferences wps_data (the platform hook does; banana-pi platform_wps_event is
 * covered by its own harness).
 *
 * Scaffolding only: get_platform_wps_event_fn is a stub returning a hook or NULL (the hook counts its calls, records the structure it received and returns the runner's value);
 * the print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_wps_event.
 */
#include "hwr_wwe.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
typedef int (*platform_wps_event_t)(wifi_wps_event_t data);
#define get_platform_wps_event_fn hwr_wwe_get_platform_wps_event_fn
#define wifi_hal_wps_event hwr_sg_wifi_hal_wps_event

hwr_wwe_world_t hwr_wwe_world;

extern "C" {
static int wwe_hook(wifi_wps_event_t data)
{
    hwr_wwe_world.hook_calls++; hwr_wwe_world.last = data;
    return hwr_wwe_world.hook_ret;
}
platform_wps_event_t hwr_wwe_get_platform_wps_event_fn() { hwr_wwe_world.getter_calls++; return hwr_wwe_world.hook_present ? wwe_hook : NULL; }

/* --- wifi_hal.c:671-680 --- */
INT wifi_hal_wps_event(wifi_wps_event_t data)
{
    platform_wps_event_t platform_wps_event_fn;
    if ((platform_wps_event_fn = get_platform_wps_event_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform wps event callback triggered\n", __func__, __LINE__);
        return (platform_wps_event_fn(data));
    }

    return RETURN_ERR;
}
}
