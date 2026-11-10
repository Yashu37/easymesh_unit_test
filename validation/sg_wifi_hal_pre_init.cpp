/*
 * HANDLER: wifi_hal_pre_init (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:583-592 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_pre_init_fn() for the platform's pre-init hook, logs and calls it when there is one, and returns RETURN_OK whatever the hook did (the hook is
 * a platform_pre_init_t, which returns int, but its result is discarded: design note, not counted).
 *
 * Scaffolding only: get_platform_pre_init_fn (src/wifi_hal_platform.c) is a stub returning a hook or NULL; the hook counts its calls; the print macro maps to hwr_print.
 * Renamed hwr_sg_wifi_hal_pre_init.
 */
#include "hwr_wpi.h"

#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_OK 0
typedef int (*platform_pre_init_t)(void);
#define get_platform_pre_init_fn hwr_wpi_get_platform_pre_init_fn
#define wifi_hal_pre_init hwr_sg_wifi_hal_pre_init

hwr_wpi_world_t hwr_wpi_world;

extern "C" {
static int wpi_hook(void) { hwr_wpi_world.hook_calls++; return 0; }
platform_pre_init_t hwr_wpi_get_platform_pre_init_fn() { hwr_wpi_world.getter_calls++; return hwr_wpi_world.hook_present ? wpi_hook : NULL; }

/* --- wifi_hal.c:583-592 --- */
INT wifi_hal_pre_init()
{
    platform_pre_init_t  pre_init_fn;
    if ((pre_init_fn = get_platform_pre_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platfrom pre init\n", __func__, __LINE__);
        pre_init_fn();
    }

    return RETURN_OK;
}
}
