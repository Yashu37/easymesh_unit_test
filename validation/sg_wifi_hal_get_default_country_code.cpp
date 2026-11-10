/*
 * HANDLER: wifi_hal_get_default_country_code (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:629-637 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_platform_country_code_default_fn() for the platform hook; without a hook it returns RETURN_ERR, otherwise it logs and returns the hook's result.  code is only
 * forwarded (the wrapper never dereferences it; the platform hook does, e.g. banana-pi platform_get_country_code_default, finding #103).
 *
 * Scaffolding only: get_platform_country_code_default_fn is a stub returning a hook or NULL (the hook counts its calls, records its argument and returns the runner's value); the
 * print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_get_default_country_code.
 */
#include "hwr_wcc.h"

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_ERR -1
typedef int (*platform_country_code_default_t)(char *code);
#define get_platform_country_code_default_fn hwr_wcc_get_platform_country_code_default_fn
#define wifi_hal_get_default_country_code hwr_sg_wifi_hal_get_default_country_code

hwr_wcc_world_t hwr_wcc_world;

extern "C" {
static int wcc_hook(char *code)
{
    hwr_wcc_world.hook_calls++; hwr_wcc_world.last_code = code;
    return hwr_wcc_world.hook_ret;
}
platform_country_code_default_t hwr_wcc_get_platform_country_code_default_fn() { hwr_wcc_world.getter_calls++; return hwr_wcc_world.hook_present ? wcc_hook : NULL; }

/* --- wifi_hal.c:629-637 --- */
INT wifi_hal_get_default_country_code(char *code)
{
    platform_country_code_default_t platform_country_code_default_fn;
    if ((platform_country_code_default_fn = get_platform_country_code_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform country code init\n", __func__, __LINE__);
        return(platform_country_code_default_fn(code));
    }
    return RETURN_ERR;
}
}
