/*
 * HANDLER: wifi_hal_post_init (src/wifi_hal.c), both build variants
 *
 * Both definitions copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:595-604 (HAL_IPC variant, argument wifi_hal_post_init_t *) and 606-615 (plain variant, argument
 * wifi_vap_info_map_t *); the list names the function twice for these two variants.  This file holds the ORIGINAL code: no fix is applied.  Each asks
 * get_platform_post_init_fn() for the platform's post-init hook, logs and calls it with the argument unchanged when there is one, and returns RETURN_OK whatever the hook
 * returned (design note, not counted: a failing platform post-init is never reported).  The argument is only forwarded, never dereferenced.
 *
 * Scaffolding only: get_platform_post_init_fn is a stub returning a hook or NULL (the hook counts its calls and records its argument); the print macro maps to hwr_print.
 * Renamed hwr_sg_wifi_hal_post_init_ipc / hwr_sg_wifi_hal_post_init_vap.
 */
#include "hwr_wpo.h"

#define wifi_hal_info_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_OK 0
typedef int (*hwr_wpo_hook_ipc_t)(wifi_hal_post_init_t *);
typedef int (*hwr_wpo_hook_vap_t)(wifi_vap_info_map_t *);

hwr_wpo_world_t hwr_wpo_world;

extern "C" {
static int wpo_hook_ipc(wifi_hal_post_init_t *a) { hwr_wpo_world.hook_calls++; hwr_wpo_world.last_arg = a; return 0; }
static int wpo_hook_vap(wifi_vap_info_map_t *a) { hwr_wpo_world.hook_calls++; hwr_wpo_world.last_arg = a; return 0; }
hwr_wpo_hook_ipc_t hwr_wpo_get_ipc() { hwr_wpo_world.getter_calls++; return hwr_wpo_world.hook_present ? wpo_hook_ipc : NULL; }
hwr_wpo_hook_vap_t hwr_wpo_get_vap() { hwr_wpo_world.getter_calls++; return hwr_wpo_world.hook_present ? wpo_hook_vap : NULL; }

#define platform_post_init_t hwr_wpo_hook_ipc_t
#define get_platform_post_init_fn hwr_wpo_get_ipc
#define wifi_hal_post_init hwr_sg_wifi_hal_post_init_ipc
/* --- wifi_hal.c:595-604 (HAL_IPC variant) --- */
INT wifi_hal_post_init(wifi_hal_post_init_t *post_init_struct)
{
    platform_post_init_t post_init_fn;
    if ((post_init_fn = get_platform_post_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform post init\n", __func__, __LINE__);
        post_init_fn(post_init_struct);
    }

    return RETURN_OK;
}
#undef platform_post_init_t
#undef get_platform_post_init_fn
#undef wifi_hal_post_init

#define platform_post_init_t hwr_wpo_hook_vap_t
#define get_platform_post_init_fn hwr_wpo_get_vap
#define wifi_hal_post_init hwr_sg_wifi_hal_post_init_vap
/* --- wifi_hal.c:606-615 (plain variant) --- */
INT wifi_hal_post_init(wifi_vap_info_map_t *vap_map)
{
    platform_post_init_t post_init_fn;
    if ((post_init_fn = get_platform_post_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform post init\n", __func__, __LINE__);
        post_init_fn(vap_map);
    }

    return RETURN_OK;
}
}
