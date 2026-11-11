/*
 * HANDLER: wifi_hal_register_frame_hook (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:3708-3714 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback in
 * hooks->frame_hooks_fn[hooks->num_hooks] and increments num_hooks; the array has MAX_APPS (12) entries and num_hooks is not compared with it.
 *
 * Scaffolding only: get_device_frame_hooks is the real accessor (wifi_hal.c:4769-4772) over the stand-alone global hwr_wrf_hooks; renamed hwr_sg_wifi_hal_register_frame_hook.
 */
#include "hwr_wrf.h"
#include <stdio.h>
#include <string.h>

#define wifi_hal_register_frame_hook hwr_sg_wifi_hal_register_frame_hook
#define get_device_frame_hooks hwr_wrf_get_device_frame_hooks

wifi_device_frame_hooks_t hwr_wrf_hooks;
INT hwr_wrf_hook_a(INT ap_index, wifi_mgmtFrameType_t type) { return 0; }
INT hwr_wrf_hook_b(INT ap_index, wifi_mgmtFrameType_t type) { return 1; }

extern "C" {
/* wifi_hal.c:4769-4772 over hwr_wrf_hooks */
wifi_device_frame_hooks_t *get_device_frame_hooks() { return &hwr_wrf_hooks; }

/* --- wifi_hal.c:3708-3714 --- */
void wifi_hal_register_frame_hook(wifi_hal_frame_hook_fn_t func)
{
    wifi_device_frame_hooks_t   *hooks;
    hooks = get_device_frame_hooks();
    hooks->frame_hooks_fn[hooks->num_hooks] = func;
    hooks->num_hooks++;
}
}
