/*
 * HANDLER: wifi_hal_register_frame_hook (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:3708-3714 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It stores the callback in
 * hooks->frame_hooks_fn[hooks->num_hooks] and increments num_hooks; the array has MAX_APPS (12) entries and num_hooks is not compared with it.
 *
 * Scaffolding only: get_device_frame_hooks is the real accessor (wifi_hal.c:4769-4772) over the stand-alone global hwr_wrf_hooks; renamed hwr_sg_wifi_hal_register_frame_hook.
 */
#include "hwr_wrf.h"
#include <stdio.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
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
    /* ---------- start fix 1: frame_hooks_fn[] has MAX_APPS entries; the 13th registration wrote past it (and num_hooks kept growing). */
    if (hooks->num_hooks >= MAX_APPS) {
        wifi_hal_error_print("%s:%d: frame hook table is full (%d), hook not registered\n", __func__, __LINE__, MAX_APPS);
        return;
    }
    /* ---------- end fix 1 */
    hooks->frame_hooks_fn[hooks->num_hooks] = func;
    hooks->num_hooks++;
}
}
