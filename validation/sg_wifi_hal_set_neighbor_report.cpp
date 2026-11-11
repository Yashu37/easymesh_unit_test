/*
 * HANDLER: wifi_hal_set_neighbor_report (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4846-4853 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It asks for the platform's set-neighbor-report function and, when
 * there is one, calls it with (apIndex, add, mac) unchanged and ignores its return value; with no platform function it does nothing.
 *
 * Scaffolding only: get_platform_set_neighbor_report_fn is a runner-controlled getter (the real one returns g_wifi_hal.platform_set_neighbor_report_fn, wifi_hal_priv.h:866); the platform function is a
 * recording stub; wifi_hal_info_print goes to the log sink hwr_print; renamed hwr_sg_wifi_hal_set_neighbor_report.
 */
#include "hwr_wnb.h"
#include <stdio.h>
#include <string.h>

hwr_wnb_world_t hwr_wnb_world;
#define wifi_hal_info_print(format, ...) hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_set_neighbor_report hwr_sg_wifi_hal_set_neighbor_report
#define get_platform_set_neighbor_report_fn hwr_wnb_get_fn
static int hwr_wnb_platform_fn(uint apIndex, uint add, mac_address_t mac)
{
	hwr_wnb_world.calls++; hwr_wnb_world.call_ap = apIndex; hwr_wnb_world.call_add = add; hwr_wnb_world.call_mac = (unsigned char *)mac;
	return hwr_wnb_world.fn_ret;
}
static platform_set_neighbor_report_t get_platform_set_neighbor_report_fn()
{
	hwr_wnb_world.getter_calls++;
	return hwr_wnb_world.no_fn ? NULL : hwr_wnb_platform_fn;
}

extern "C" {
/* --- wifi_hal.c:4846-4853 --- */
void wifi_hal_set_neighbor_report(uint apIndex,uint add,mac_address_t mac)
{
    platform_set_neighbor_report_t platform_set_neighbor_report_fn;
    if ((platform_set_neighbor_report_fn = get_platform_set_neighbor_report_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform set_neighbor_repor\n", __func__, __LINE__);
        platform_set_neighbor_report_fn(apIndex,add,mac);
    }
}
}
