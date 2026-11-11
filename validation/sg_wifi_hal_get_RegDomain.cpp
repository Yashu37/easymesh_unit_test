/*
 * HANDLER: wifi_hal_get_RegDomain (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:5012-5020 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It asks for the platform's get-RegDomain function and returns
 * its result for (radioIndex, reg_domain); with no platform function it returns RETURN_ERR.
 *
 * Scaffolding only: get_platform_get_RegDomain_fn is a runner-controlled getter; the platform function is a recording stub; the print macro goes to the log sink hwr_print; renamed
 * hwr_sg_wifi_hal_get_RegDomain.
 */
#include "hwr_wgr.h"
#include <stdio.h>
#include <string.h>

hwr_wgr_world_t hwr_wgr_world;
#define wifi_hal_dbg_print(format, ...) hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_get_RegDomain hwr_sg_wifi_hal_get_RegDomain
#define get_platform_get_RegDomain_fn hwr_wgr_get_fn
static int hwr_wgr_platform_fn(wifi_radio_index_t index, uint *reg_domain)
{
	hwr_wgr_world_t *w = &hwr_wgr_world;
	w->calls++; w->call_index = index; w->call_out = reg_domain;
	if (w->write_dom && reg_domain != NULL) *reg_domain = w->dom_value;
	return w->fn_ret;
}
static platform_get_RegDomain_t get_platform_get_RegDomain_fn()
{
	hwr_wgr_world.getter_calls++;
	return hwr_wgr_world.no_fn ? NULL : hwr_wgr_platform_fn;
}

/* --- wifi_hal.c:5012-5020 --- */
INT wifi_hal_get_RegDomain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
    platform_get_RegDomain_t platform_get_RegDomain_fn;
    if ((platform_get_RegDomain_fn = get_platform_get_RegDomain_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: Get RegDomain \n", __func__, __LINE__);
        return (platform_get_RegDomain_fn(radioIndex, reg_domain));
    }
    return RETURN_ERR;
}
