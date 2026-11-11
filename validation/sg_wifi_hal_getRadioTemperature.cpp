/*
 * HANDLER: wifi_hal_getRadioTemperature (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4855-4873 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It asks for the platform's get-radio-phytemperature function
 * (RETURN_ERR when there is none), calls it with (radioIndex, radioPhyTemperature) and returns RETURN_ERR when it returns a negative value; otherwise it logs radioPhyTemperature->radio_Temperature and
 * returns RETURN_OK.
 *
 * Scaffolding only: get_platform_get_radio_phytemperature_fn is a runner-controlled getter; the platform function is a recording stub that models the real ones (the banana-pi / emulator versions return 0
 * without writing the output); the print macros go to the log sink hwr_print; renamed hwr_sg_wifi_hal_getRadioTemperature.
 */
#include "hwr_wrt.h"
#include <stdio.h>
#include <string.h>

hwr_wrt_world_t hwr_wrt_world;
#define wifi_hal_stats_error_print(format, ...) hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_stats_dbg_print(format, ...)   hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_getRadioTemperature hwr_sg_wifi_hal_getRadioTemperature
#define get_platform_get_radio_phytemperature_fn hwr_wrt_get_fn
static int hwr_wrt_platform_fn(wifi_radio_index_t index, wifi_radioTemperature_t *radioPhyTemperature)
{
	hwr_wrt_world_t *w = &hwr_wrt_world;
	w->calls++; w->call_index = index; w->call_out = radioPhyTemperature;
	if (w->write_temp && radioPhyTemperature != NULL) radioPhyTemperature->radio_Temperature = w->temp_value;
	return w->fn_ret;
}
static platform_get_radio_phytemperature_t get_platform_get_radio_phytemperature_fn()
{
	hwr_wrt_world.getter_calls++;
	return hwr_wrt_world.no_fn ? NULL : hwr_wrt_platform_fn;
}

extern "C" {
/* --- wifi_hal.c:4855-4873 --- */
INT wifi_hal_getRadioTemperature(wifi_radio_index_t radioIndex,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    platform_get_radio_phytemperature_t get_radio_phytemperature_fn;

    get_radio_phytemperature_fn = get_platform_get_radio_phytemperature_fn();
    if (get_radio_phytemperature_fn == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get phytemperature platfrom cb\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    if (get_radio_phytemperature_fn(radioIndex, radioPhyTemperature) < 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio temperature\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_stats_dbg_print("%s:%d Temperature is %u\n", __func__, __LINE__, radioPhyTemperature->radio_Temperature);
    return RETURN_OK;
}
}
