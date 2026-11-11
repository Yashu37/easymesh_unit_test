/*
 * HANDLER: wifi_setGASConfiguration (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:674-690 (~/Desktop/G/rdk-wifi-hal), compiled with FEATURE_SUPPORT_PASSPOINT defined.  This file holds the ORIGINAL code (no fixes).
 * It rejects a NULL input and any advertisement id other than 0 (RETURN_ERR), otherwise copies the configuration into gasCfg[0], applies it and returns RETURN_OK.
 *
 * Scaffolding only: the static gasCfg[GAS_CFG_TYPE_SUPPORTED] is declared like wifi_hal_anqp.c:61 and exposed by hwr_wgc_cfg(); wifi_applyGASConfiguration is a recording stub; renamed
 * hwr_sg_wifi_setGASConfiguration.
 */
#include "hwr_wgc.h"
#include <string.h>

#define FEATURE_SUPPORT_PASSPOINT 1
hwr_wgc_world_t hwr_wgc_world;
static wifi_GASConfiguration_t gasCfg[GAS_CFG_TYPE_SUPPORTED];
extern "C" wifi_GASConfiguration_t *hwr_wgc_cfg(void) { return gasCfg; }
extern "C" INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct)
{
	hwr_wgc_world.apply_calls++; hwr_wgc_world.apply_arg = input_struct; memcpy(hwr_wgc_world.apply_copy, input_struct, sizeof(wifi_GASConfiguration_t));
	return RETURN_OK;
}
#define wifi_setGASConfiguration hwr_sg_wifi_setGASConfiguration

extern "C" {
/* --- wifi_hal_anqp.c:674-690 --- */
INT wifi_setGASConfiguration(UINT advertisementID, wifi_GASConfiguration_t *input_struct)
{
    if (!input_struct)
    {
        return RETURN_ERR;
    }
    if (0 != advertisementID)
    {
        return RETURN_ERR; //Only ANQP (0) is supported
    }
    memcpy(&gasCfg[advertisementID], input_struct, sizeof(wifi_GASConfiguration_t));

#if defined (FEATURE_SUPPORT_PASSPOINT)
    wifi_applyGASConfiguration(input_struct);
#endif
    return RETURN_OK;
}
}
