/*
 * HANDLER: wifi_getRadioTransmitPower (platform/broadcom)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/broadcom/platform.c:4429-4432 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no
 * fix applied.  It is a one-line wrapper: it returns wifi_hal_getRadioTransmitPower(radioIndex, tx_power) (src/wifi_hal_nl80211.c:21539).  The logic of
 * that core function (get_radio_tx_power / get_radio_txpwr_handler, the nl80211 GET_INTERFACE reply) belongs to the src module of the campaign and is not
 * re-tested here.
 *
 * Scaffolding only: wifi_hal_getRadioTransmitPower (renamed hwr_bgp_core_getRadioTransmitPower by a macro) is a recording stub whose return value the
 * runner sets (it can also write a value through the pointer).  Renamed hwr_bcm_wifi_getRadioTransmitPower because other harnesses use the real name.
 */
#include "hwr_bgp.h"

#define wifi_getRadioTransmitPower hwr_bcm_wifi_getRadioTransmitPower
#define wifi_hal_getRadioTransmitPower hwr_bgp_core_getRadioTransmitPower

hwr_bgp_world_t hwr_bgp_world;

static INT wifi_hal_getRadioTransmitPower(INT radioIndex, ULONG *tx_power)
{
	hwr_bgp_world.calls++;
	hwr_bgp_world.last_radio = radioIndex;
	hwr_bgp_world.last_tx = tx_power;
	if (hwr_bgp_world.write_out && tx_power != NULL) *tx_power = hwr_bgp_world.write_value;
	return hwr_bgp_world.ret;
}

/* --- platform.c:4429-4432 --- */
extern "C" {
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *tx_power)
{
    return wifi_hal_getRadioTransmitPower(radioIndex, tx_power);
}
}
