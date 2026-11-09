/*
 * HANDLER: wifi_getRadioChannel (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1806-1823 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied
 * (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It looks the radio up by RDK index and, when the radio is configured and enabled, stores its primary channel through output_ulong and returns
 * RETURN_OK; an unknown radio or a radio that is not configured / not enabled gives RETURN_ERR without writing the output.  Renamed
 * hwr_int_wifi_getRadioChannel because other harnesses may use the real name.
 *
 * Scaffolding only: wifi_radio_info_t is replaced by igc_radio_t (configured, oper_param - the real wifi_radio_operationParam_t); get_radio_by_rdk_index is a
 * runner-controlled lookup (radio found when its RDK index matches).  The radio object is NOT poisoned: the function reads it.
 */
#include "hwr_igc.h"

#define wifi_radio_info_t igc_radio_t
#define wifi_getRadioChannel hwr_int_wifi_getRadioChannel

hwr_igc_world_t hwr_igc_world;

static igc_radio_t *get_radio_by_rdk_index(int index)
{
	hwr_igc_world.lookups++; hwr_igc_world.last_lookup = index;
	return (hwr_igc_world.radio != NULL && hwr_igc_world.radio_rdk_index == index) ? hwr_igc_world.radio : NULL;
}

/* --- platform.c:1806-1823 --- */
extern "C" {
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)
{
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(radioIndex);

    if (!radio)
    {
        return RETURN_ERR;
    }

    if (radio->configured && radio->oper_param.enable){
        /* start fix 1 */
        if (output_ulong == NULL) {
            return RETURN_ERR;
        }
        /* end fix 1 */
        *output_ulong = radio->oper_param.channel;
        return RETURN_OK;
    } else {
        return RETURN_ERR;
    }
}
}
