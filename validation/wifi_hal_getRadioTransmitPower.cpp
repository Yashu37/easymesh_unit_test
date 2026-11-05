/*
 * HANDLER: wifi_hal_getRadioTransmitPower
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:553-573
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_GTP_FIX 0 it is the VERBATIM original (reproduces the findings); with
 * RDK_GTP_FIX 1 it carries FIX 1..2 below.
 *
 * Scaffolding only: the platform function wifi_getRadioTransmitPower (halinterface prototype) is a stub in the
 * construct file (renamed hwr_gtp_platform; it records its arguments, returns a configurable result and, on
 * success, writes the power through the pointer like the real platform code does); the prints are the real
 * macros over the log sink.  The function under test is renamed hwr_wifi_hal_getRadioTransmitPower
 * (ipc_server_output already stubs the real name).
 */
#include "hwr_gtp.h"

/* 1 = with FIX 1..2, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GTP_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_getRadioTransmitPower   hwr_gtp_platform
#define wifi_hal_getRadioTransmitPower hwr_wifi_hal_getRadioTransmitPower

//--------------------------------------------------------------------------------------------------
extern "C" {
INT wifi_hal_getRadioTransmitPower( INT radioIndex,
                                    ULONG *output_ulong)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
#if RDK_GTP_FIX
    /* FIX 1: output_ulong is forwarded unchecked; the platform writes the power through it. */
    if (output_ulong == NULL) {
        return RETURN_ERR;
    }
#endif
    /*
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(radioIndex);

    if (!radio){
        wifi_hal_dbg_print("%s:%d: radio info for index %d is NULL.\n", __func__, __LINE__, radioIndex);
        return -1;
    }

    *output_ulong = radio->oper_param.transmitPower;
    */

#if RDK_GTP_FIX
    /* FIX 2: the platform result was ignored: a failing query (unknown radio, driver error) left *output_ulong
     * unwritten and 0 was reported as success. */
    if (wifi_getRadioTransmitPower(radioIndex, output_ulong) != RETURN_OK) {
        return RETURN_ERR;
    }
#else
    wifi_getRadioTransmitPower(radioIndex, output_ulong);
#endif

    return 0;
}
}
