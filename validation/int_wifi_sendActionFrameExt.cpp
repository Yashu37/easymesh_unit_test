/*
 * HANDLER: wifi_sendActionFrameExt (platform/intel)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/intel/platform.c:1898-1901 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: it does not log, does
 * not read MacAddr or frame and returns RETURN_ERR (-1) for every input ("unsupported").  The banana-pi version sends the frame through
 * wifi_hal_send_mgmt_frame (different code, already harnessed); the intel one does not, so there is no finding and no fix switch.
 * Renamed hwr_int_wifi_sendActionFrameExt because the other platforms define the same name.
 */
#include "hwr_isa.h"

#define wifi_sendActionFrameExt hwr_int_wifi_sendActionFrameExt

/* --- platform.c:1898-1901 --- */
extern "C" {
INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    return RETURN_ERR;
}
}
